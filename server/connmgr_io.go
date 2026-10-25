// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"net/netip"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

// ioConn is a Class 0 or 1 connection the server is the target of: it
// consumes O->T (output data or heartbeats) and produces T->O, point to
// point itself or through a shared multicast production.
type ioConn struct {
	cm   *connectionManager
	info ethernetip.ConnectionInfo
	orig netip.Addr
	out  *Assembly // the O->T point
	in   *Assembly // the T->O point
	// consumer consumes O->T; for point-to-point T->O it produces too.
	consumer *implicit.Connection
	prod     *production // multicast T->O, shared
	listen   bool        // a listen-only connection

	mu     sync.Mutex
	closed bool
}

// production is a multicast T->O production shared by the connections of
// one T->O point.
type production struct {
	point  uint32
	toID   uint32
	group  netip.Addr
	port   uint16
	rpi    uint32
	conn   *implicit.Connection
	owners map[*ioConn]bool // connections that are not listen-only
	listen map[*ioConn]bool
}

func (c *ioConn) connInfo() ethernetip.ConnectionInfo { return c.info }
func (c *ioConn) originator() netip.Addr              { return c.orig }

func (c *ioConn) shutdown(error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	if c.consumer != nil {
		c.consumer.Close()
	}
	if c.out != nil {
		c.out.mu.Lock()
		if c.out.owner == c {
			c.out.owner = nil
			c.out.run = false
		}
		c.out.mu.Unlock()
	}
	if c.in != nil {
		c.in.removeProducer(c.consumer)
	}
	if c.prod != nil {
		c.cm.leaveProduction(c)
	}
}

// formats returns the real-time formats the server uses for an O->T point
// of kind k and for T->O.
func (s *Server) formats(k AssemblyKind) (ot, to implicit.Format) {
	ot, to = implicit.FormatModeless, implicit.FormatModeless
	switch {
	case k == AssemblyInputOnly || k == AssemblyListenOnly:
		ot = implicit.FormatHeartbeat
	case s.opts.runIdleOT:
		ot = implicit.FormatHeader32
	}
	if s.opts.runIdleTO {
		to = implicit.FormatHeader32
	}
	return ot, to
}

func (cm *connectionManager) openIO(ex *exchange, fo cip.ForwardOpen, parts openParts, remote net.Addr) (cip.ForwardOpenReply, []encap.Item, *failure) {
	var reply cip.ForwardOpenReply
	if parts.class != cip.ClassAssembly {
		return reply, nil, connFailure(cip.ConnStatusInvalidApplicationPath)
	}
	var cfgInst, otPoint, toPoint uint32
	switch len(parts.points) {
	case 3:
		cfgInst, otPoint, toPoint = parts.points[0], parts.points[1], parts.points[2]
	case 2:
		otPoint, toPoint = parts.points[0], parts.points[1]
	default:
		return reply, nil, connFailure(cip.ConnStatusInvalidApplicationPath)
	}
	asm := cm.s.assemblies
	out, in := asm.get(otPoint), asm.get(toPoint)
	if out == nil || (out.kind != AssemblyOutput && out.kind != AssemblyInputOnly && out.kind != AssemblyListenOnly) {
		return reply, nil, connFailure(cip.ConnStatusInvalidConsumingPath)
	}
	if in == nil || in.kind != AssemblyInput {
		return reply, nil, connFailure(cip.ConnStatusInvalidProducingPath)
	}
	var cfg *Assembly
	if cfgInst != 0 {
		cfg = asm.get(cfgInst)
	}
	if parts.hasData {
		if cfg == nil || cfg.kind != AssemblyConfig {
			return reply, nil, connFailure(cip.ConnStatusInvalidConfigurationAppPath)
		}
		if len(parts.config) != cfg.size {
			return reply, nil, connFailure(cip.ConnStatusInvalidConfigurationSize, uint16(cfg.size/2))
		}
	}
	class := fo.Transport.Class()
	if t := fo.Transport.Trigger(); t != cip.TriggerCyclic && t != cip.TriggerChangeOfState {
		return reply, nil, connFailure(cip.ConnStatusTriggerNotSupported)
	}
	if fo.OTParams.Type != cip.ConnectionPointToPoint {
		return reply, nil, connFailure(cip.ConnStatusInvalidOTType)
	}
	if fo.TOParams.Type != cip.ConnectionPointToPoint && fo.TOParams.Type != cip.ConnectionMulticast {
		return reply, nil, connFailure(cip.ConnStatusInvalidTOType)
	}
	otFmt, toFmt := cm.s.formats(out.kind)
	if want := out.size + otFmt.Overhead(class); !sizeOK(fo.OTParams, want) {
		return reply, nil, connFailure(cip.ConnStatusInvalidOTSize, uint16(want))
	}
	if want := in.size + toFmt.Overhead(class); !sizeOK(fo.TOParams, want) {
		return reply, nil, connFailure(cip.ConnStatusInvalidTOSize, uint16(want))
	}
	listenOnly := out.kind == AssemblyListenOnly
	if listenOnly && fo.TOParams.Type != cip.ConnectionMulticast {
		return reply, nil, connFailure(cip.ConnStatusNonListenOnlyNotOpened)
	}
	orig := remoteIP(remote)
	if !orig.IsValid() {
		return reply, nil, connFailure(cip.ConnStatusMiscellaneous)
	}
	// Where the originator wants its T->O datagrams: its address, at the
	// port of a Sockaddr Info T->O item, 2222 otherwise.
	toPort := uint16(encap.IOPort)
	if it, ok := encap.Find(ex.items, encap.ItemSockaddrTO); ok {
		if sa, err := encap.DecodeSockaddr(it.Data); err == nil && sa.Port != 0 {
			toPort = sa.Port
		}
	}

	cm.mu.Lock()
	if _, dup := cm.conns[fo.Triad]; dup {
		cm.mu.Unlock()
		return reply, nil, connFailure(cip.ConnStatusInUse)
	}
	out.mu.Lock()
	owned := out.kind == AssemblyOutput && out.owner != nil
	out.mu.Unlock()
	if owned {
		cm.mu.Unlock()
		return reply, nil, connFailure(cip.ConnStatusOwnershipConflict)
	}
	prod := cm.productions[toPoint]
	if listenOnly && (prod == nil || len(prod.owners) == 0) {
		cm.mu.Unlock()
		return reply, nil, connFailure(cip.ConnStatusNonListenOnlyNotOpened)
	}
	c := &ioConn{cm: cm, orig: orig, out: out, in: in, listen: listenOnly}
	otID := cm.newID()
	toID := fo.TOConnID
	multicast := fo.TOParams.Type == cip.ConnectionMulticast
	toRPI := fo.TORPI
	var group netip.Addr
	if multicast {
		if prod == nil {
			prod = &production{point: toPoint, toID: cm.newID(), group: cm.s.multicastGroup(cm.nextGroup), port: toPort,
				rpi: fo.TORPI, owners: map[*ioConn]bool{}, listen: map[*ioConn]bool{}}
			cm.nextGroup++
			cm.productions[toPoint] = prod
		}
		if listenOnly {
			prod.listen[c] = true
		} else {
			prod.owners[c] = true
		}
		c.prod = prod
		toID, toRPI, group = prod.toID, prod.rpi, prod.group
	}
	c.info = ethernetip.ConnectionInfo{
		Class: class, OTConnID: otID, TOConnID: toID,
		Serial: fo.Serial, VendorID: fo.VendorID, OriginatorSerial: fo.OriginatorSerial,
		OTRPI: time.Duration(fo.OTRPI) * time.Microsecond, TORPI: time.Duration(toRPI) * time.Microsecond,
		Path: fo.Path,
	}
	cm.conns[fo.Triad] = c
	cm.mu.Unlock()

	if parts.hasData {
		cfg.write(parts.config, true)
	}
	if out.kind == AssemblyOutput {
		out.mu.Lock()
		out.owner = c
		out.mu.Unlock()
	}
	ep := cm.s.io
	timeout := cip.ConnectionTimeout(c.info.OTRPI, fo.TimeoutMultiplier)
	cfgIO := implicit.Config{
		Class:         class,
		ConsumedID:    otID,
		Timeout:       timeout,
		FirstTimeout:  max(timeout, 10*time.Second),
		ConsumeFormat: otFmt,
		ConsumeSize:   out.size,
		Source:        orig,
		OnData: func(data []byte, run bool) {
			if out.kind == AssemblyOutput {
				out.write(data, run)
			}
		},
		OnTimeout: func() { cm.remove(c, ethernetip.ErrTimeout) },
	}
	if !multicast {
		cfgIO.ProducedID = toID
		cfgIO.Destination = netip.AddrPortFrom(orig, toPort)
		cfgIO.ProduceRPI = c.info.TORPI
		cfgIO.ProduceFormat = toFmt
		cfgIO.ProduceSize = in.size
		cfgIO.Produce = func() ([]byte, bool) { return in.Data(), true }
	}
	consumer, err := ep.Open(cfgIO)
	if err == nil && multicast {
		err = cm.startProduction(prod, in, toFmt)
	}
	if err != nil {
		if consumer != nil {
			consumer.Close()
		}
		cm.remove(c, err)
		return reply, nil, connFailure(cip.ConnStatusNoBufferMemory)
	}
	c.mu.Lock()
	c.consumer = consumer
	closed := c.closed
	c.mu.Unlock()
	if closed {
		consumer.Close()
		return reply, nil, connFailure(cip.ConnStatusMiscellaneous)
	}
	if !multicast && fo.Transport.Trigger() == cip.TriggerChangeOfState {
		in.addProducer(consumer)
	}
	cm.opened(remote, c.info)

	var items []encap.Item
	if p := ep.LocalAddr().Port(); p != encap.IOPort {
		local := cm.s.localIP(ex.sess.local)
		items = append(items, encap.Item{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.AddrPortFrom(local, p)).Encode()})
	}
	if multicast {
		items = append(items, encap.Item{Type: encap.ItemSockaddrTO, Data: encap.SockaddrOf(netip.AddrPortFrom(group, prod.port)).Encode()})
	}
	return cip.ForwardOpenReply{
		OTConnID: otID, TOConnID: toID, Triad: fo.Triad,
		OTAPI: fo.OTRPI, TOAPI: toRPI,
	}, items, nil
}

// sizeOK checks a requested connection size against the one the server
// needs: equal for fixed sizes, at least for variable sizes.
func sizeOK(p cip.NetworkParams, want int) bool {
	if p.Variable {
		return int(p.Size) >= want
	}
	return int(p.Size) == want
}

// startProduction starts the multicast production of prod unless it runs.
func (cm *connectionManager) startProduction(prod *production, in *Assembly, f implicit.Format) error {
	cm.mu.Lock()
	running := prod.conn != nil
	cm.mu.Unlock()
	if running {
		return nil
	}
	pc, err := cm.s.io.Open(implicit.Config{
		Class:         1,
		ProducedID:    prod.toID,
		Destination:   netip.AddrPortFrom(prod.group, prod.port),
		ProduceRPI:    time.Duration(prod.rpi) * time.Microsecond,
		ProduceFormat: f,
		ProduceSize:   in.size,
		Produce:       func() ([]byte, bool) { return in.Data(), true },
	})
	if err != nil {
		return err
	}
	cm.mu.Lock()
	if prod.conn != nil {
		cm.mu.Unlock()
		pc.Close()
		return nil
	}
	prod.conn = pc
	cm.mu.Unlock()
	in.addProducer(pc)
	return nil
}

// leaveProduction removes c from its multicast production; the last
// connection that is not listen-only takes the listen-only ones and the
// production with it.
func (cm *connectionManager) leaveProduction(c *ioConn) {
	cm.mu.Lock()
	p := c.prod
	delete(p.owners, c)
	delete(p.listen, c)
	var orphans []conn
	var stop *implicit.Connection
	if len(p.owners) == 0 {
		for l := range p.listen {
			orphans = append(orphans, l)
		}
		if len(p.listen) == 0 || len(orphans) > 0 {
			stop = p.conn
			p.conn = nil
			if cm.productions[p.point] == p {
				delete(cm.productions, p.point)
				delete(cm.ids, p.toID)
			}
		}
	}
	cm.mu.Unlock()
	for _, o := range orphans {
		cm.remove(o, ethernetip.ErrConnectionLost)
	}
	if stop != nil {
		c.in.removeProducer(stop)
		stop.Close()
	}
}

// addProducer registers a connection that produces the assembly with a
// change-of-state trigger: SetData triggers it.
func (a *Assembly) addProducer(c *implicit.Connection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.producers == nil {
		a.producers = map[*implicit.Connection]bool{}
	}
	a.producers[c] = true
}

func (a *Assembly) removeProducer(c *implicit.Connection) {
	if c == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.producers, c)
}
