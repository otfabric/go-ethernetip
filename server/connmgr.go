// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Counters of the Connection Manager instance, attributes 1 to 8.
const (
	cntOpenRequests = iota
	cntOpenFormatRejects
	cntOpenResourceRejects
	cntOpenOtherRejects
	cntCloseRequests
	cntCloseFormatRejects
	cntCloseOtherRejects
	cntTimeouts
	numCounters
)

// connectionManager is the Connection Manager (class 0x06), instance 1,
// and the registry of the server's connections.
type connectionManager struct {
	*StandardObject
	s *Server

	mu          sync.Mutex
	conns       map[cip.Triad]conn
	explicit    map[uint32]*explicitConn // by O->T connection ID
	productions map[uint32]*production   // multicast productions, by T->O point
	ids         map[uint32]bool          // connection IDs in use
	counters    [numCounters]uint16
	nextGroup   int
}

// conn is an open connection of the registry.
type conn interface {
	connInfo() ethernetip.ConnectionInfo
	originator() netip.Addr
	// shutdown stops the connection; the registry entry is removed by the
	// caller.
	shutdown(err error)
}

func newConnectionManager(s *Server) *connectionManager {
	cm := &connectionManager{
		StandardObject: NewObject(cip.ClassConnectionManager, 1),
		s:              s,
		conns:          map[cip.Triad]conn{},
		explicit:       map[uint32]*explicitConn{},
		productions:    map[uint32]*production{},
		ids:            map[uint32]bool{},
	}
	in := cm.AddInstance(1)
	for i := 0; i < numCounters; i++ {
		i := i
		in.SetAttribute(uint16(i+1), Attribute{Get: func() []byte {
			cm.mu.Lock()
			defer cm.mu.Unlock()
			return cip.AppendUint16(nil, cm.counters[i])
		}, InGetAll: true})
	}
	cm.HandleService(cip.ServiceForwardOpen, cm.forwardOpen)
	cm.HandleService(cip.ServiceLargeForwardOpen, cm.forwardOpen)
	cm.HandleService(cip.ServiceForwardClose, cm.forwardClose)
	cm.HandleService(cip.ServiceUnconnectedSend, cm.unconnectedSend)
	return cm
}

func (cm *connectionManager) count(i int) {
	cm.mu.Lock()
	cm.counters[i]++
	cm.mu.Unlock()
}

// newID returns an unused connection ID; cm.mu is held.
func (cm *connectionManager) newID() uint32 {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		id := binary.LittleEndian.Uint32(b[:])
		if id != 0 && !cm.ids[id] {
			cm.ids[id] = true
			return id
		}
	}
}

func (cm *connectionManager) list() []ethernetip.ConnectionInfo {
	cm.mu.Lock()
	out := make([]ethernetip.ConnectionInfo, 0, len(cm.conns))
	for _, c := range cm.conns {
		out = append(out, c.connInfo())
	}
	cm.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].OTConnID < out[j].OTConnID })
	return out
}

// closeAll closes every connection.
func (cm *connectionManager) closeAll(err error) {
	cm.mu.Lock()
	all := make([]conn, 0, len(cm.conns))
	for _, c := range cm.conns {
		all = append(all, c)
	}
	cm.mu.Unlock()
	for _, c := range all {
		cm.remove(c, err)
	}
}

// remove closes c and removes it from the registry, once.
func (cm *connectionManager) remove(c conn, err error) {
	info := c.connInfo()
	triad := cip.Triad{Serial: info.Serial, VendorID: info.VendorID, OriginatorSerial: info.OriginatorSerial}
	cm.mu.Lock()
	if cm.conns[triad] != c {
		cm.mu.Unlock()
		return
	}
	delete(cm.conns, triad)
	if ec, ok := c.(*explicitConn); ok {
		delete(cm.explicit, ec.info.OTConnID)
	}
	delete(cm.ids, info.OTConnID)
	cm.mu.Unlock()
	c.shutdown(err)
	if errors.Is(err, ethernetip.ErrTimeout) {
		cm.count(cntTimeouts)
	}
	cm.s.log.Info("connection closed", "ot", info.OTConnID, "to", info.TOConnID, "class", info.Class, "error", err)
	if cm.s.sm != nil {
		var remote net.Addr
		if a := c.originator(); a.IsValid() {
			remote = &net.IPAddr{IP: a.AsSlice()}
		}
		cm.s.sm.OnConnectionClosed(remote, info, err)
	}
}

// sessionClosed closes the Class 3 connections of a session.
func (cm *connectionManager) sessionClosed(ss *session) {
	cm.mu.Lock()
	var mine []conn
	for _, ec := range cm.explicit {
		if ec.sess == ss {
			mine = append(mine, ec)
		}
	}
	cm.mu.Unlock()
	for _, c := range mine {
		cm.remove(c, ethernetip.ErrConnectionLost)
	}
}

// explicitConn returns the Class 3 connection with O->T ID id opened on
// session ss.
func (cm *connectionManager) explicitConn(id uint32, ss *session) *explicitConn {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	ec := cm.explicit[id]
	if ec == nil || ec.sess != ss {
		return nil
	}
	return ec
}

// failure is a refused Forward_Open or Forward_Close.
type failure struct {
	status   cip.GeneralStatus
	extended []uint16
}

func connFailure(ext cip.ConnectionStatus, more ...uint16) *failure {
	return &failure{status: cip.StatusConnectionFailure, extended: append([]uint16{uint16(ext)}, more...)}
}

func (f *failure) response(t cip.Triad) cip.Response {
	return cip.Response{Status: f.status, Extended: f.extended, Data: cip.ConnectionFailure{Triad: t}.Encode()}
}

func (cm *connectionManager) forwardOpen(ctx context.Context, r *Request) cip.Response {
	if r.Instance != 1 {
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
	cm.count(cntOpenRequests)
	fo, err := cip.DecodeForwardOpen(r.Data, r.Service == cip.ServiceLargeForwardOpen)
	if err != nil {
		cm.count(cntOpenFormatRejects)
		if errors.Is(err, cip.ErrTruncated) {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		return connFailure(cip.ConnStatusInvalidSegment).response(fo.Triad)
	}
	ex := exchangeOf(ctx)
	if ex == nil {
		return cip.Response{Status: cip.StatusDeviceStateConflict}
	}
	reply, items, f := cm.open(ex, fo, r.Remote)
	if f != nil {
		switch f.extended[0] {
		case uint16(cip.ConnStatusOutOfConnections), uint16(cip.ConnStatusTargetOutOfConnections):
			cm.count(cntOpenResourceRejects)
		case uint16(cip.ConnStatusInvalidSegment), uint16(cip.ConnStatusInvalidNetworkParameter):
			cm.count(cntOpenFormatRejects)
		default:
			cm.count(cntOpenOtherRejects)
		}
		cm.s.log.Info("Forward_Open refused", "remote", addrString(r.Remote), "status", cip.ConnectionStatus(f.extended[0]).String())
		return f.response(fo.Triad)
	}
	ex.addItems = append(ex.addItems, items...)
	b, err := reply.Encode()
	if err != nil {
		return cip.Response{Status: cip.StatusReplyDataTooLarge}
	}
	return cip.Response{Data: b}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func remoteIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// localPath removes the route prefix that addresses this server: port 1
// with the server's slot. Any other port segment cannot be routed.
func (cm *connectionManager) localPath(p cip.Path) (cip.Path, *failure) {
	for len(p) > 0 {
		ps, ok := p[0].(cip.PortSegment)
		if !ok {
			break
		}
		if ps.Port != 1 || len(ps.Link) != 1 || int(ps.Link[0]) != cm.s.opts.slot {
			return nil, connFailure(cip.ConnStatusPortNotAvailable)
		}
		p = p[1:]
	}
	return p, nil
}

// openParts is a connection path taken apart.
type openParts struct {
	class   cip.Class
	points  []uint32
	config  []byte
	hasData bool
}

func (cm *connectionManager) parsePath(p cip.Path) (openParts, *failure) {
	var op openParts
	id := cm.s.identity.get()
	gotClass := false
	for _, seg := range p {
		switch s := seg.(type) {
		case cip.KeySegment:
			if s.VendorID != 0 && s.VendorID != id.VendorID || s.ProductCode != 0 && s.ProductCode != id.ProductCode {
				return op, connFailure(cip.ConnStatusVendorMismatch)
			}
			if s.DeviceType != 0 && s.DeviceType != uint16(id.DeviceType) {
				return op, connFailure(cip.ConnStatusDeviceTypeMismatch)
			}
			if s.Major != 0 {
				ok := s.Major == id.Revision.Major && (s.Minor == 0 || s.Minor == id.Revision.Minor || s.Compatible && s.Minor <= id.Revision.Minor)
				if !ok {
					return op, connFailure(cip.ConnStatusRevisionMismatch)
				}
			}
		case cip.NetworkSegment:
			// Production inhibit time and the like: the server produces at
			// the RPI, which satisfies any inhibit time below it.
		case cip.DataSegment:
			op.config, op.hasData = s.Data, true
		case cip.LogicalSegment:
			switch s.Type {
			case cip.LogicalClass:
				if gotClass {
					return op, connFailure(cip.ConnStatusInvalidSegment)
				}
				op.class, gotClass = cip.Class(s.Value), true
			case cip.LogicalInstance, cip.LogicalConnectionPoint:
				if !gotClass {
					return op, connFailure(cip.ConnStatusInvalidSegment)
				}
				op.points = append(op.points, s.Value)
			default:
				return op, connFailure(cip.ConnStatusInvalidSegment)
			}
		default:
			return op, connFailure(cip.ConnStatusInvalidSegment)
		}
	}
	if !gotClass {
		return op, connFailure(cip.ConnStatusInvalidSegment)
	}
	return op, nil
}

func (cm *connectionManager) open(ex *exchange, fo cip.ForwardOpen, remote net.Addr) (cip.ForwardOpenReply, []encap.Item, *failure) {
	var reply cip.ForwardOpenReply
	if fo.TimeoutMultiplier > 7 {
		return reply, nil, connFailure(cip.ConnStatusTimeoutMultiplierNotAcceptable)
	}
	cm.mu.Lock()
	_, dup := cm.conns[fo.Triad]
	n := len(cm.conns)
	cm.mu.Unlock()
	if dup {
		return reply, nil, connFailure(cip.ConnStatusInUse)
	}
	if n >= cm.s.opts.maxConnections {
		return reply, nil, connFailure(cip.ConnStatusOutOfConnections)
	}
	path, f := cm.localPath(fo.Path)
	if f != nil {
		return reply, nil, f
	}
	parts, f := cm.parsePath(path)
	if f != nil {
		return reply, nil, f
	}
	for _, rpi := range []uint32{fo.OTRPI, fo.TORPI} {
		d := time.Duration(rpi) * time.Microsecond
		if d < cm.s.opts.minRPI || d > cm.s.opts.maxRPI {
			return reply, nil, connFailure(cip.ConnStatusRPINotAcceptable)
		}
	}
	switch fo.Transport.Class() {
	case 3:
		return cm.openExplicit(ex, fo, parts, remote)
	case 0, 1:
		return cm.openIO(ex, fo, parts, remote)
	default:
		return reply, nil, connFailure(cip.ConnStatusTransportClassNotSupported)
	}
}

// explicitConn is a Class 3 connection: requests in SendUnitData on the
// session that opened it, with duplicate detection by sequence count and an
// inactivity timeout.
type explicitConn struct {
	cm      *connectionManager
	info    ethernetip.ConnectionInfo
	sess    *session
	orig    netip.Addr
	timeout time.Duration

	mu        sync.Mutex
	timer     *time.Timer
	have      bool
	lastSeq   uint16
	lastReply []byte
	closed    bool
}

func (cm *connectionManager) openExplicit(ex *exchange, fo cip.ForwardOpen, parts openParts, remote net.Addr) (cip.ForwardOpenReply, []encap.Item, *failure) {
	if parts.class != cip.ClassMessageRouter || len(parts.points) != 1 || parts.points[0] != 1 || parts.hasData {
		return cip.ForwardOpenReply{}, nil, connFailure(cip.ConnStatusInvalidSegment)
	}
	if fo.OTParams.Type != cip.ConnectionPointToPoint || fo.TOParams.Type != cip.ConnectionPointToPoint {
		return cip.ForwardOpenReply{}, nil, connFailure(cip.ConnStatusInvalidNetworkParameter)
	}
	if fo.Transport.Trigger() != cip.TriggerApplication && fo.Transport.Trigger() != cip.TriggerCyclic {
		return cip.ForwardOpenReply{}, nil, connFailure(cip.ConnStatusTriggerNotSupported)
	}
	if ex.sess == nil {
		return cip.ForwardOpenReply{}, nil, connFailure(cip.ConnStatusMiscellaneous)
	}
	ec := &explicitConn{
		cm:      cm,
		sess:    ex.sess,
		orig:    remoteIP(remote),
		timeout: cip.ConnectionTimeout(time.Duration(fo.OTRPI)*time.Microsecond, fo.TimeoutMultiplier),
	}
	cm.mu.Lock()
	if _, dup := cm.conns[fo.Triad]; dup {
		cm.mu.Unlock()
		return cip.ForwardOpenReply{}, nil, connFailure(cip.ConnStatusInUse)
	}
	ot := cm.newID()
	ec.info = ethernetip.ConnectionInfo{
		Class: 3, OTConnID: ot, TOConnID: fo.TOConnID,
		Serial: fo.Serial, VendorID: fo.VendorID, OriginatorSerial: fo.OriginatorSerial,
		OTRPI: time.Duration(fo.OTRPI) * time.Microsecond, TORPI: time.Duration(fo.TORPI) * time.Microsecond,
		Path: fo.Path,
	}
	cm.conns[fo.Triad] = ec
	cm.explicit[ot] = ec
	cm.mu.Unlock()
	ec.mu.Lock()
	ec.timer = time.AfterFunc(ec.timeout, func() { cm.remove(ec, ethernetip.ErrTimeout) })
	ec.mu.Unlock()
	cm.opened(remote, ec.info)
	return cip.ForwardOpenReply{
		OTConnID: ot, TOConnID: fo.TOConnID, Triad: fo.Triad,
		OTAPI: fo.OTRPI, TOAPI: fo.TORPI,
	}, nil, nil
}

func (cm *connectionManager) opened(remote net.Addr, info ethernetip.ConnectionInfo) {
	cm.s.log.Info("connection opened", "remote", addrString(remote), "class", info.Class, "ot", info.OTConnID, "to", info.TOConnID)
	if cm.s.sm != nil {
		cm.s.sm.OnConnectionOpened(remote, info)
	}
}

func (ec *explicitConn) connInfo() ethernetip.ConnectionInfo { return ec.info }
func (ec *explicitConn) originator() netip.Addr              { return ec.orig }

func (ec *explicitConn) shutdown(error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.closed = true
	if ec.timer != nil {
		ec.timer.Stop()
	}
}

// request handles a request with sequence count seq: a new one is
// handled by handle, a repeat of the last one is answered with the last
// reply. It returns false when there is nothing to answer.
func (ec *explicitConn) request(seq uint16, handle func() []byte) ([]byte, bool) {
	ec.mu.Lock()
	if ec.closed {
		ec.mu.Unlock()
		return nil, false
	}
	ec.timer.Reset(ec.timeout)
	if ec.have && seq == ec.lastSeq {
		r := ec.lastReply
		ec.mu.Unlock()
		return r, r != nil
	}
	ec.mu.Unlock()
	r := handle()
	ec.mu.Lock()
	ec.have, ec.lastSeq, ec.lastReply = true, seq, r
	ec.mu.Unlock()
	return r, r != nil
}

func (cm *connectionManager) forwardClose(ctx context.Context, r *Request) cip.Response {
	if r.Instance != 1 {
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
	cm.count(cntCloseRequests)
	fc, err := cip.DecodeForwardClose(r.Data)
	if err != nil {
		cm.count(cntCloseFormatRejects)
		if errors.Is(err, cip.ErrTruncated) {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		return connFailure(cip.ConnStatusForwardClosePathError).response(fc.Triad)
	}
	cm.mu.Lock()
	c := cm.conns[fc.Triad]
	cm.mu.Unlock()
	if c == nil || (c.originator().IsValid() && remoteIP(r.Remote).IsValid() && c.originator() != remoteIP(r.Remote)) {
		cm.count(cntCloseOtherRejects)
		return connFailure(cip.ConnStatusNotFound).response(fc.Triad)
	}
	cm.remove(c, nil)
	b, _ := cip.ForwardCloseReply{Triad: fc.Triad}.Encode()
	return cip.Response{Data: b}
}

func (cm *connectionManager) unconnectedSend(ctx context.Context, r *Request) cip.Response {
	if r.Instance != 1 {
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
	us, err := cip.DecodeUnconnectedSend(r.Data)
	if err != nil {
		if errors.Is(err, cip.ErrTruncated) {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		return cip.Response{Status: cip.StatusConnectionFailure, Extended: []uint16{uint16(cip.ConnStatusUnconnectedParameterError)}}
	}
	route, f := cm.localPath(us.Route)
	if f != nil || len(route) != 0 {
		words, _ := us.Route.Words()
		return cip.Response{Status: cip.StatusConnectionFailure, Extended: []uint16{uint16(cip.ConnStatusPortNotAvailable)}, Data: []byte{byte(words), 0}}
	}
	if c, _ := us.Request.Path.Class(); us.Request.Service == cip.ServiceUnconnectedSend && c == cip.ClassConnectionManager {
		return cip.Response{Status: cip.StatusConnectionFailure, Extended: []uint16{uint16(cip.ConnStatusUnconnectedParameterError)}}
	}
	// The reply of an Unconnected_Send is the embedded request's reply,
	// with its service.
	resp := cm.s.route(ctx, us.Request, r.Remote, r.Connected)
	resp.Service = us.Request.Service
	return resp
}
