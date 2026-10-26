// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

// Assemblies of the test server.
const (
	asmIn         = 100
	asmOut        = 150
	asmCfg        = 151
	asmInputOnly  = 152
	asmListenOnly = 153
	asmSize       = 8
	cfgSize       = 4
)

// startServer starts a server on loopback, with the I/O endpoint on a free
// port, and closes it at the end of the test.
func startServer(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s, err := New(append([]Option{WithIOAddress("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, s, "127.0.0.1:0")
	return s
}

// serve listens on addr and serves s until the end of the test.
func serve(t testing.TB, s *Server, addr string) {
	t.Helper()
	if err := s.Listen(addr); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ethernetip.ErrClosed) {
				t.Errorf("Serve = %v, want ErrClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
}

// startIOServer is startServer with the test assemblies.
func startIOServer(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s, err := New(append([]Option{WithIOAddress("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	addAssemblies(t, s)
	serve(t, s, "127.0.0.1:0")
	return s
}

func addAssemblies(t testing.TB, s *Server) {
	t.Helper()
	for _, a := range []struct {
		inst uint32
		kind AssemblyKind
		size int
	}{
		{asmIn, AssemblyInput, asmSize},
		{asmOut, AssemblyOutput, asmSize},
		{asmCfg, AssemblyConfig, cfgSize},
		{asmInputOnly, AssemblyInputOnly, 0},
		{asmListenOnly, AssemblyListenOnly, 0},
	} {
		if _, err := s.AddAssembly(a.inst, a.kind, a.size); err != nil {
			t.Fatal(err)
		}
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// peer is a hand-written originator speaking raw encapsulation over TCP.
type peer struct {
	t      testing.TB
	c      net.Conn
	handle uint32
	buf    []byte
	ctx    uint64
}

func dialPeer(t testing.TB, s *Server) *peer {
	t.Helper()
	c, err := net.Dial("tcp4", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &peer{t: t, c: c}
}

// write writes raw octets.
func (p *peer) write(b []byte) {
	p.t.Helper()
	_ = p.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.c.Write(b); err != nil {
		p.t.Fatalf("write: %v", err)
	}
}

// send writes a packet; its sender context is a fresh number.
func (p *peer) send(cmd encap.Command, session uint32, data []byte) encap.Header {
	p.t.Helper()
	p.ctx++
	h := encap.Header{Command: cmd, Session: session}
	binary.LittleEndian.PutUint64(h.Context[:], p.ctx)
	b, err := encap.Packet{Header: h, Data: data}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	p.write(b)
	return h
}

// recv reads one packet.
func (p *peer) recv() encap.Packet {
	p.t.Helper()
	pkt, err := p.tryRecv(5 * time.Second)
	if err != nil {
		p.t.Fatalf("recv: %v", err)
	}
	return pkt
}

func (p *peer) tryRecv(d time.Duration) (encap.Packet, error) {
	_ = p.c.SetReadDeadline(time.Now().Add(d))
	pkt, nb, err := encap.ReadPacket(p.c, p.buf, 0)
	p.buf = nil
	if err != nil {
		return pkt, err
	}
	pkt.Data = append([]byte(nil), pkt.Data...)
	_ = nb
	return pkt, nil
}

// roundTrip sends a packet and returns the reply, checking that it
// answers the request.
func (p *peer) roundTrip(cmd encap.Command, session uint32, data []byte) encap.Packet {
	p.t.Helper()
	h := p.send(cmd, session, data)
	r := p.recv()
	if r.Command != cmd || r.Context != h.Context {
		p.t.Fatalf("reply %s context %x to %s context %x", r.Command, r.Context, cmd, h.Context)
	}
	return r
}

// expectClosed reads until the server closes the connection.
func (p *peer) expectClosed() {
	p.t.Helper()
	for {
		_, err := p.tryRecv(5 * time.Second)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			p.t.Fatal("connection not closed by the server")
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			// A reset is a close too.
			return
		}
		return
	}
}

// expectSilence checks that nothing arrives within d.
func (p *peer) expectSilence(d time.Duration) {
	p.t.Helper()
	pkt, err := p.tryRecv(d)
	if err == nil {
		p.t.Fatalf("unexpected packet %s status %s", pkt.Command, pkt.Status)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		p.t.Fatalf("connection failed: %v", err)
	}
}

func (p *peer) register() uint32 {
	p.t.Helper()
	r := p.roundTrip(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode())
	if r.Status != encap.StatusSuccess || r.Session == 0 {
		p.t.Fatalf("RegisterSession: status %s session %d", r.Status, r.Session)
	}
	p.handle = r.Session
	return r.Session
}

// rrData sends a SendRRData with the given message and extra items, and
// returns the decoded reply and its items.
func (p *peer) rrData(msg []byte, extra ...encap.Item) (cip.Response, []encap.Item) {
	p.t.Helper()
	items := append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}, extra...)
	data, err := encap.RRData{Items: items}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	r := p.roundTrip(encap.CommandSendRRData, p.handle, data)
	if r.Status != encap.StatusSuccess {
		p.t.Fatalf("SendRRData status %s", r.Status)
	}
	rr, err := encap.DecodeRRData(r.Data)
	if err != nil {
		p.t.Fatal(err)
	}
	it, ok := encap.Find(rr.Items, encap.ItemUnconnectedData)
	if !ok {
		p.t.Fatal("reply without unconnected data")
	}
	resp, err := cip.DecodeResponse(it.Data)
	if err != nil {
		p.t.Fatalf("response: %v", err)
	}
	return resp, rr.Items
}

// do sends an explicit request and returns the response.
func (p *peer) do(req cip.Request, extra ...encap.Item) cip.Response {
	p.t.Helper()
	b, err := req.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	r, _ := p.rrData(b, extra...)
	return r
}

func (p *peer) get(c cip.Class, inst uint32, attr uint16) cip.Response {
	p.t.Helper()
	return p.do(cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(c, inst, attr)})
}

func (p *peer) set(c cip.Class, inst uint32, attr uint16, data []byte) cip.Response {
	p.t.Helper()
	return p.do(cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(c, inst, attr), Data: data})
}

// unitData sends a SendUnitData on connection ot with sequence count seq,
// and returns the reply packet.
func (p *peer) unitData(ot uint32, seq uint16, req cip.Request) encap.Packet {
	p.t.Helper()
	msg, err := req.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	payload := binary.LittleEndian.AppendUint16(nil, seq)
	data, err := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(ot), {Type: encap.ItemConnectedData, Data: append(payload, msg...)}}}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	p.send(encap.CommandSendUnitData, p.handle, data)
	return p.recv()
}

// connectedResponse decodes the response of a SendUnitData reply.
func connectedResponse(t testing.TB, pkt encap.Packet) (uint32, uint16, cip.Response) {
	t.Helper()
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := encap.Find(rr.Items, encap.ItemConnectedAddress)
	id, err := encap.DecodeConnectedAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := encap.Find(rr.Items, encap.ItemConnectedData)
	if !ok || len(d.Data) < 2 {
		t.Fatal("no connected data")
	}
	resp, err := cip.DecodeResponse(d.Data[2:])
	if err != nil {
		t.Fatal(err)
	}
	return id, binary.LittleEndian.Uint16(d.Data), resp
}

var serialSeq atomic.Uint32

// fwdOpen returns a Forward_Open with a unique triad and the given
// transport and path; the defaults suit an exclusive owner connection to
// the test assemblies with the server's default formats.
func fwdOpen(class uint8, trig cip.Trigger, path cip.Path) cip.ForwardOpen {
	otSize, toSize := uint16(asmSize+2+4), uint16(asmSize+2)
	if class == 0 {
		otSize, toSize = asmSize+4, asmSize
	}
	if class == 3 {
		otSize, toSize = 500, 500
	}
	return cip.ForwardOpen{
		PriorityTick: 10, TimeoutTicks: 10,
		TOConnID:          0x1000 + serialSeq.Add(1),
		Triad:             cip.Triad{Serial: uint16(serialSeq.Add(1)), VendorID: 0x1234, OriginatorSerial: 0xCAFE},
		TimeoutMultiplier: 1,
		OTRPI:             10000,
		OTParams:          cip.NetworkParams{Type: cip.ConnectionPointToPoint, Size: otSize},
		TORPI:             10000,
		TOParams:          cip.NetworkParams{Type: cip.ConnectionPointToPoint, Size: toSize},
		Transport:         cip.NewTransportTrigger(class, trig, false),
		Path:              path,
	}
}

// ioPath is a connection path to the assemblies cfg (0: none), ot and to.
func ioPath(cfg, ot, to uint32) cip.Path {
	p := cip.Path{cip.ClassSegment(cip.ClassAssembly)}
	if cfg != 0 {
		p = append(p, cip.InstanceSegment(cfg))
	}
	return append(p, cip.ConnectionPointSegment(ot), cip.ConnectionPointSegment(to))
}

// open sends a Forward_Open (Large when fo.Large) and returns the response
// and the reply's items.
func (p *peer) open(fo cip.ForwardOpen, extra ...encap.Item) (cip.Response, []encap.Item) {
	p.t.Helper()
	data, err := fo.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	msg, err := cip.Request{Service: fo.Service(), Path: cip.ConnectionManagerPath(), Data: data}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	return p.rrData(msg, extra...)
}

// openNoFatal is open for use from other goroutines: failures are
// reported as a general error response.
func (p *peer) openNoFatal(fo cip.ForwardOpen) (cip.Response, error) {
	data, err := fo.Encode()
	if err != nil {
		return cip.Response{Status: cip.StatusGeneralError}, err
	}
	msg, _ := cip.Request{Service: fo.Service(), Path: cip.ConnectionManagerPath(), Data: data}.Encode()
	rr, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}}.Encode()
	p.ctx++
	h := encap.Header{Command: encap.CommandSendRRData, Session: p.handle}
	binary.LittleEndian.PutUint64(h.Context[:], p.ctx)
	b, _ := encap.Packet{Header: h, Data: rr}.Encode()
	if _, err := p.c.Write(b); err != nil {
		return cip.Response{Status: cip.StatusGeneralError}, err
	}
	pkt, err := p.tryRecv(5 * time.Second)
	if err != nil {
		return cip.Response{Status: cip.StatusGeneralError}, err
	}
	d, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		return cip.Response{Status: cip.StatusGeneralError}, err
	}
	it, _ := encap.Find(d.Items, encap.ItemUnconnectedData)
	resp, err := cip.DecodeResponse(it.Data)
	if err != nil {
		return cip.Response{Status: cip.StatusGeneralError}, err
	}
	return resp, nil
}

// mustOpen opens a connection and returns the reply.
func (p *peer) mustOpen(fo cip.ForwardOpen, extra ...encap.Item) (cip.ForwardOpenReply, []encap.Item) {
	p.t.Helper()
	resp, items := p.open(fo, extra...)
	if !resp.OK() {
		p.t.Fatalf("Forward_Open: %s %x", resp.Status, resp.Extended)
	}
	r, err := cip.DecodeForwardOpenReply(resp.Data)
	if err != nil {
		p.t.Fatal(err)
	}
	if r.Triad != fo.Triad {
		p.t.Fatalf("reply triad %v, want %v", r.Triad, fo.Triad)
	}
	return r, items
}

// connStatus returns the extended status of a connection failure.
func connStatus(r cip.Response) cip.ConnectionStatus {
	if r.Status != cip.StatusConnectionFailure || len(r.Extended) == 0 {
		return 0
	}
	return cip.ConnectionStatus(r.Extended[0])
}

func (p *peer) close(t cip.Triad, path cip.Path) cip.Response {
	p.t.Helper()
	data, err := cip.ForwardClose{PriorityTick: 10, TimeoutTicks: 10, Triad: t, Path: path}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	return p.do(cip.Request{Service: cip.ServiceForwardClose, Path: cip.ConnectionManagerPath(), Data: data})
}

// ioSocket is a UDP socket on loopback that receives T->O datagrams.
type ioSocket struct {
	t testing.TB
	c *net.UDPConn
}

func newIOSocket(t testing.TB) *ioSocket {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &ioSocket{t: t, c: c}
}

func (s *ioSocket) port() uint16 { return uint16(s.c.LocalAddr().(*net.UDPAddr).Port) }

// sockaddrTO is the Sockaddr Info T->O item that sends T->O datagrams to
// this socket.
func (s *ioSocket) sockaddrTO() encap.Item {
	return encap.Item{Type: encap.ItemSockaddrTO,
		Data: encap.SockaddrOf(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.port())).Encode()}
}

// recv returns the next datagram for connection id that satisfies ok.
func (s *ioSocket) recv(id uint32, ok func(implicit.Message) bool) implicit.Message {
	s.t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = s.c.SetReadDeadline(deadline)
		n, err := s.c.Read(buf)
		if err != nil {
			s.t.Fatalf("no datagram for connection %#x: %v", id, err)
		}
		m, err := implicit.Decode(append([]byte(nil), buf[:n]...))
		if err != nil || m.ConnID != id {
			continue
		}
		if ok == nil || ok(m) {
			return m
		}
	}
}

// sendIO sends one O->T datagram to the server.
func (s *ioSocket) sendIO(srv *Server, id, seq uint32, payload []byte) {
	s.t.Helper()
	b, err := implicit.Message{ConnID: id, EncapSeq: seq, Payload: payload}.Encode()
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.c.WriteToUDPAddrPort(b, srv.IOAddr()); err != nil {
		s.t.Fatal(err)
	}
}

// recMetrics records the callbacks of every metrics interface.
type recMetrics struct {
	mu        sync.Mutex
	connects  int
	discs     []error
	sent      map[encap.Command]int
	received  map[encap.Command]int
	decodeErr int
	handled   map[cip.Service][]cip.GeneralStatus
	opened    []ethernetip.ConnectionInfo
	closed    []error
	ioSent    int
	ioRecv    int
	ioDropped []string
}

func newRecMetrics() *recMetrics {
	return &recMetrics{sent: map[encap.Command]int{}, received: map[encap.Command]int{}, handled: map[cip.Service][]cip.GeneralStatus{}}
}

func (m *recMetrics) OnConnect(net.Addr) { m.mu.Lock(); m.connects++; m.mu.Unlock() }
func (m *recMetrics) OnDisconnect(_ net.Addr, err error) {
	m.mu.Lock()
	m.discs = append(m.discs, err)
	m.mu.Unlock()
}
func (m *recMetrics) OnPacketSent(_ net.Addr, c encap.Command, _ int) {
	m.mu.Lock()
	m.sent[c]++
	m.mu.Unlock()
}
func (m *recMetrics) OnPacketReceived(_ net.Addr, c encap.Command, _ int) {
	m.mu.Lock()
	m.received[c]++
	m.mu.Unlock()
}
func (m *recMetrics) OnDecodeError(net.Addr, error) { m.mu.Lock(); m.decodeErr++; m.mu.Unlock() }
func (m *recMetrics) OnHandled(_ net.Addr, s cip.Service, st cip.GeneralStatus, _ time.Duration) {
	m.mu.Lock()
	m.handled[s] = append(m.handled[s], st)
	m.mu.Unlock()
}
func (m *recMetrics) OnConnectionOpened(_ net.Addr, info ethernetip.ConnectionInfo) {
	m.mu.Lock()
	m.opened = append(m.opened, info)
	m.mu.Unlock()
}
func (m *recMetrics) OnConnectionClosed(_ net.Addr, _ ethernetip.ConnectionInfo, err error) {
	m.mu.Lock()
	m.closed = append(m.closed, err)
	m.mu.Unlock()
}
func (m *recMetrics) OnIOSent(uint32, int)     { m.mu.Lock(); m.ioSent++; m.mu.Unlock() }
func (m *recMetrics) OnIOReceived(uint32, int) { m.mu.Lock(); m.ioRecv++; m.mu.Unlock() }
func (m *recMetrics) OnIODropped(_ net.Addr, reason string) {
	m.mu.Lock()
	m.ioDropped = append(m.ioDropped, reason)
	m.mu.Unlock()
}

func (m *recMetrics) with(f func(m *recMetrics) bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return f(m)
}
