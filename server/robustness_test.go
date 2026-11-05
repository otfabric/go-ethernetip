// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// TestRandomMessages sends random explicit messages, valid encapsulation
// carrying random CIP, to every object of a server with assemblies. The
// server must answer each one (a panic would end the test binary) and keep
// serving.
func TestRandomMessages(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	rng := rand.New(rand.NewSource(1))
	classes := s.Classes()
	services := []cip.Service{
		cip.ServiceGetAttributesAll, cip.ServiceGetAttributeList, cip.ServiceReset,
		cip.ServiceMultipleServicePacket, cip.ServiceGetAttributeSingle, cip.ServiceSetAttributeSingle,
		cip.ServiceForwardClose, cip.ServiceUnconnectedSend, cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen,
	}
	n := 3000
	if testing.Short() {
		n = 300
	}
	for i := 0; i < n; i++ {
		svc := services[rng.Intn(len(services))]
		path := cip.Path{cip.ClassSegment(classes[rng.Intn(len(classes))]), cip.InstanceSegment(uint32(rng.Intn(3)))}
		if rng.Intn(2) == 0 {
			path = append(path, cip.AttributeSegment(uint16(rng.Intn(20))))
		}
		data := make([]byte, rng.Intn(64))
		rng.Read(data)
		if svc == cip.ServiceForwardOpen && rng.Intn(2) == 0 {
			// A valid header with a random path tail.
			fo := fwdOpen(uint8(rng.Intn(4)), cip.Trigger(rng.Intn(3)), ioPath(uint32(rng.Intn(3))*asmCfg, asmOut, asmIn))
			b, err1 := fo.Encode()
			pb, err2 := fo.Path.Encode()
			if err1 == nil && err2 == nil {
				head := append([]byte(nil), b[:len(b)-len(pb)]...)
				tail := append(pb[:len(pb)-2:len(pb)-2], data[:len(data)&^1]...)
				head[len(head)-1] = byte(len(tail) / 2)
				data = append(head, tail...)
			}
		}
		msg, err := cip.Request{Service: svc, Path: path, Data: data}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		r, _ := p.rrData(msg)
		if r.Service != svc && svc != cip.ServiceUnconnectedSend {
			t.Fatalf("reply service %v to %v", r.Service, svc)
		}
	}
	// Random octets as the message.
	for i := 0; i < n; i++ {
		b := make([]byte, rng.Intn(40))
		rng.Read(b)
		p.rrData(b)
	}
	// Random encapsulation data for every command.
	for i := 0; i < n/10; i++ {
		cmds := []encap.Command{encap.CommandSendRRData, encap.CommandSendUnitData, encap.CommandRegisterSession, encap.CommandListIdentity}
		b := make([]byte, rng.Intn(80))
		rng.Read(b)
		cmd := cmds[rng.Intn(len(cmds))]
		p.send(cmd, p.handle, b)
		// A ListServices fence: every packet before its reply answers
		// the random one (SendUnitData may also go unanswered).
		fence := p.send(encap.CommandListServices, 0, nil)
		replies := 0
		for {
			r, err := p.tryRecv(5 * time.Second)
			if err != nil {
				t.Fatalf("%s with random data: %v", cmd, err)
			}
			if r.Context == fence.Context {
				break
			}
			replies++
		}
		if replies > 1 || replies == 0 && cmd != encap.CommandSendUnitData {
			t.Fatalf("%s with random data answered %d times", cmd, replies)
		}
	}
	// Random connected messages on a Class 3 connection.
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.OTRPI = 10_000_000
	reply, _ := p.mustOpen(fo)
	for i := 0; i < n/10; i++ {
		b := make([]byte, rng.Intn(40))
		rng.Read(b)
		payload := append([]byte{byte(i), byte(i >> 8)}, b...)
		data, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(reply.OTConnID), {Type: encap.ItemConnectedData, Data: payload}}}.Encode()
		p.send(encap.CommandSendUnitData, p.handle, data)
		r := p.recv()
		if r.Command != encap.CommandSendUnitData || r.Status != encap.StatusSuccess {
			t.Fatalf("connected random message: %s %s", r.Command, r.Status)
		}
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("server not serving after random input: %s", r.Status)
	}
}

// TestClassBeyond16Bits: class codes are 16-bit. A class segment value
// above 0xFFFF addresses no object; truncated, 0x1FFFF would have reached
// class 0xFFFF and 0x10001 the Identity object. The cip decoder refuses
// 32-bit class segments on the wire; the router and the Connection
// Manager do not rely on it.
func TestClassBeyond16Bits(t *testing.T) {
	s := startServer(t)
	top := NewObject(0xFFFF, 1)
	top.AddInstance(1).SetAttribute(1, Attribute{Get: func() []byte { return []byte{7} }})
	s.RegisterObject(top)
	get := func(class uint32) cip.Response {
		path := cip.Path{cip.LogicalSegment{Type: cip.LogicalClass, Value: class}, cip.InstanceSegment(1), cip.AttributeSegment(1)}
		return s.route(context.Background(), cip.Request{Service: cip.ServiceGetAttributeSingle, Path: path}, nil, false)
	}
	if r := get(0xFFFF); !r.OK() || !bytes.Equal(r.Data, []byte{7}) {
		t.Errorf("class 0xFFFF: %s %x", r.Status, r.Data)
	}
	for _, c := range []uint32{0x10000, 0x10001, 0x1FFFF, math.MaxUint32} {
		if r := get(c); r.Status != cip.StatusPathDestinationUnknown {
			t.Errorf("class 0x%X: %s %x, want path destination unknown", c, r.Status, r.Data)
		}
	}
	// On the wire: class 0x10001 in a 32-bit segment is not Identity.
	p := dialPeer(t, s)
	p.register()
	if r, _ := p.rrData([]byte{0x0E, 5, 0x23, 0, 1, 0, 1, 0, 0x24, 1, 0x30, 1}); r.OK() {
		t.Errorf("32-bit class 0x10001 answered: %x", r.Data)
	}

	// The connection path of a Forward_Open likewise.
	path := func(class uint32) cip.Path {
		return cip.Path{cip.LogicalSegment{Type: cip.LogicalClass, Value: class}, cip.InstanceSegment(1)}
	}
	if op, f := s.cm.parsePath(path(0xFFFF)); f != nil || op.class != 0xFFFF {
		t.Errorf("connection path to class 0xFFFF: %+v %v", op, f)
	}
	if _, f := s.cm.parsePath(path(0x10000 | uint32(cip.ClassMessageRouter))); f == nil || f.extended[0] != uint16(cip.ConnStatusInvalidSegment) {
		t.Errorf("connection path to class 0x10002: %v", f)
	}
}

func TestSaturate(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want uint16
	}{{-1, 0}, {0, 0}, {1, 1}, {0xFFFE, 0xFFFE}, {0xFFFF, 0xFFFF}, {0x10000, 0xFFFF}, {math.MaxInt, 0xFFFF}} {
		if got := saturate16(tc.in); got != tc.want {
			t.Errorf("saturate16(%d) = %d", tc.in, got)
		}
	}
	for _, tc := range []struct {
		in   uint32
		want uint16
	}{{0xFFFF, 0xFFFF}, {0x10000, 0xFFFF}, {math.MaxUint32, 0xFFFF}} {
		if got := saturate16(tc.in); got != tc.want {
			t.Errorf("saturate16(%d) = %d", tc.in, got)
		}
	}
	for _, tc := range []struct {
		in   int
		want uint8
	}{{-1, 0}, {0, 0}, {254, 254}, {255, 255}, {256, 255}} {
		if got := saturate8(tc.in); got != tc.want {
			t.Errorf("saturate8(%d) = %d", tc.in, got)
		}
	}
}

// TestClassAttributesSaturate: Max Instance and Number of Instances are
// UINTs; 32-bit instance IDs report 0xFFFF rather than wrapping to 0.
func TestClassAttributesSaturate(t *testing.T) {
	o := NewObject(0x64, 1)
	maxInst := func() uint16 { return binary.LittleEndian.Uint16(o.classAttrs[2].Get()) }
	o.AddInstance(0xFFFF)
	if got := maxInst(); got != 0xFFFF {
		t.Errorf("max instance 0xFFFF: %#x", got)
	}
	o.AddInstance(0x10000)
	if got := maxInst(); got != 0xFFFF {
		t.Errorf("max instance 0x10000: %#x", got)
	}
}

// classOnly is an object that answers nothing, for registering many.
type classOnly cip.Class

func (c classOnly) Class() cip.Class                              { return cip.Class(c) }
func (classOnly) ServeCIP(context.Context, *Request) cip.Response { return cip.Response{} }

func TestMessageRouterAttributesSaturate(t *testing.T) {
	if _, err := New(WithMaxConnections(math.MaxUint16 + 1)); err == nil {
		t.Error("WithMaxConnections(65536) accepted")
	}
	s, err := New(WithMaxConnections(math.MaxUint16))
	if err != nil {
		t.Fatal(err)
	}
	mr := s.Object(cip.ClassMessageRouter).(*StandardObject).Instance(1)
	if got := binary.LittleEndian.Uint16(mr.attrs[2].Get()); got != 0xFFFF {
		t.Errorf("connections supported = %#x", got)
	}
	// Every class code registered: 65536 classes, of which the UINT
	// count lists the first 65535.
	for c := 0; c <= math.MaxUint16; c++ {
		if s.Object(cip.Class(c)) == nil {
			s.RegisterObject(classOnly(c))
		}
	}
	b := mr.attrs[1].Get()
	if n := binary.LittleEndian.Uint16(b); n != 0xFFFF || len(b) != 2+2*0xFFFF {
		t.Errorf("object list: count %#x, %d octets", n, len(b))
	}
}

// TestDelayedDiscoveryBound: delayed UDP ListIdentity replies beyond
// maxPendingDiscovery are dropped; the last one that fits is answered.
func TestDelayedDiscoveryBound(t *testing.T) {
	s := startServer(t, WithDiscoveryDelay(time.Millisecond))
	if s.UDPAddr() == nil {
		t.Skip("UDP explicit port not available")
	}
	var ctx [8]byte
	binary.LittleEndian.PutUint16(ctx[:], 1)
	s.pendingDiscovery.Store(maxPendingDiscovery - 1)
	udpRoundTrip(t, s, encap.CommandListIdentity, ctx)
	waitFor(t, "pending reply done", func() bool { return s.pendingDiscovery.Load() == maxPendingDiscovery-1 })

	s.pendingDiscovery.Store(maxPendingDiscovery)
	c, err := net.DialUDP("udp4", nil, s.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b, _ := encap.Packet{Header: encap.Header{Command: encap.CommandListIdentity, Context: ctx}}.Encode()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("ListIdentity beyond the pending bound answered (%d octets)", n)
	}
	if got := s.pendingDiscovery.Load(); got != maxPendingDiscovery {
		t.Errorf("pending = %d after a dropped request", got)
	}
	// Undelayed requests are not bounded.
	s.pendingDiscovery.Store(maxPendingDiscovery)
	udpRoundTrip(t, s, encap.CommandListServices, [8]byte{})
	s.pendingDiscovery.Store(0)
}

func (s *Server) tcpConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// TestTCPConnectionLimit: the server holds at most 2*maxSessions+16 TCP
// connections, registered or not; one more is closed on accept, and a
// closed one makes room again.
func TestTCPConnectionLimit(t *testing.T) {
	s := startServer(t, WithMaxSessions(1), WithInactivityTimeout(0))
	limit := s.maxTCPConns()
	if limit != 18 {
		t.Fatalf("limit %d", limit)
	}
	peers := make([]*peer, limit)
	for i := range peers {
		peers[i] = dialPeer(t, s)
		peers[i].roundTrip(encap.CommandListServices, 0, nil)
	}
	waitFor(t, "connections", func() bool { return s.tcpConns() == limit })
	extra := dialPeer(t, s)
	extra.expectClosed()
	if n := s.tcpConns(); n != limit {
		t.Errorf("%d connections after the refused one", n)
	}
	_ = peers[0].c.Close()
	waitFor(t, "connection released", func() bool { return s.tcpConns() == limit-1 })
	p := dialPeer(t, s)
	p.roundTrip(encap.CommandListServices, 0, nil)

	big := &Server{opts: options{maxSessions: math.MaxInt}}
	if big.maxTCPConns() != math.MaxInt {
		t.Errorf("limit for MaxInt sessions: %d", big.maxTCPConns())
	}
}

// TestCloseUnregistered: Close ends TCP connections that never
// registered, even without an inactivity timeout.
func TestCloseUnregistered(t *testing.T) {
	s := startServer(t, WithInactivityTimeout(0))
	p := dialPeer(t, s)
	p.roundTrip(encap.CommandListServices, 0, nil)
	// A slowloris peer: half a header.
	slow := dialPeer(t, s)
	slow.write(make([]byte, encap.HeaderSize/2))
	waitFor(t, "connections", func() bool { return s.tcpConns() == 2 })
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked by unregistered connections")
	}
	p.expectClosed()
	slow.expectClosed()
	if n := s.tcpConns(); n != 0 {
		t.Errorf("%d connections after Close", n)
	}
}

// TestPartialHeaderTimeout: a header sent in part is subject to the
// inactivity timeout.
func TestPartialHeaderTimeout(t *testing.T) {
	s := startServer(t, WithInactivityTimeout(100*time.Millisecond))
	p := dialPeer(t, s)
	p.write(make([]byte, encap.HeaderSize-1))
	p.expectClosed()
	waitFor(t, "connection released", func() bool { return s.tcpConns() == 0 })
}

// TestConcurrentForwardOpenLimit: Forward_Opens racing on many sessions
// never open more connections than the limit.
func TestConcurrentForwardOpenLimit(t *testing.T) {
	const limit, sessions = 2, 16
	s := startIOServer(t, WithMaxConnections(limit))
	peers := make([]*peer, sessions)
	for i := range peers {
		peers[i] = dialPeer(t, s)
		peers[i].register()
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened, refused := 0, 0
	for _, p := range peers {
		wg.Go(func() {
			r, err := p.openNoFatal(fwdOpen(3, cip.TriggerApplication, explicitPath))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("Forward_Open: %v", err)
			case r.OK():
				opened++
			case connStatus(r) == cip.ConnStatusOutOfConnections:
				refused++
			default:
				t.Errorf("Forward_Open: %s %x", r.Status, r.Extended)
			}
		})
	}
	wg.Wait()
	if opened != limit || refused != sessions-limit || len(s.Connections()) != limit {
		t.Errorf("%d opened, %d refused, %d connections", opened, refused, len(s.Connections()))
	}
}

// TestOversizeConnectedReply: a Class 3 reply that cannot fit a
// SendUnitData is answered with reply data too large; the largest one
// that fits is sent as it is.
func TestOversizeConnectedReply(t *testing.T) {
	s := startIOServer(t)
	o := NewObject(0x0300, 1)
	in := o.AddInstance(1)
	// The response is the 4-octet reply header and the attribute.
	in.SetAttribute(1, Attribute{Get: func() []byte { return make([]byte, maxConnectedReply-4) }})
	in.SetAttribute(2, Attribute{Get: func() []byte { return make([]byte, maxConnectedReply-3) }})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	// Large_Forward_Open: a T->O size that holds the largest reply, so
	// that the packet, not the connection, is the bound.
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.OTRPI = 10_000_000
	fo.Large = true
	fo.TOParams.Size = maxConnectedReply + 2
	reply, _ := p.mustOpen(fo)
	req := func(attr uint16) cip.Request {
		return cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, attr)}
	}
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 1, req(1))); !r.OK() || len(r.Data) != maxConnectedReply-4 {
		t.Errorf("largest reply: %s, %d octets", r.Status, len(r.Data))
	}
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 2, req(2))); r.Status != cip.StatusReplyDataTooLarge || r.Service != cip.ServiceGetAttributeSingle {
		t.Errorf("one octet more: %s service %v", r.Status, r.Service)
	}
}
