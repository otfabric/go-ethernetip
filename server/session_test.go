// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

func TestRegisterSession(t *testing.T) {
	s := startServer(t, WithMaxSessions(1))
	p := dialPeer(t, s)

	// Bad length: 3 and 5 octets.
	for _, data := range [][]byte{{1, 0, 0}, {1, 0, 0, 0, 0}} {
		if r := p.roundTrip(encap.CommandRegisterSession, 0, data); r.Status != encap.StatusInvalidLength || r.Session != 0 {
			t.Errorf("%d octets: status %s session %d", len(data), r.Status, r.Session)
		}
	}
	// Unsupported version or options: the reply carries version 1.
	for _, reg := range []encap.Register{{ProtocolVersion: 2}, {ProtocolVersion: 1, Options: 1}} {
		r := p.roundTrip(encap.CommandRegisterSession, 0, reg.Encode())
		if r.Status != encap.StatusUnsupportedProtocol {
			t.Errorf("%+v: status %s", reg, r.Status)
		}
		if got, _ := encap.DecodeRegister(r.Data); got.ProtocolVersion != 1 {
			t.Errorf("%+v: reply version %d", reg, got.ProtocolVersion)
		}
	}
	if s.Sessions() != 0 {
		t.Fatalf("Sessions = %d after refusals", s.Sessions())
	}
	h := p.register()
	if s.Sessions() != 1 {
		t.Fatalf("Sessions = %d", s.Sessions())
	}
	// Twice on one socket: invalid command, the session stays.
	if r := p.roundTrip(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode()); r.Status != encap.StatusInvalidCommand {
		t.Errorf("second RegisterSession: status %s", r.Status)
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("request after a second RegisterSession: %s", r.Status)
	}
	// Beyond the maximum: insufficient memory.
	q := dialPeer(t, s)
	if r := q.roundTrip(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode()); r.Status != encap.StatusInsufficientMemory {
		t.Errorf("RegisterSession beyond the maximum: status %s", r.Status)
	}
	// UnRegisterSession with a wrong handle is refused; with the right one
	// it closes the connection without a reply.
	if r := p.roundTrip(encap.CommandUnRegisterSession, h+1, nil); r.Status != encap.StatusInvalidSessionHandle {
		t.Errorf("UnRegisterSession wrong handle: status %s", r.Status)
	}
	p.send(encap.CommandUnRegisterSession, h, nil)
	p.expectClosed()
	waitFor(t, "session removed", func() bool { return s.Sessions() == 0 })
	// The slot is free again.
	q.register()
	// UnRegisterSession before RegisterSession is refused.
	r := dialPeer(t, s)
	if pkt := r.roundTrip(encap.CommandUnRegisterSession, 0, nil); pkt.Status != encap.StatusInvalidSessionHandle {
		t.Errorf("UnRegisterSession without a session: %s", pkt.Status)
	}
}

func TestSendRRDataErrors(t *testing.T) {
	m := newRecMetrics()
	s := startServer(t, WithMetrics(m))
	p := dialPeer(t, s)
	good, _ := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}.Encode()
	rr := func(r encap.RRData) []byte {
		b, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: good}}})

	for _, cmd := range []encap.Command{encap.CommandSendRRData, encap.CommandSendUnitData} {
		if r := p.roundTrip(cmd, 0, valid); r.Status != encap.StatusInvalidSessionHandle {
			t.Errorf("%s without a session: %s", cmd, r.Status)
		}
	}
	h := p.register()
	for _, cmd := range []encap.Command{encap.CommandSendRRData, encap.CommandSendUnitData} {
		if r := p.roundTrip(cmd, h^0xFFFF, valid); r.Status != encap.StatusInvalidSessionHandle {
			t.Errorf("%s with a wrong handle: %s", cmd, r.Status)
		}
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated", []byte{0, 0, 0}},
		{"malformed CPF", []byte{0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 9, 0}},
		{"interface handle", rr(encap.RRData{InterfaceHandle: 1, Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: good}}})},
		{"no null address", rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemUnconnectedData, Data: good}}})},
		{"no message", rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}}})},
		{"null address with data", rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress, Data: []byte{1, 2}}, {Type: encap.ItemUnconnectedData, Data: good}}})},
	}
	for _, tc := range cases {
		if r := p.roundTrip(encap.CommandSendRRData, h, tc.data); r.Status != encap.StatusIncorrectData {
			t.Errorf("SendRRData %s: %s", tc.name, r.Status)
		}
	}
	unit := []struct {
		name string
		data []byte
	}{
		{"truncated", []byte{0, 0}},
		{"no address", rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemConnectedData, Data: []byte{1, 0}}}})},
		{"no data", rr(encap.RRData{Items: []encap.Item{encap.ConnectedAddress(1)}})},
		{"bad address", rr(encap.RRData{Items: []encap.Item{{Type: encap.ItemConnectedAddress, Data: []byte{1}}, {Type: encap.ItemConnectedData, Data: []byte{1, 0}}}})},
		{"no sequence count", rr(encap.RRData{Items: []encap.Item{encap.ConnectedAddress(1), {Type: encap.ItemConnectedData, Data: []byte{1}}}})},
	}
	for _, tc := range unit {
		if r := p.roundTrip(encap.CommandSendUnitData, h, tc.data); r.Status != encap.StatusIncorrectData {
			t.Errorf("SendUnitData %s: %s", tc.name, r.Status)
		}
	}
	// SendUnitData for an unknown connection is not answered.
	p.send(encap.CommandSendUnitData, h, rr(encap.RRData{Items: []encap.Item{encap.ConnectedAddress(0xDEAD), {Type: encap.ItemConnectedData, Data: append([]byte{1, 0}, good...)}}}))
	// Nor is NOP; the next request proves the session is still served.
	p.send(encap.CommandNOP, 0, []byte{1, 2, 3})
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("request after NOP: %s", r.Status)
	}
	// A malformed CIP message is answered and reported.
	malformed, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: []byte{0x0E}}}}.Encode()
	if r := p.roundTrip(encap.CommandSendRRData, h, malformed); r.Status != encap.StatusSuccess {
		t.Errorf("malformed message: encapsulation status %s", r.Status)
	}
	// Unknown command.
	if r := p.roundTrip(encap.Command(0x0099), h, nil); r.Status != encap.StatusInvalidCommand {
		t.Errorf("unknown command: %s", r.Status)
	}
	if !m.with(func(m *recMetrics) bool { return m.decodeErr >= 4 && m.received[encap.CommandNOP] == 1 }) {
		t.Error("decode errors or NOP not reported to metrics")
	}
}

func TestOptionsDiscardedAndPartialWrites(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	// A packet with options set is discarded without a reply.
	b, _ := encap.Packet{Header: encap.Header{Command: encap.CommandListIdentity, Options: 1}}.Encode()
	p.write(b)
	// A packet written one octet at a time is answered.
	b, _ = encap.Packet{Header: encap.Header{Command: encap.CommandListServices, Context: [8]byte{7}}}.Encode()
	for i := range b {
		p.write(b[i : i+1])
	}
	r := p.recv()
	if r.Command != encap.CommandListServices || r.Context[0] != 7 {
		t.Fatalf("reply %s context %x: the discarded packet was answered", r.Command, r.Context)
	}
	items, err := encap.DecodeCPF(r.Data)
	if err != nil || len(items) != 1 || items[0].Type != encap.ItemListServices {
		t.Fatalf("ListServices items %v, %v", items, err)
	}
	svc, err := encap.DecodeServiceItem(items[0].Data)
	if err != nil || svc.Name != "Communications" {
		t.Fatalf("service item %+v, %v", svc, err)
	}
}

func TestPacketTooLarge(t *testing.T) {
	m := newRecMetrics()
	s := startServer(t, WithMaxPacket(600), WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	h := encap.Header{Command: encap.CommandSendRRData, Length: 601, Session: p.handle}
	p.write(h.AppendTo(nil))
	r := p.recv()
	if r.Status != encap.StatusInvalidLength || r.Command != encap.CommandSendRRData {
		t.Fatalf("reply %s status %s", r.Command, r.Status)
	}
	p.expectClosed()
	waitFor(t, "disconnect reported", func() bool {
		return m.with(func(m *recMetrics) bool { return len(m.discs) == 1 && m.discs[0] != nil })
	})
}

func TestListCommandsTCP(t *testing.T) {
	id := DefaultIdentity
	id.ProductName = "list test"
	s := startServer(t, WithIdentity(id))
	p := dialPeer(t, s)
	// List commands need no session.
	r := p.roundTrip(encap.CommandListIdentity, 0, nil)
	items, err := encap.DecodeCPF(r.Data)
	if err != nil || len(items) != 1 {
		t.Fatalf("ListIdentity items %v, %v", items, err)
	}
	it, err := encap.DecodeIdentityItem(items[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if it.ProductName != "list test" || it.Socket.AddrPort() != netip.MustParseAddrPort(s.Addr().String()) {
		t.Errorf("identity item %+v socket %v", it.Identity, it.Socket.AddrPort())
	}
	r = p.roundTrip(encap.CommandListInterfaces, 0, nil)
	if !bytes.Equal(r.Data, []byte{0, 0}) {
		t.Errorf("ListInterfaces data %x", r.Data)
	}
}

func udpRoundTrip(t *testing.T, s *Server, cmd encap.Command, ctx [8]byte) (encap.Packet, time.Duration) {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, s.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b, _ := encap.Packet{Header: encap.Header{Command: cmd, Session: 5, Context: ctx}}.Encode()
	start := time.Now()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s over UDP: %v", cmd, err)
	}
	pkt, err := encap.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Command != cmd || pkt.Context != ctx || pkt.Session != 0 || pkt.Status != encap.StatusSuccess {
		t.Fatalf("UDP reply %+v", pkt.Header)
	}
	return pkt, time.Since(start)
}

func TestListCommandsUDP(t *testing.T) {
	s := startServer(t, WithDiscoveryDelay(50*time.Millisecond))
	if s.UDPAddr() == nil {
		t.Skip("UDP explicit port not available")
	}
	pkt, _ := udpRoundTrip(t, s, encap.CommandListIdentity, [8]byte{})
	items, _ := encap.DecodeCPF(pkt.Data)
	it, err := encap.DecodeIdentityItem(items[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if got := it.Socket.AddrPort().Addr(); got != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("identity socket address %v", got)
	}
	// A request asking for a delay of up to 20 ms is answered with one.
	var ctx [8]byte
	binary.LittleEndian.PutUint16(ctx[:], 20)
	if _, d := udpRoundTrip(t, s, encap.CommandListIdentity, ctx); d > 2*time.Second {
		t.Errorf("delayed reply took %v", d)
	}
	pkt, _ = udpRoundTrip(t, s, encap.CommandListServices, [8]byte{1})
	if items, err := encap.DecodeCPF(pkt.Data); err != nil || items[0].Type != encap.ItemListServices {
		t.Errorf("ListServices over UDP: %v %v", items, err)
	}
	pkt, _ = udpRoundTrip(t, s, encap.CommandListInterfaces, [8]byte{2})
	if !bytes.Equal(pkt.Data, []byte{0, 0}) {
		t.Errorf("ListInterfaces over UDP: %x", pkt.Data)
	}

	// Other commands, malformed datagrams and options are ignored; the
	// socket keeps serving.
	c, err := net.DialUDP("udp4", nil, s.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	reg, _ := encap.Packet{Header: encap.Header{Command: encap.CommandRegisterSession}, Data: encap.Register{ProtocolVersion: 1}.Encode()}.Encode()
	opt, _ := encap.Packet{Header: encap.Header{Command: encap.CommandListIdentity, Options: 1}}.Encode()
	for _, b := range [][]byte{reg, opt, {1, 2, 3}} {
		_, _ = c.Write(b)
	}
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("ignored datagram answered (%d octets)", n)
	}
	udpRoundTrip(t, s, encap.CommandListServices, [8]byte{3})
}

func TestDiscoveryDelay(t *testing.T) {
	s := &Server{opts: defaultOptions()}
	li := encap.Packet{Header: encap.Header{Command: encap.CommandListIdentity}}
	if d := s.discoveryDelay(li); d != 0 {
		t.Errorf("delay without WithDiscoveryDelay: %v", d)
	}
	s.opts.discoveryDelayMax = 30 * time.Millisecond
	ls := encap.Packet{Header: encap.Header{Command: encap.CommandListServices}}
	if d := s.discoveryDelay(ls); d != 0 {
		t.Errorf("ListServices delayed by %v", d)
	}
	for i := 0; i < 100; i++ {
		if d := s.discoveryDelay(li); d < 0 || d >= 30*time.Millisecond {
			t.Fatalf("delay %v outside [0, 30ms)", d)
		}
		binary.LittleEndian.PutUint16(li.Context[:], 5)
		if d := s.discoveryDelay(li); d < 0 || d >= 5*time.Millisecond {
			t.Fatalf("delay %v outside the requested 5 ms", d)
		}
		binary.LittleEndian.PutUint16(li.Context[:], 0)
	}
}

func TestReplyAddr(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got := replyAddr(c, netip.MustParseAddrPort("127.0.0.1:9"))
	if ua, ok := got.(*net.UDPAddr); !ok || !ua.IP.IsLoopback() {
		t.Errorf("replyAddr of a wildcard socket = %v, want a loopback address", got)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if got := replyAddr(b, netip.MustParseAddrPort("127.0.0.1:9")); got.String() != b.LocalAddr().String() {
		t.Errorf("replyAddr of a bound socket = %v", got)
	}
	// An unroutable peer falls back to the local address.
	if got := replyAddr(c, netip.AddrPortFrom(netip.IPv6Loopback(), 9)); got.String() != c.LocalAddr().String() {
		t.Errorf("replyAddr fallback = %v", got)
	}
}

func TestInactivityTimeout(t *testing.T) {
	m := newRecMetrics()
	s := startServer(t, WithInactivityTimeout(50*time.Millisecond), WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	p.expectClosed()
	waitFor(t, "session removed", func() bool { return s.Sessions() == 0 })
	// The idle close is reported as an error.
	waitFor(t, "disconnect", func() bool {
		return m.with(func(m *recMetrics) bool { return len(m.discs) == 1 && m.discs[0] != nil })
	})
}

func TestInactivityAttribute(t *testing.T) {
	s := startServer(t, WithInactivityTimeout(0))
	p := dialPeer(t, s)
	p.register()
	if r := p.get(cip.ClassTCPIPInterface, 1, 13); !r.OK() || binary.LittleEndian.Uint16(r.Data) != 0 {
		t.Fatalf("attribute 13 = %x %s", r.Data, r.Status)
	}
	for _, tc := range []struct {
		data []byte
		want cip.GeneralStatus
	}{
		{[]byte{1}, cip.StatusNotEnoughData},
		{[]byte{1, 0, 0}, cip.StatusTooMuchData},
		{cip.AppendUint16(nil, 3601), cip.StatusInvalidAttributeValue},
		{cip.AppendUint16(nil, 1), cip.StatusSuccess},
	} {
		if r := p.set(cip.ClassTCPIPInterface, 1, 13, tc.data); r.Status != tc.want {
			t.Errorf("set %x: %s, want %s", tc.data, r.Status, tc.want)
		}
	}
	if r := p.get(cip.ClassTCPIPInterface, 1, 13); binary.LittleEndian.Uint16(r.Data) != 1 {
		t.Fatalf("attribute 13 after Set = %x", r.Data)
	}
	if s.inactivityTimeout() != time.Second {
		t.Fatalf("inactivity = %v", s.inactivityTimeout())
	}
	// A new connection idles out after one second.
	q := dialPeer(t, s)
	start := time.Now()
	q.expectClosed()
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Errorf("closed after %v, want about 1s", d)
	}
}
