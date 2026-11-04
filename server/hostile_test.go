// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// The tests of this file play a hostile originator against the server:
// stalled and dripping packets, forged session handles, floods, unknown
// commands, inconsistent CPF, absurd Forward_Opens, 32-bit logical IDs and
// malformed Multiple Service Packets. The server must answer with the
// right status or close the connection, stay up, and close promptly.

// hostileHeader returns the encoding of a header announcing length octets
// of data.
func hostileHeader(cmd encap.Command, length uint16, session uint32) []byte {
	return encap.Header{Command: cmd, Length: length, Session: session}.AppendTo(nil)
}

// hostileFence sends ListServices and reads until its reply: every packet
// before it is returned. It fails the test when the connection ends.
func hostileFence(t *testing.T, p *peer) []encap.Packet {
	t.Helper()
	h := p.send(encap.CommandListServices, 0, nil)
	var before []encap.Packet
	for {
		r, err := p.tryRecv(5 * time.Second)
		if err != nil {
			t.Fatalf("fence: %v", err)
		}
		if r.Command == encap.CommandListServices && r.Context == h.Context {
			return before
		}
		before = append(before, r)
	}
}

// hostileStillServing checks that a fresh originator gets a correct answer.
func hostileStillServing(t *testing.T, s *Server) {
	t.Helper()
	p := dialPeer(t, s)
	p.register()
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() || len(r.Data) != 2 {
		t.Fatalf("server not serving: %s % X", r.Status, r.Data)
	}
}

// hostileClosedWithin reads from c until it is closed by the server and
// fails when that takes longer than d.
func hostileClosedWithin(t *testing.T, c net.Conn, d time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(d))
	buf := make([]byte, 512)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open after %v", d)
		}
		return time.Since(start)
	}
}

// TestHostileSlowloris stalls inside packets: a header announcing data that
// never comes, half a header, and a packet whose octets drip in slower
// than the inactivity timeout allows for the whole packet. Each connection
// is closed by the inactivity timeout, the session is removed and the
// server keeps serving.
func TestHostileSlowloris(t *testing.T) {
	s := startServer(t, WithInactivityTimeout(100*time.Millisecond))
	cases := []struct {
		name string
		run  func(p *peer)
	}{
		{"announced 4000 octets, none sent", func(p *peer) {
			p.write(hostileHeader(encap.CommandSendRRData, 4000, p.handle))
		}},
		{"announced 4000 octets, 100 sent", func(p *peer) {
			p.write(append(hostileHeader(encap.CommandSendRRData, 4000, p.handle), make([]byte, 100)...))
		}},
		{"half a header", func(p *peer) {
			p.write(hostileHeader(encap.CommandSendRRData, 10, p.handle)[:10])
		}},
		{"one octet", func(p *peer) { p.write([]byte{0x6F}) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := dialPeer(t, s)
			p.register()
			c.run(p)
			if d := hostileClosedWithin(t, p.c, 3*time.Second); d > 2*time.Second {
				t.Fatalf("closed after %v", d)
			}
		})
	}
	t.Run("drip", func(t *testing.T) {
		p := dialPeer(t, s)
		p.register()
		hdr := hostileHeader(encap.CommandSendRRData, 200, p.handle)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			// One octet every 20 ms: each read makes progress, the packet
			// never completes within the timeout.
			for _, b := range append(hdr, make([]byte, 200)...) {
				select {
				case <-stop:
					return
				case <-time.After(20 * time.Millisecond):
				}
				if _, err := p.c.Write([]byte{b}); err != nil {
					return
				}
			}
		})
		d := hostileClosedWithin(t, p.c, 3*time.Second)
		close(stop)
		wg.Wait()
		if d > 2*time.Second {
			t.Fatalf("dripping connection closed after %v", d)
		}
	})
	waitFor(t, "sessions removed", func() bool { return s.Sessions() == 0 })
	hostileStillServing(t, s)
}

// TestHostileAnnouncedMaximum announces the largest length the header can
// carry: the server refuses it with invalid length before reading the
// data and closes the session.
func TestHostileAnnouncedMaximum(t *testing.T) {
	s := startServer(t)
	for _, cmd := range []encap.Command{encap.CommandSendRRData, encap.CommandRegisterSession, encap.CommandNOP, 0x7777} {
		p := dialPeer(t, s)
		p.write(hostileHeader(cmd, 0xFFFF, 0))
		r := p.recv()
		if r.Status != encap.StatusInvalidLength {
			t.Fatalf("%s: status %s", cmd, r.Status)
		}
		p.expectClosed()
	}
	hostileStillServing(t, s)
}

// TestHostileForeignSessionHandle uses the session handle of another
// connection: requests and UnRegisterSession with it are refused, and the
// owner's session is untouched.
func TestHostileForeignSessionHandle(t *testing.T) {
	s := startServer(t)
	owner := dialPeer(t, s)
	h := owner.register()
	thief := dialPeer(t, s)
	rr, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: mustEncode(t, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)})}}}.Encode()
	ud, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(1), {Type: encap.ItemConnectedData, Data: []byte{0, 0, 1, 0}}}}.Encode()
	try := func(what string) {
		t.Helper()
		for _, x := range []struct {
			cmd  encap.Command
			data []byte
		}{{encap.CommandSendRRData, rr}, {encap.CommandSendUnitData, ud}, {encap.CommandUnRegisterSession, nil}} {
			r := thief.roundTrip(x.cmd, h, x.data)
			if r.Status != encap.StatusInvalidSessionHandle {
				t.Fatalf("%s: %s with the owner's handle: status %s", what, x.cmd, r.Status)
			}
		}
		for _, other := range []uint32{h + 1, ^h, 0} {
			if r := thief.roundTrip(encap.CommandSendRRData, other, rr); r.Status != encap.StatusInvalidSessionHandle {
				t.Fatalf("%s: session %#x: status %s", what, other, r.Status)
			}
		}
	}
	try("unregistered")
	mine := thief.register()
	if mine == h {
		t.Fatal("two connections share a session handle")
	}
	try("registered")
	if s.Sessions() != 2 {
		t.Fatalf("%d sessions", s.Sessions())
	}
	if r := owner.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("owner after the attempts: %s", r.Status)
	}
}

// TestHostileRegisterFlood registers sessions past the limit, and again and
// again on one connection: the limit holds, refused originators get
// insufficient memory, a second RegisterSession on a session is refused,
// and the slots come back when sessions end.
func TestHostileRegisterFlood(t *testing.T) {
	const limit = 3
	s := startServer(t, WithMaxSessions(limit))
	var owners []*peer
	for range limit {
		p := dialPeer(t, s)
		p.register()
		owners = append(owners, p)
	}
	// One connection asks again and again.
	for range 50 {
		r := owners[0].roundTrip(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode())
		if r.Status != encap.StatusInvalidCommand {
			t.Fatalf("second RegisterSession: status %s", r.Status)
		}
	}
	// Many connections beyond the limit, each asking several times.
	for range 20 {
		p := dialPeer(t, s)
		for range 3 {
			r := p.roundTrip(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode())
			if r.Status != encap.StatusInsufficientMemory || r.Session != 0 {
				t.Fatalf("RegisterSession beyond the limit: status %s session %#x", r.Status, r.Session)
			}
		}
		_ = p.c.Close()
	}
	// Malformed registrations.
	p := dialPeer(t, s)
	for _, d := range [][]byte{nil, {1, 0, 0}, {1, 0, 0, 0, 0}, {2, 0, 0, 0}, {1, 0, 1, 0}} {
		r := p.roundTrip(encap.CommandRegisterSession, 0, d)
		if r.Status == encap.StatusSuccess || r.Session != 0 {
			t.Fatalf("RegisterSession % X: status %s session %#x", d, r.Status, r.Session)
		}
	}
	if n := s.Sessions(); n != limit {
		t.Fatalf("%d sessions, limit %d", n, limit)
	}
	for _, o := range owners {
		_ = o.c.Close()
	}
	waitFor(t, "sessions released", func() bool { return s.Sessions() == 0 })
	for range limit {
		dialPeer(t, s).register()
	}
}

// TestHostileUnregisteredConnections opens many TCP connections that never
// register a session. Each holds a goroutine and a socket until its
// inactivity timeout (120 s by default) unless the server bounds them:
// the connections beyond a limit must be closed.
func TestHostileUnregisteredConnections(t *testing.T) {
	const sessions = 2
	const n = 80
	s := startServer(t, WithMaxSessions(sessions))
	conns := make([]net.Conn, 0, n)
	for range n {
		c, err := net.Dial("tcp4", s.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	// A connection the server closed reads EOF (or a reset); one it holds
	// times out.
	open := 0
	deadline := time.Now().Add(2 * time.Second)
	for {
		open = 0
		for _, c := range conns {
			_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
			var b [1]byte
			_, err := c.Read(b[:])
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				open++
			}
		}
		if open < n || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if open >= n {
		t.Fatalf("all %d unregistered connections held open with a limit of %d sessions", n, sessions)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	// The slots come back once the connections are gone.
	deadline = time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp4", s.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		p := &peer{t: t, c: c}
		_, rerr := func() (encap.Packet, error) {
			p.send(encap.CommandListServices, 0, nil)
			return p.tryRecv(time.Second)
		}()
		_ = c.Close()
		if rerr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not serving after the connections closed: %v", rerr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHostileCloseWithIdlePeers checks that Close returns promptly while
// connections that never registered, and registered ones stalled inside a
// packet, are still open (the inactivity timeout is the default 120 s).
func TestHostileCloseWithIdlePeers(t *testing.T) {
	srv, err := New(WithIOAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range 5 {
		c, err := net.Dial("tcp4", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	stalled := &peer{t: t, c: nil}
	c, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, c)
	stalled.c = c
	stalled.register()
	stalled.write(hostileHeader(encap.CommandSendRRData, 1000, stalled.handle))
	// A connection mid-header, never registered.
	c2, err := net.Dial("tcp4", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, c2)
	_, _ = c2.Write([]byte{0x65, 0x00, 0x04})
	time.Sleep(20 * time.Millisecond) // let the server accept them all
	closed := make(chan struct{})
	start := time.Now()
	go func() { _ = srv.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked by connections that never registered")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	if err := <-done; !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Serve: %v", err)
	}
	for _, c := range conns {
		hostileClosedWithin(t, c, time.Second)
	}
}

// TestHostileUnknownCommands sends commands the server does not know, and
// the ones a target never receives: each is refused with invalid command
// (or ignored) and the session survives.
func TestHostileUnknownCommands(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	for _, cmd := range []encap.Command{0x0001, 0x0002, 0x0005, 0x0062, 0x0067, 0x006E, 0x0071, 0x00C8, 0x7FFF, 0xFFFF} {
		for _, data := range [][]byte{nil, {1, 2, 3}, make([]byte, 600)} {
			r := p.roundTrip(cmd, p.handle, data)
			if r.Status != encap.StatusInvalidCommand {
				t.Fatalf("%s with %d octets: status %s", cmd, len(data), r.Status)
			}
		}
	}
	for _, cmd := range []encap.Command{encap.CommandIndicateStatus, encap.CommandCancel, encap.CommandNOP} {
		p.send(cmd, p.handle, []byte{9, 9})
		for _, r := range hostileFence(t, p) {
			if r.Status == encap.StatusSuccess {
				t.Fatalf("%s answered with success", cmd)
			}
		}
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("session after unknown commands: %s", r.Status)
	}
}

// TestHostileCPF sends SendRRData and SendUnitData whose common packet
// format disagrees with the packet: item counts, item lengths and
// trailing octets. Each is refused with incorrect data; nothing is
// dispatched; the session survives.
func TestHostileCPF(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	msg := mustEncode(t, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)})
	item := func(typ encap.ItemType, length int, data []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(typ))
		b = binary.LittleEndian.AppendUint16(b, uint16(length))
		return append(b, data...)
	}
	rr := func(count int, items ...[]byte) []byte {
		b := make([]byte, 6) // interface handle, timeout
		b = binary.LittleEndian.AppendUint16(b, uint16(count))
		for _, it := range items {
			b = append(b, it...)
		}
		return b
	}
	null := item(encap.ItemNullAddress, 0, nil)
	good := item(encap.ItemUnconnectedData, len(msg), msg)
	cases := []struct {
		name string
		cmd  encap.Command
		data []byte
	}{
		{"no data", encap.CommandSendRRData, nil},
		{"5 octets", encap.CommandSendRRData, make([]byte, 5)},
		{"no item count", encap.CommandSendRRData, make([]byte, 6)},
		{"65535 items announced, 2 present", encap.CommandSendRRData, rr(0xFFFF, null, good)},
		{"3 items announced, 2 present", encap.CommandSendRRData, rr(3, null, good)},
		{"1 item announced, 2 present", encap.CommandSendRRData, rr(1, null, good)},
		{"item longer than the packet", encap.CommandSendRRData, rr(2, null, item(encap.ItemUnconnectedData, 0xFFFF, msg))},
		{"item length one beyond", encap.CommandSendRRData, rr(2, null, item(encap.ItemUnconnectedData, len(msg)+1, msg))},
		{"trailing octets", encap.CommandSendRRData, append(rr(2, null, good), 0xAA, 0xBB)},
		{"null address with data", encap.CommandSendRRData, rr(2, item(encap.ItemNullAddress, 4, []byte{1, 2, 3, 4}), good)},
		{"no message item", encap.CommandSendRRData, rr(1, null)},
		{"no address item", encap.CommandSendRRData, rr(1, good)},
		{"interface handle", encap.CommandSendRRData, append([]byte{1, 0, 0, 0, 0, 0}, rr(2, null, good)[6:]...)},
		{"unit data: 65535 items", encap.CommandSendUnitData, rr(0xFFFF, item(encap.ItemConnectedAddress, 4, []byte{1, 0, 0, 0}))},
		{"unit data: address of 2 octets", encap.CommandSendUnitData, rr(2, item(encap.ItemConnectedAddress, 2, []byte{1, 0}), item(encap.ItemConnectedData, 4, []byte{0, 0, 1, 2}))},
		{"unit data: no sequence count", encap.CommandSendUnitData, rr(2, item(encap.ItemConnectedAddress, 4, []byte{1, 0, 0, 0}), item(encap.ItemConnectedData, 1, []byte{0}))},
		{"unit data: data longer than the packet", encap.CommandSendUnitData, rr(2, item(encap.ItemConnectedAddress, 4, []byte{1, 0, 0, 0}), item(encap.ItemConnectedData, 300, []byte{0, 0}))},
	}
	for _, c := range cases {
		r := p.roundTrip(c.cmd, p.handle, c.data)
		if r.Status != encap.StatusIncorrectData {
			t.Fatalf("%s: status %s", c.name, r.Status)
		}
		if len(r.Data) != 0 {
			t.Fatalf("%s: refusal with %d octets of data", c.name, len(r.Data))
		}
	}
	// SendUnitData for a connection that does not exist is not answered.
	unknown, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(0xDEADBEEF), {Type: encap.ItemConnectedData, Data: []byte{0, 0, 0x01, 0x02, 0x20, 0x01, 0x24, 0x01}}}}.Encode()
	p.send(encap.CommandSendUnitData, p.handle, unknown)
	if got := hostileFence(t, p); len(got) != 0 {
		t.Fatalf("SendUnitData for an unknown connection answered: %s %s", got[0].Command, got[0].Status)
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("session after inconsistent CPF: %s", r.Status)
	}
}

// TestHostileForwardOpen sends Forward_Opens with absurd sizes, intervals,
// multipliers and connection paths: each is refused with a status, no
// connection is left open, and a valid one still opens afterwards.
func TestHostileForwardOpen(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	io1 := func() cip.ForwardOpen { return fwdOpen(1, cip.TriggerCyclic, ioPath(asmCfg, asmOut, asmIn)) }
	cases := []struct {
		name string
		fo   func() cip.ForwardOpen
	}{
		{"RPI 0", func() cip.ForwardOpen { f := io1(); f.OTRPI = 0; return f }},
		{"T->O RPI 0", func() cip.ForwardOpen { f := io1(); f.TORPI = 0; return f }},
		{"RPI 0xFFFFFFFF", func() cip.ForwardOpen { f := io1(); f.OTRPI = 0xFFFFFFFF; return f }},
		{"class 3 RPI 0xFFFFFFFF", func() cip.ForwardOpen {
			f := fwdOpen(3, cip.TriggerApplication, explicitPath)
			f.OTRPI = 0xFFFFFFFF
			return f
		}},
		{"timeout multiplier 255", func() cip.ForwardOpen { f := io1(); f.TimeoutMultiplier = 255; return f }},
		{"O->T size 0x1FF", func() cip.ForwardOpen { f := io1(); f.OTParams.Size = 0x1FF; return f }},
		{"large O->T size 0xFFFF", func() cip.ForwardOpen {
			f := io1()
			f.Large = true
			f.OTParams.Size, f.TOParams.Size = 0xFFFF, 0xFFFF
			return f
		}},
		{"O->T size 0", func() cip.ForwardOpen { f := io1(); f.OTParams.Size = 0; return f }},
		{"T->O size 0", func() cip.ForwardOpen { f := io1(); f.TOParams.Size = 0; return f }},
		{"transport class 7", func() cip.ForwardOpen {
			f := io1()
			f.Transport = cip.NewTransportTrigger(7, cip.TriggerCyclic, false)
			return f
		}},
		{"100 connection points", func() cip.ForwardOpen {
			f := io1()
			for range 100 {
				f.Path = append(f.Path, cip.ConnectionPointSegment(uint32(asmIn)))
			}
			return f
		}},
		{"connection points 2^32-1", func() cip.ForwardOpen {
			f := io1()
			f.Path = cip.Path{cip.ClassSegment(cip.ClassAssembly), cip.InstanceSegment(0xFFFFFFFF), cip.ConnectionPointSegment(0xFFFFFFFF), cip.ConnectionPointSegment(0xFFFFFFFF)}
			return f
		}},
		{"assemblies aliased beyond 16 bits", func() cip.ForwardOpen {
			f := io1()
			f.Path = ioPath(0x10000+asmCfg, 0x10000+asmOut, 0x10000+asmIn)
			return f
		}},
		{"class 3 to the Identity object", func() cip.ForwardOpen {
			return fwdOpen(3, cip.TriggerApplication, cip.ObjectPath(cip.ClassIdentity, 1))
		}},
		{"class 3 to the Message Router instance 0x10001", func() cip.ForwardOpen {
			return fwdOpen(3, cip.TriggerApplication, cip.ObjectPath(cip.ClassMessageRouter, 0x10001))
		}},
		{"route through port 2", func() cip.ForwardOpen {
			f := io1()
			f.Path = append(cip.Path{cip.PortSegment{Port: 2, Link: []byte("10.0.0.1")}}, f.Path...)
			return f
		}},
		{"route through port 1 slot 200", func() cip.ForwardOpen {
			f := io1()
			f.Path = append(cip.Path{cip.PortSegment{Port: 1, Link: []byte{200}}}, f.Path...)
			return f
		}},
	}
	for _, c := range cases {
		fo := c.fo()
		data, err := fo.Encode()
		if err != nil {
			continue // not encodable: covered by the raw cases below
		}
		r := p.do(cip.Request{Service: fo.Service(), Path: cip.ConnectionManagerPath(), Data: data})
		if r.OK() {
			t.Errorf("%s: accepted", c.name)
		}
		if r.Service != fo.Service() {
			t.Errorf("%s: reply service %v", c.name, r.Service)
		}
	}
	// Raw Forward_Opens: a path size beyond the data, and truncated
	// headers.
	good, err := io1().Encode()
	if err != nil {
		t.Fatal(err)
	}
	pathAt := len(good) - (len(good) - 36)
	for _, raw := range [][]byte{
		good[:10],
		good[:pathAt-1],
		append(append([]byte(nil), good[:pathAt-1]...), 0xFF),
		append(append(append([]byte(nil), good[:pathAt-1]...), 0x7F), make([]byte, 20)...),
	} {
		r := p.cmRaw(cip.ServiceForwardOpen, 1, raw)
		if r.OK() {
			t.Errorf("raw Forward_Open of %d octets accepted", len(raw))
		}
		r = p.cmRaw(cip.ServiceLargeForwardOpen, 1, raw)
		if r.OK() {
			t.Errorf("raw Large_Forward_Open of %d octets accepted", len(raw))
		}
	}
	if n := len(s.Connections()); n != 0 {
		t.Fatalf("%d connections left open by refused Forward_Opens", n)
	}
	p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
}

// hostileRaw sends a raw CIP message (service, path and data octets as
// given) and returns the response.
func hostileRaw(t *testing.T, p *peer, svc cip.Service, path []byte, data []byte) cip.Response {
	t.Helper()
	msg := append([]byte{byte(svc), byte(len(path) / 2)}, path...)
	r, _ := p.rrData(append(msg, data...))
	return r
}

// TestHostileLogical32 addresses classes, instances and attributes with
// 32-bit logical segments (and 16-bit ones above the defined range): a
// value above 16 bits must not alias the class or instance it truncates
// to.
func TestHostileLogical32(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	seg32 := func(head byte, v uint32) []byte { return binary.LittleEndian.AppendUint32([]byte{head, 0}, v) }
	seg16 := func(head byte, v uint16) []byte { return binary.LittleEndian.AppendUint16([]byte{head | 1, 0}, v) }
	const class, inst, attr = 0x20, 0x24, 0x30
	identity := uint32(cip.ClassIdentity)
	cases := []struct {
		name string
		svc  cip.Service
		path []byte
	}{
		{"class 0x00010001 (Identity + 2^16)", cip.ServiceGetAttributesAll, cat(seg32(class|2, 0x10000+identity), []byte{inst, 1})},
		{"class 0xFFFF0001", cip.ServiceGetAttributesAll, cat(seg32(class|2, 0xFFFF0000+identity), []byte{inst, 1})},
		{"class 32-bit reserved format 3", cip.ServiceGetAttributesAll, cat(seg32(class|3, 0x10000+identity), []byte{inst, 1})},
		{"Identity instance 0x00010001", cip.ServiceGetAttributesAll, cat([]byte{class, byte(identity)}, seg32(inst|2, 0x10001))},
		{"Identity instance 0x80000001", cip.ServiceGetAttributesAll, cat([]byte{class, byte(identity)}, seg32(inst|2, 0x80000001))},
		{"Identity attribute 0x00010001", cip.ServiceGetAttributeSingle, cat([]byte{class, byte(identity), inst, 1}, seg32(attr|2, 0x10001))},
		{"Assembly instance 2^16+100", cip.ServiceGetAttributeSingle, cat([]byte{class, byte(cip.ClassAssembly)}, seg32(inst|2, 0x10000+asmIn), []byte{attr, 3})},
		{"Assembly instance 2^32-1", cip.ServiceGetAttributeSingle, cat([]byte{class, byte(cip.ClassAssembly)}, seg32(inst|2, 0xFFFFFFFF), []byte{attr, 3})},
		{"Connection Manager instance 2^16+1", cip.ServiceGetAttributesAll, cat([]byte{class, byte(cip.ClassConnectionManager)}, seg32(inst|2, 0x10001))},
		{"Message Router instance 2^16+1 MSP", cip.ServiceMultipleServicePacket, cat([]byte{class, byte(cip.ClassMessageRouter)}, seg32(inst|2, 0x10001))},
		{"class 0x0101 (16-bit, unknown)", cip.ServiceGetAttributesAll, cat(seg16(class, 0x0100+uint16(identity)), []byte{inst, 1})},
	}
	for _, c := range cases {
		data := []byte(nil)
		if c.svc == cip.ServiceMultipleServicePacket {
			data, _ = cip.EncodeMultipleService([]cip.Request{{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)}})
		}
		r := hostileRaw(t, p, c.svc, c.path, data)
		if r.OK() || r.Status == cip.StatusEmbeddedServiceError {
			t.Errorf("%s: answered %s with %d octets (aliased?)", c.name, r.Status, len(r.Data))
		}
	}
	// Through Unconnected_Send too.
	for _, c := range cases[:3] {
		embedded := append([]byte{byte(c.svc), byte(len(c.path) / 2)}, c.path...)
		us := []byte{10, 10}
		us = binary.LittleEndian.AppendUint16(us, uint16(len(embedded)))
		us = append(us, embedded...)
		if len(embedded)%2 != 0 {
			us = append(us, 0)
		}
		us = append(us, 1, 0, 0x01, 0x00) // route: port 1, slot 0
		r := p.cmRaw(cip.ServiceUnconnectedSend, 1, us)
		if r.OK() {
			t.Errorf("Unconnected_Send of %s: answered with %d octets", c.name, len(r.Data))
		}
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("after 32-bit segments: %s", r.Status)
	}
}

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

// TestHostileMultipleService sends Multiple Service Packets with service
// counts, offsets and nesting a hostile originator would choose.
func TestHostileMultipleService(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	idReq := mustEncode(t, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)})
	msp := func(data []byte) cip.Response {
		t.Helper()
		return p.do(cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: data})
	}
	offsets := func(n int, off ...uint16) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(n))
		for _, o := range off {
			b = binary.LittleEndian.AppendUint16(b, o)
		}
		return b
	}
	refused := []struct {
		name string
		data []byte
	}{
		{"no data", nil},
		{"count only", offsets(0xFFFF)},
		{"65535 services in 8 octets", append(offsets(0xFFFF, 6, 6), 1, 2)},
		{"offset beyond the data", append(offsets(1, 0xFFF0), idReq...)},
		{"offset inside the offset table", append(offsets(2, 2, 6), idReq...)},
		{"offsets going backwards", append(append(offsets(2, 6+uint16(len(idReq)), 6), idReq...), idReq...)},
		{"offset 0", append(offsets(1, 0), idReq...)},
	}
	for _, c := range refused {
		r := msp(c.data)
		if r.OK() || r.Status == cip.StatusEmbeddedServiceError {
			t.Errorf("%s: status %s", c.name, r.Status)
		}
	}
	// 1001 empty services: beyond the bound of one packet.
	n := 1001
	tbl := offsets(n)
	for i := 0; i < n; i++ {
		tbl = binary.LittleEndian.AppendUint16(tbl, uint16(2+2*n))
	}
	if r := msp(tbl); r.OK() || r.Status == cip.StatusEmbeddedServiceError {
		t.Errorf("1001 services: status %s", r.Status)
	}
	// 1000 empty services: each refused, the reply bounded.
	n = 1000
	tbl = offsets(n)
	for i := 0; i < n; i++ {
		tbl = binary.LittleEndian.AppendUint16(tbl, uint16(2+2*n))
	}
	r := msp(tbl)
	if r.Status != cip.StatusEmbeddedServiceError && r.Status != cip.StatusResourceUnavailable {
		t.Errorf("1000 empty services: status %s", r.Status)
	}
	if r.Status == cip.StatusEmbeddedServiceError {
		parts, err := cip.SplitMultiple(r.Data)
		if err != nil || len(parts) != n {
			t.Fatalf("1000 empty services: %d replies, %v", len(parts), err)
		}
		for i, part := range parts {
			resp, err := cip.DecodeResponse(part)
			if err != nil || resp.OK() {
				t.Fatalf("empty service %d: %v %s", i, err, resp.Status)
			}
		}
	}
	// A Multiple Service Packet inside one is refused, inside an
	// Unconnected_Send inside one too, at any depth, and the server
	// answers.
	inner, _ := cip.EncodeMultipleService([]cip.Request{{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)}})
	r = msp(append(offsets(1, 4), append([]byte{byte(cip.ServiceMultipleServicePacket), 2, 0x20, 0x02, 0x24, 0x01}, inner...)...))
	if r.Status != cip.StatusEmbeddedServiceError {
		t.Errorf("nested Multiple Service Packet: status %s", r.Status)
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("after Multiple Service Packets: %s", r.Status)
	}
}

// TestHostileNestingDepth wraps a request in Unconnected_Send and Multiple
// Service Packet alternately as deep as the largest packet allows: the
// server answers (or refuses) without exhausting itself.
func TestHostileNestingDepth(t *testing.T) {
	s := startIOServer(t, WithMaxPacket(65535))
	p := dialPeer(t, s)
	p.register()
	req := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}
	depth := 0
	for {
		us := cip.UnconnectedSend{PriorityTick: 10, TimeoutTicks: 10, Request: req, Route: cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}}}
		data, err := us.Encode()
		if err != nil {
			break
		}
		next := cip.Request{Service: cip.ServiceUnconnectedSend, Path: cip.ConnectionManagerPath(), Data: data}
		md, err := cip.EncodeMultipleService([]cip.Request{next})
		if err != nil {
			break
		}
		cand := cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: md}
		b, err := cand.Encode()
		if err != nil || len(b) > 60000 {
			break
		}
		req = cand
		depth++
	}
	if depth < 100 {
		t.Fatalf("only %d levels", depth)
	}
	start := time.Now()
	r := p.do(req)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("%d levels took %v", depth, d)
	}
	_ = r
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("after %d levels: %s", depth, r.Status)
	}
}

// TestHostileOversizeReply makes the server build a reply larger than an
// encapsulation packet can carry (an object attribute of 65000 octets).
// The originator must get an answer (reply data too large), not silence
// until its timeout.
func TestHostileOversizeReply(t *testing.T) {
	s := startIOServer(t)
	o := NewObject(0x0300, 1)
	// 65530 octets: the response (4 + 65530) fits a CPF item, the
	// SendRRData data around it (16 more) does not fit the 16-bit length.
	big := bytes.Repeat([]byte{0x5A}, 65530)
	o.AddInstance(1).SetAttribute(1, Attribute{Get: func() []byte { return big }})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	msg := mustEncode(t, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, 1)})
	data, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}}.Encode()
	h := p.send(encap.CommandSendRRData, p.handle, data)
	pkt, err := p.tryRecv(2 * time.Second)
	if err != nil {
		t.Fatalf("no reply to a request whose reply does not fit a packet: %v", err)
	}
	if pkt.Context != h.Context {
		t.Fatalf("reply context %x", pkt.Context)
	}
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	it, _ := encap.Find(rr.Items, encap.ItemUnconnectedData)
	resp, err := cip.DecodeResponse(it.Data)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != cip.StatusReplyDataTooLarge {
		t.Fatalf("status %s, want reply data too large", resp.Status)
	}
}

// TestHostileUDPFlood floods the UDP explicit port with ListIdentity
// requests, garbage, commands that are TCP only, truncated and oversize
// datagrams: the server answers the valid List commands only, keeps
// serving TCP, and Close returns promptly with delayed replies pending.
func TestHostileUDPFlood(t *testing.T) {
	s, err := New(WithIOAddress("127.0.0.1:0"), WithDiscoveryDelay(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var ua *net.UDPAddr
	for attempt := 0; attempt < 20 && ua == nil; attempt++ {
		cand, err := New(WithIOAddress("127.0.0.1:0"), WithDiscoveryDelay(300*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if err := cand.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if a, ok := cand.UDPAddr().(*net.UDPAddr); ok && a != nil {
			s, ua = cand, a
			break
		}
		_ = cand.Close()
	}
	if ua == nil {
		t.Skip("no server with a UDP socket")
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	closed := false
	defer func() {
		if !closed {
			_ = s.Close()
		}
	}()
	c, err := net.DialUDP("udp4", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	packet := func(cmd encap.Command, ctx0 uint16, data []byte, opts uint32) []byte {
		h := encap.Header{Command: cmd, Options: opts}
		binary.LittleEndian.PutUint16(h.Context[:], ctx0)
		b, _ := encap.Packet{Header: h, Data: data}.Encode()
		return b
	}
	valid := 0
	for i := range 3000 {
		var b []byte
		switch i % 8 {
		case 0:
			b = packet(encap.CommandListIdentity, 0xFFFF, nil, 0) // the longest delay
			valid++
		case 1:
			b = packet(encap.CommandSendRRData, 0, make([]byte, 20), 0)
		case 2:
			b = packet(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode(), 0)
		case 3:
			b = packet(encap.CommandListIdentity, 0, nil, 1) // options set
		case 4:
			b = packet(encap.CommandListIdentity, 0, nil, 0)[:23]
		case 5:
			b = append(packet(encap.CommandListIdentity, 0, nil, 0), 0) // length disagrees
		case 6:
			b = packet(encap.CommandListServices, 0, make([]byte, 4000), 0) // above 1500
		default:
			b = bytes.Repeat([]byte{byte(i)}, i%100)
		}
		_, _ = c.Write(b)
	}
	// TCP keeps working during the flood.
	hostileStillServing(t, s)
	// Close with replies still waiting in timers.
	start := time.Now()
	_ = s.Close()
	closed = true
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ethernetip.ErrClosed) {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	// Count what arrived: only ListIdentity replies, at most one per valid
	// request.
	got := 0
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		pkt, err := encap.Decode(buf[:n])
		if err != nil || pkt.Command != encap.CommandListIdentity {
			t.Fatalf("unexpected UDP reply: % X", buf[:n])
		}
		got++
	}
	if got > valid {
		t.Fatalf("%d replies to %d valid requests", got, valid)
	}
}
