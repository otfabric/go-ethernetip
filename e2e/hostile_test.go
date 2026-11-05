// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/logix"
)

// TestHostileLogixFragments sends Logix fragmented reads and writes with
// offsets at, beyond and far beyond the tag, counts beyond the elements,
// and Read-Modify-Write masks longer than the data: each is refused with
// a CIP status, the tag is not changed, and the server keeps serving.
func TestHostileLogixFragments(t *testing.T) {
	a, ts := startLogix(t)
	c := dial(t, a.addr)
	ctx := ctxT(t)
	path := func(name string) cip.Path {
		tp, err := logix.ParseTag(name)
		if err != nil {
			t.Fatal(err)
		}
		return tp.Path
	}
	before, err := ts.Get("Big")
	if err != nil {
		t.Fatal(err)
	}
	le16 := func(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
	le32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	join := func(bs ...[]byte) []byte { return bytes.Join(bs, nil) }
	int16 := le16(uint16(cip.TypeINT))
	const elems = 1000 // Big is INT[1000]: 2000 octets
	cases := []struct {
		name string
		req  cip.Request
	}{
		{"read at the end", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: join(le16(elems), le32(2001))}},
		{"read at 2^31", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: join(le16(elems), le32(1<<31))}},
		{"read at 2^32-1", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: join(le16(elems), le32(0xFFFFFFFF))}},
		{"read beyond the elements", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: join(le16(elems+1), le32(0))}},
		{"read of 0 elements", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: join(le16(0), le32(0))}},
		{"read 65535 elements of the last", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big[999]"), Data: join(le16(0xFFFF), le32(0))}},
		{"read without offset", cip.Request{Service: cip.ServiceReadTagFragmented, Path: path("Big"), Data: le16(1)}},
		{"write at the end", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(elems), le32(2000), []byte{1, 2})}},
		{"write across the end", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(elems), le32(1998), []byte{1, 2, 3, 4})}},
		{"write at 2^32-2", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(elems), le32(0xFFFFFFFE), []byte{1, 2, 3, 4})}},
		{"write at 2^31", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(elems), le32(1<<31), []byte{1, 2})}},
		{"write of more elements than the tag", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(elems+1), le32(0), []byte{1, 2})}},
		{"write of the wrong type", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(le16(uint16(cip.TypeDINT)), le16(1), le32(0), []byte{1, 2, 3, 4})}},
		{"write of a structure handle", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(le16(0x02A0), le16(0xFFFF), le16(1), le32(0), []byte{1, 2})}},
		{"write of the last element, 2 elements long", cip.Request{Service: cip.ServiceWriteTag, Path: path("Big[999]"), Data: join(int16, le16(2), []byte{1, 2, 3, 4})}},
		{"write with a truncated header", cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path("Big"), Data: join(int16, le16(1), []byte{0, 0})}},
		{"read-modify-write mask of 0xFFFF", cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: path("Big[999]"), Data: join(le16(0xFFFF), make([]byte, 8))}},
		{"read-modify-write mask longer than INT", cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: path("Big[999]"), Data: join(le16(8), make([]byte, 8), bytes.Repeat([]byte{0xFF}, 8))}},
		{"element beyond the array", cip.Request{Service: cip.ServiceReadTag, Path: append(cip.Path{cip.SymbolSegment{Name: "Big"}}, cip.MemberSegment(1000)), Data: le16(1)}},
		{"element 2^32-1", cip.Request{Service: cip.ServiceReadTag, Path: append(cip.Path{cip.SymbolSegment{Name: "Big"}}, cip.MemberSegment(0xFFFFFFFF)), Data: le16(1)}},
		{"three indices on one dimension", cip.Request{Service: cip.ServiceReadTag, Path: append(cip.Path{cip.SymbolSegment{Name: "Big"}}, cip.MemberSegment(1), cip.MemberSegment(1), cip.MemberSegment(1)), Data: le16(1)}},
		{"Grid element out of its second dimension", cip.Request{Service: cip.ServiceReadTag, Path: append(cip.Path{cip.SymbolSegment{Name: "Grid"}}, cip.MemberSegment(0), cip.MemberSegment(4)), Data: le16(1)}},
	}
	for _, tc := range cases {
		resp, err := c.Do(ctx, tc.req)
		var ce *ethernetip.CIPError
		if err == nil || !errors.As(err, &ce) {
			t.Errorf("%s: %v (status %s, %d octets)", tc.name, err, resp.Status, len(resp.Data))
		}
	}
	after, err := ts.Get("Big")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("refused writes changed the tag")
	}
	// Template reads beyond the definition, and template instances above
	// 16 bits that would alias a template.
	tpl := func(inst uint32, data []byte) cip.Request {
		return cip.Request{Service: cip.ServiceReadTemplate, Path: cip.ObjectPath(cip.ClassTemplate, inst), Data: data}
	}
	for _, req := range []cip.Request{
		tpl(uint32(motorTemplate.ID), join(le32(0xFFFFFFFF), le16(100))),
		tpl(uint32(motorTemplate.ID), join(le32(1<<20), le16(0xFFFF))),
		tpl(0x10000+uint32(motorTemplate.ID), join(le32(0), le16(100))),
		{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, 0x10000+uint32(motorTemplate.ID)), Data: join(le16(1), le16(4))},
		{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, uint32(motorTemplate.ID)), Data: le16(0xFFFF)},
	} {
		if resp, err := c.Do(ctx, req); err == nil {
			t.Errorf("template request %x on %v answered with %d octets", req.Data, req.Path, len(resp.Data))
		}
	}
	lc := logix.NewClient(c)
	if v, err := lc.Read(ctx, "Big", elems); err != nil || len(v.Data) != 2*elems {
		t.Fatalf("Big after the attempts: %v", err)
	}
}

// truncProxy is a TCP proxy that, while enabled, cuts a reply of the
// server at a random octet and closes both connections: every request
// in flight sees a reply that never completes.
type truncProxy struct {
	l       net.Listener
	target  string
	enabled atomic.Bool
	cuts    atomic.Int64
	mu      sync.Mutex
	rng     *rand.Rand
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newTruncProxy(t *testing.T, target string, seed int64) *truncProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &truncProxy{l: l, target: target, rng: rand.New(rand.NewSource(seed)), conns: map[net.Conn]struct{}{}}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(func() {
		_ = p.l.Close()
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *truncProxy) intn(n int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Intn(n)
}

func (p *truncProxy) accept() {
	defer p.wg.Done()
	for {
		in, err := p.l.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = in.Close()
			continue
		}
		p.mu.Lock()
		p.conns[in], p.conns[out] = struct{}{}, struct{}{}
		p.mu.Unlock()
		p.wg.Add(2)
		go p.pump(in, out, false)
		go p.pump(out, in, true)
	}
}

func (p *truncProxy) pump(src, dst net.Conn, replies bool) {
	defer p.wg.Done()
	defer func() {
		_ = src.Close()
		_ = dst.Close()
		p.mu.Lock()
		delete(p.conns, src)
		delete(p.conns, dst)
		p.mu.Unlock()
	}()
	var buf []byte
	for {
		// Packet by packet, so that a cut falls inside one.
		pkt, nb, err := encap.ReadPacket(src, buf, 0)
		buf = nb
		if err != nil {
			return
		}
		b, _ := pkt.Encode()
		if replies && p.enabled.Load() && pkt.Command == encap.CommandSendRRData && p.intn(4) == 0 {
			_, _ = dst.Write(b[:p.intn(len(b))])
			p.cuts.Add(1)
			return
		}
		if _, err := dst.Write(b); err != nil {
			return
		}
	}
}

// TestChaosTruncatedReplies cuts replies in the middle, explicit requests
// and Forward_Opens alike: every request returns (no hang) with a correct
// answer or a connection error, the scanner's opens succeed or fail
// cleanly, and the connections the adapter opened for Forward_Opens whose
// replies were cut do not stay open beyond their first-packet timeout.
func TestChaosTruncatedReplies(t *testing.T) {
	seed := chaosSeed(t)
	a := startAdapter(t)
	p := newTruncProxy(t, a.addr, seed)
	c := dial(t, p.l.Addr().String(), client.WithAutoReconnect(), client.WithTimeout(time.Second))
	p.enabled.Store(true)
	want := bytes.Repeat([]byte{0x3C}, ioSize)
	if err := a.in.SetData(want); err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	for i := range 200 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		got, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, asmInput, 3)
		cancel()
		if d := time.Since(start); d > 1500*time.Millisecond {
			t.Fatalf("request %d took %v", i, d)
		}
		switch {
		case err == nil:
			if !bytes.Equal(got, want) {
				t.Fatalf("wrong data %x", got)
			}
			ok++
		case allowedChaosError(err) || errors.Is(err, ethernetip.ErrProtocol):
			failed++
		default:
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if p.cuts.Load() == 0 || ok == 0 {
		t.Fatalf("%d cuts, %d answers", p.cuts.Load(), ok)
	}
	// Class 1 opens through the proxy: a cut Forward_Open reply leaves the
	// adapter with a connection the scanner does not know about.
	s := newScanner(t, c)
	opened := 0
	for i := range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cfg := exclusiveOwner(10 * time.Millisecond)
		io, err := s.Open(ctx, cfg)
		cancel()
		if err != nil {
			if !allowedChaosError(err) && !errors.Is(err, ethernetip.ErrProtocol) && !errors.As(err, new(*ethernetip.CIPError)) {
				t.Fatalf("open %d: %v", i, err)
			}
			continue
		}
		opened++
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = io.Close(cctx)
		ccancel()
	}
	p.enabled.Store(false)
	// Every connection whose Forward_Open reply was lost times out at the
	// adapter: no datagram ever arrives for it, so after the first-packet
	// timeout of 10 s; none stays.
	deadline := time.Now().Add(13 * time.Second)
	for len(a.srv.Connections()) != 0 {
		if time.Now().After(deadline) {
			for _, ci := range a.srv.Connections() {
				t.Logf("left open: %+v", ci)
			}
			t.Fatalf("%d connections still open 13 s after the opens (%d of 20 opened, %d cuts)", len(a.srv.Connections()), opened, p.cuts.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx := ctxT(t)
	var err error
	until := time.Now().Add(5 * time.Second)
	for {
		if _, err = c.Identity(ctx); err == nil || time.Now().After(until) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no recovery: %v", err)
	}
	t.Logf("%d answers, %d failures, %d cuts, %d of 20 opens", ok, failed, p.cuts.Load(), opened)
}

// TestHostileSessionLossDuringIO cuts the explicit session of a scanner
// while its Class 1 connection runs: the I/O keeps flowing (it does not
// depend on the TCP session), and the scanner's Close does not hang.
func TestHostileSessionLossDuringIO(t *testing.T) {
	a := startAdapter(t)
	p := newTruncProxy(t, a.addr, 1)
	c := dial(t, p.l.Addr().String(), client.WithAutoReconnect(), client.WithTimeout(time.Second))
	s := newScanner(t, c)
	ctx := ctxT(t)
	io, err := s.Open(ctx, exclusiveOwner(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	out := bytes.Repeat([]byte{0x42}, ioSize)
	if err := io.SetOutput(out); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "output", func() bool { return bytes.Equal(a.out.Data(), out) })
	// Kill every TCP connection of the proxy.
	p.mu.Lock()
	for cn := range p.conns {
		_ = cn.Close()
	}
	p.mu.Unlock()
	eventually(t, 3*time.Second, "session lost", func() bool { return a.srv.Sessions() == 0 })
	sent := io.Stats().Sent
	eventually(t, 3*time.Second, "I/O after the session loss", func() bool { return io.Stats().Sent > sent+20 })
	out2 := bytes.Repeat([]byte{0x24}, ioSize)
	if err := io.SetOutput(out2); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "output after the session loss", func() bool { return bytes.Equal(a.out.Data(), out2) })
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_ = io.Close(cctx)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v", d)
	}
}

// TestHostileInputDatagrams sends forged T->O datagrams to a scanner's I/O
// endpoint while a Class 1 connection runs: stale sequence numbers, the
// wrong size, unknown connection IDs, truncated headers and garbage. The
// scanner keeps the adapter's input and stays connected. (A forged
// datagram with a newer sequence number would be taken: the protocol has
// no authentication, SECURITY.md.)
func TestHostileInputDatagrams(t *testing.T) {
	seed := chaosSeed(t)
	rng := rand.New(rand.NewSource(seed))
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	cfg := exclusiveOwner(5 * time.Millisecond)
	cfg.TimeoutMultiplier = 5
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The adapter copies its output to its input.
	real := bytes.Repeat([]byte{0x77}, ioSize)
	if err := io.SetOutput(real); err != nil {
		t.Fatal(err)
	}
	input := func() []byte { b, _, _ := io.Input(); return b }
	eventually(t, 3*time.Second, "input", func() bool { return bytes.Equal(input(), real) })
	eventually(t, 3*time.Second, "100 datagrams", func() bool { return io.Stats().Received > 100 })
	attacker, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(s.Endpoint().LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attacker.Close() }()
	id := io.Info().TOConnID
	forge := func(seq uint32, count uint16, data []byte) []byte {
		payload := implicit.AppendPayload(nil, 1, implicit.FormatModeless, implicit.Payload{SeqCount: count, Data: data})
		b, _ := implicit.Message{ConnID: id, EncapSeq: seq, Payload: payload}.Encode()
		return b
	}
	evil := bytes.Repeat([]byte{0xEE}, ioSize+8)
	for range 500 {
		var b []byte
		switch rng.Intn(6) {
		case 0: // a replay
			b = forge(uint32(io.Stats().Received)-200-uint32(rng.Intn(1000)), uint16(rng.Intn(1<<16)), evil[:ioSize])
		case 1: // too short
			b = forge(1<<31, 1, evil[:rng.Intn(ioSize)])
		case 2: // too long
			b = forge(1<<31, 1, evil[:ioSize+1+rng.Intn(8)])
		case 3: // an unknown connection
			b, _ = implicit.Message{ConnID: id ^ 0x5A5A5A5A, EncapSeq: 1 << 31, Payload: make([]byte, 2+ioSize)}.Encode()
		case 4: // a truncated header
			b = forge(1<<31, 1, evil[:ioSize])[:rng.Intn(18)]
		default:
			b = make([]byte, rng.Intn(80))
			rng.Read(b)
		}
		_, _ = attacker.Write(b)
	}
	// What the forged datagrams did is not observable otherwise: let the
	// real producer send a few more and compare.
	n := io.Stats().Received
	eventually(t, 3*time.Second, "real datagrams after the forged ones", func() bool { return io.Stats().Received > n+20 })
	if got := input(); !bytes.Equal(got, real) {
		t.Fatalf("input %x after forged datagrams", got)
	}
	if io.State() != ethernetip.StateConnected {
		t.Fatalf("state %v", io.State())
	}
	if st := io.Stats(); st.Dropped == 0 {
		t.Fatalf("no forged datagram counted as dropped: %+v", st)
	}
}
