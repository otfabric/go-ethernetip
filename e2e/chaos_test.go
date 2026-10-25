// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/implicit"
)

// chaosSeed returns the seed of a chaos test (ETHERNETIP_CHAOS_SEED, or
// the clock) and logs it when the test fails.
func chaosSeed(t *testing.T) int64 {
	t.Helper()
	seed := time.Now().UnixNano()
	if s := os.Getenv("ETHERNETIP_CHAOS_SEED"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("ETHERNETIP_CHAOS_SEED=%q", s)
		}
		seed = v
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("repeat with ETHERNETIP_CHAOS_SEED=%d", seed)
		}
	})
	return seed
}

// chaosProxy is a TCP proxy between a client and a server that, while
// enabled, splits and delays writes, corrupts octets (when corrupt is
// set) and kills connections at random.
type chaosProxy struct {
	l       net.Listener
	target  string
	corrupt bool
	enabled atomic.Bool
	kills   atomic.Int64
	mu      sync.Mutex
	rng     *rand.Rand
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
	done    chan struct{}
}

func newChaosProxy(t *testing.T, target string, seed int64, corrupt bool) *chaosProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &chaosProxy{l: l, target: target, corrupt: corrupt, rng: rand.New(rand.NewSource(seed)),
		conns: map[net.Conn]struct{}{}, done: make(chan struct{})}
	p.enabled.Store(true)
	p.wg.Add(2)
	go p.accept()
	go p.killer()
	t.Cleanup(p.close)
	return p
}

func (p *chaosProxy) addr() string { return p.l.Addr().String() }

func (p *chaosProxy) float() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Float64()
}

func (p *chaosProxy) intn(n int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Intn(n)
}

func (p *chaosProxy) accept() {
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
		go p.pump(in, out)
		go p.pump(out, in)
	}
}

func (p *chaosProxy) pump(src, dst net.Conn) {
	defer p.wg.Done()
	defer func() { _ = src.Close(); _ = dst.Close() }()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		b := append([]byte(nil), buf[:n]...)
		if p.enabled.Load() {
			if p.corrupt {
				for i := range b {
					if p.float() < 0.001 {
						b[i] ^= byte(1 << p.intn(8))
					}
				}
			}
			if p.float() < 0.05 {
				time.Sleep(time.Duration(p.intn(10)) * time.Millisecond)
			}
		}
		for len(b) > 0 {
			k := len(b)
			if p.enabled.Load() && k > 1 && p.float() < 0.3 {
				k = 1 + p.intn(k-1)
			}
			if _, err := dst.Write(b[:k]); err != nil {
				return
			}
			b = b[k:]
		}
	}
}

func (p *chaosProxy) killer() {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case <-time.After(time.Duration(100+p.intn(200)) * time.Millisecond):
		}
		p.mu.Lock()
		if p.enabled.Load() && len(p.conns) > 0 {
			k := p.rng.Intn(len(p.conns))
			for c := range p.conns {
				if k == 0 {
					_ = c.Close()
					delete(p.conns, c)
					p.kills.Add(1)
					break
				}
				k--
			}
		}
		p.mu.Unlock()
	}
}

func (p *chaosProxy) close() {
	select {
	case <-p.done:
		return
	default:
	}
	close(p.done)
	_ = p.l.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// allowedChaosError reports whether err is a failure the chaos may cause:
// the connection lost or not yet back, a timeout.
func allowedChaosError(err error) bool {
	return errors.Is(err, ethernetip.ErrConnectionLost) || errors.Is(err, ethernetip.ErrTimeout) ||
		errors.Is(err, ethernetip.ErrNotConnected) || errors.Is(err, ethernetip.ErrConnectFailed)
}

// TestChaosExplicit sends requests through a proxy that splits and delays
// writes and kills connections: every answer that arrives is correct,
// failures are of the kinds the faults cause, the client reconnects by
// itself, and everything works once the faults stop.
func TestChaosExplicit(t *testing.T) {
	seed := chaosSeed(t)
	a := startAdapter(t)
	p := newChaosProxy(t, a.addr, seed, false)
	c := dial(t, p.addr(), client.WithAutoReconnect(), client.WithTimeout(time.Second))
	want := bytes.Repeat([]byte{0x5A}, ioSize)
	if err := a.in.SetData(want); err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, asmInput, 3)
		cancel()
		switch {
		case err == nil:
			if !bytes.Equal(got, want) {
				t.Fatalf("wrong data %x", got)
			}
			ok++
		case allowedChaosError(err):
			failed++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if p.kills.Load() == 0 || ok == 0 {
		t.Fatalf("%d kills, %d answers", p.kills.Load(), ok)
	}
	p.enabled.Store(false)
	ctx := ctxT(t)
	var err error
	for i := 0; i < 5; i++ {
		if _, err = c.Identity(ctx); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("no recovery: %v", err)
	}
	t.Logf("%d answers, %d failures, %d connections killed", ok, failed, p.kills.Load())
}

// TestChaosCorruption corrupts octets on the wire as well: the server
// survives (no panic, keeps serving others), and answers that do arrive
// are well-formed or refused.
func TestChaosCorruption(t *testing.T) {
	seed := chaosSeed(t)
	a := startAdapter(t)
	p := newChaosProxy(t, a.addr, seed, true)
	c := dial(t, p.addr(), client.WithAutoReconnect(), client.WithTimeout(500*time.Millisecond))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, err := c.MultipleService(ctx, []cip.Request{
			{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)},
			{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassAssembly, asmInput)},
		})
		cancel()
		if err != nil && !allowedChaosError(err) && !errors.Is(err, ethernetip.ErrProtocol) &&
			!errors.Is(err, ethernetip.ErrSession) {
			var ce *ethernetip.CIPError
			if !errors.As(err, &ce) {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	}
	// The server is still serving a direct client.
	d := dial(t, a.addr)
	if _, err := d.Identity(ctxT(t)); err != nil {
		t.Fatalf("server not serving after corruption: %v", err)
	}
}

// TestChaosInjectedDatagrams sends forged and replayed datagrams to the
// server's I/O endpoint while a connection runs: duplicates, old sequence
// numbers, wrong sizes, unknown connection IDs and garbage. The connection
// stays up and the output keeps the data of the real originator.
func TestChaosInjectedDatagrams(t *testing.T) {
	seed := chaosSeed(t)
	rng := rand.New(rand.NewSource(seed))
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	io, err := s.Open(ctx, exclusiveOwner(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	real := bytes.Repeat([]byte{0x11}, ioSize)
	if err := io.SetOutput(real); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "output", func() bool { return bytes.Equal(a.out.Data(), real) })
	// Let the scanner's sequence numbers run ahead, so that the replayed
	// ones below are stale.
	eventually(t, 3*time.Second, "100 datagrams", func() bool { return io.Stats().Sent > 100 })
	attacker, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(a.srv.IOAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attacker.Close() }()
	id := io.Info().OTConnID
	forge := func(seq uint32, count uint16, data []byte) []byte {
		payload := implicit.AppendPayload(nil, 1, implicit.FormatHeader32, implicit.Payload{SeqCount: count, Header: implicit.RunBit, Data: data})
		b, _ := implicit.Message{ConnID: id, EncapSeq: seq, Payload: payload}.Encode()
		return b
	}
	evil := bytes.Repeat([]byte{0xEE}, ioSize)
	for i := 0; i < 500; i++ {
		var b []byte
		switch rng.Intn(5) {
		case 0: // a stale encapsulation sequence number (a replay)
			b = forge(uint32(io.Stats().Sent)-50-uint32(rng.Intn(1000)), uint16(rng.Intn(1<<16)), evil)
		case 1: // the wrong size
			b = forge(1<<31, 1, evil[:rng.Intn(ioSize)])
		case 2: // an unknown connection
			b, _ = implicit.Message{ConnID: id + 1, EncapSeq: 1 << 31, Payload: make([]byte, 6+ioSize)}.Encode()
		case 3: // garbage
			b = make([]byte, rng.Intn(64))
			rng.Read(b)
		default: // a truncated header
			b = forge(1<<31, 1, evil)[:rng.Intn(20)]
		}
		_, _ = attacker.Write(b)
	}
	// The forged datagrams come from the scanner's address (loopback), so
	// source filtering does not stop them: sizes, connection IDs and
	// sequence numbers do. A forged datagram with a newer sequence number
	// would be taken: the protocol has no authentication (SECURITY.md).
	time.Sleep(50 * time.Millisecond) // the injected datagrams are not observable otherwise
	eventually(t, time.Second, "real output kept", func() bool { return bytes.Equal(a.out.Data(), real) })
	if io.State() != ethernetip.StateConnected || len(a.srv.Connections()) != 1 {
		t.Fatalf("connection lost: %v, %d", io.State(), len(a.srv.Connections()))
	}
}
