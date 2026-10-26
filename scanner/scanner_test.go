// SPDX-License-Identifier: MIT

package scanner

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/server"
)

const (
	asmInput      = 100
	asmOutput     = 150
	asmConfig     = 151
	asmInputOnly  = 152
	asmListenOnly = 153
	asmBigIn      = 200
	asmBigOut     = 201
	ioSize        = 8
	bigSize       = 600
	configSize    = 4
)

func ctxT(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type adapter struct {
	srv     *server.Server
	addr    string
	in, out *server.Assembly
	config  *server.Assembly
	stopped chan struct{}
}

// startAdapter starts a server with the test assemblies on addr.
func startAdapter(t testing.TB, addr string, opts ...server.Option) *adapter {
	t.Helper()
	srv, err := server.New(append([]server.Option{server.WithIOAddress("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	a := &adapter{srv: srv, stopped: make(chan struct{})}
	add := func(inst uint32, k server.AssemblyKind, size int) *server.Assembly {
		as, err := srv.AddAssembly(inst, k, size)
		if err != nil {
			t.Fatal(err)
		}
		return as
	}
	a.in = add(asmInput, server.AssemblyInput, ioSize)
	a.out = add(asmOutput, server.AssemblyOutput, ioSize)
	a.config = add(asmConfig, server.AssemblyConfig, configSize)
	add(asmInputOnly, server.AssemblyInputOnly, 0)
	add(asmListenOnly, server.AssemblyListenOnly, 0)
	add(asmBigIn, server.AssemblyInput, bigSize)
	add(asmBigOut, server.AssemblyOutput, bigSize)
	if err := srv.Listen(addr); err != nil {
		t.Fatal(err)
	}
	a.addr = srv.Addr().String()
	go func() { _ = srv.Serve(); close(a.stopped) }()
	t.Cleanup(func() { a.stop(t) })
	return a
}

func (a *adapter) stop(t testing.TB) {
	_ = a.srv.Close()
	select {
	case <-a.stopped:
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return")
	}
}

func dial(t testing.TB, addr string) *client.Client {
	t.Helper()
	c, err := client.Dial(ctxT(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newScanner(t testing.TB, c *client.Client, opts ...Option) *Scanner {
	t.Helper()
	s, err := New(c, append([]Option{WithLocalAddr("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

func owner(rpi time.Duration) IOConfig {
	return IOConfig{ConfigInstance: asmConfig, OutputInstance: asmOutput, InputInstance: asmInput,
		OutputSize: ioSize, InputSize: ioSize, RPI: rpi,
		// 16 RPIs: short RPIs meet coarse timers on loaded CI runners.
		TimeoutMultiplier: 2}
}

// stateRec records state changes.
type stateRec struct {
	mu     sync.Mutex
	states []ethernetip.State
	errs   []error
}

func (r *stateRec) on(s ethernetip.State, err error) {
	r.mu.Lock()
	r.states = append(r.states, s)
	r.errs = append(r.errs, err)
	r.mu.Unlock()
}

func (r *stateRec) get() []ethernetip.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ethernetip.State(nil), r.states...)
}

func (r *stateRec) count(s ethernetip.State) int {
	n := 0
	for _, x := range r.get() {
		if x == s {
			n++
		}
	}
	return n
}

func connStatus(err error) cip.ConnectionStatus {
	var ce *ethernetip.CIPError
	if errors.As(err, &ce) && ce.Status == cip.StatusConnectionFailure && len(ce.Extended) > 0 {
		return cip.ConnectionStatus(ce.Extended[0])
	}
	return 0
}

func TestOptions(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("nil client = %v", err)
	}
	c, err := client.New("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(c, WithEndpoint(nil)); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("nil endpoint = %v", err)
	}
	if _, err := New(c, WithLocalAddr("127.0.0.1:notaport")); err == nil {
		t.Error("bad local address accepted")
	}
	s, err := New(c, WithLocalAddr("127.0.0.1:0"), WithLogger(ethernetip.NopLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Endpoint().LocalAddr().IsValid() {
		t.Error("no endpoint address")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Open(context.Background(), owner(time.Millisecond)); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Open after Close = %v", err)
	}
	// The scanner's own endpoint is closed with it.
	if _, err := s.Endpoint().Open(implicit.Config{ConsumedID: 1}); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("endpoint after Close = %v, want ErrClosed", err)
	}
}

func TestIOConfigValidation(t *testing.T) {
	c, _ := client.New("127.0.0.1:1")
	s, err := New(c, WithLocalAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	cases := map[string]func(*IOConfig){
		"no output":      func(c *IOConfig) { c.OutputInstance = 0 },
		"no input":       func(c *IOConfig) { c.InputInstance = 0 },
		"no rpi":         func(c *IOConfig) { c.RPI = 0 },
		"no to rpi":      func(c *IOConfig) { c.RPI, c.OTRPI = 0, time.Millisecond },
		"rpi above max":  func(c *IOConfig) { c.RPI = maxRPI + time.Microsecond },
		"to rpi too big": func(c *IOConfig) { c.TORPI = maxRPI + time.Microsecond },
		"negative size":  func(c *IOConfig) { c.OutputSize = -1 },
		"input too big":  func(c *IOConfig) { c.InputSize = 65001 },
		"multiplier":     func(c *IOConfig) { c.TimeoutMultiplier = 8 },
		"odd config":     func(c *IOConfig) { c.ConfigData = []byte{1, 2, 3} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := owner(time.Millisecond)
			mod(&cfg)
			st := &stateRec{}
			cfg.OnState = st.on
			if _, err := s.Open(context.Background(), cfg); !errors.Is(err, ethernetip.ErrInvalidOption) {
				t.Fatalf("Open = %v, want ErrInvalidOption", err)
			}
		})
	}
	// Per-direction RPIs replace RPI.
	cfg := IOConfig{RPI: time.Second, OTRPI: 2 * time.Millisecond, TORPI: 3 * time.Millisecond}
	if ot, to := cfg.rpis(); ot != 2*time.Millisecond || to != 3*time.Millisecond {
		t.Errorf("rpis = %v, %v", ot, to)
	}
	if (IOConfig{ClassZero: true}).class() != 0 || (IOConfig{}).class() != 1 {
		t.Error("class")
	}
	f := implicit.FormatModeless
	if (IOConfig{OutputFormat: &f, OutputSize: 4}).outputFormat() != implicit.FormatModeless ||
		(IOConfig{}).outputFormat() != implicit.FormatHeartbeat || (IOConfig{OutputSize: 1}).outputFormat() != implicit.FormatHeader32 {
		t.Error("outputFormat")
	}
	if targetIP(nil).IsValid() || targetIP(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}).IsValid() {
		t.Error("targetIP of a non-TCP address")
	}
}

func TestOpenWithoutTarget(t *testing.T) {
	c, _ := client.New("127.0.0.1:1", client.WithTimeout(time.Second))
	s, err := New(c, WithLocalAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	st := &stateRec{}
	cfg := owner(time.Millisecond)
	cfg.OnState = st.on
	if _, err := s.Open(ctxT(t), cfg); !errors.Is(err, ethernetip.ErrConnectFailed) {
		t.Fatalf("Open = %v, want ErrConnectFailed", err)
	}
	if got := st.get(); len(got) != 2 || got[0] != ethernetip.StateConnecting || got[1] != ethernetip.StateDisconnected {
		t.Errorf("states %v", got)
	}
}

func TestExchangeAndAPI(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	st := &stateRec{}
	inputs := make(chan []byte, 64)
	cfg := owner(5 * time.Millisecond)
	cfg.ConfigData = []byte{1, 2, 3, 4}
	// 320 ms: this test is about the API, not timeouts, and a loaded
	// runner (macOS on Intel) can stall longer than 16 RPIs.
	cfg.TimeoutMultiplier = 4
	cfg.OnState = st.on
	cfg.OnInput = func(d []byte, _ bool) {
		select {
		case inputs <- append([]byte(nil), d...):
		default:
		}
	}
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if io.State() != ethernetip.StateConnected || io.Err() != nil {
		t.Fatalf("state %v err %v", io.State(), io.Err())
	}
	if in, _, at := io.Input(); len(in) != 0 && at.IsZero() {
		t.Error("input without a time")
	}
	if !bytes.Equal(a.config.Data(), cfg.ConfigData) {
		t.Errorf("configuration %x", a.config.Data())
	}
	if err := io.SetOutput([]byte{1}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("SetOutput of a wrong size = %v", err)
	}
	out := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := io.SetOutput(out); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "output at the target", func() bool { return bytes.Equal(a.out.Data(), out) && a.out.Run() })
	io.SetRun(false)
	eventually(t, 3*time.Second, "idle at the target", func() bool { return !a.out.Run() })
	want := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	if err := a.in.SetData(want); err != nil {
		t.Fatal(err)
	}
	if !waitUntil(3*time.Second, func() bool {
		in, _, at := io.Input()
		return bytes.Equal(in, want) && !at.IsZero()
	}) {
		in, _, at := io.Input()
		t.Fatalf("no input from the target: state %v, err %v, input %x at %v", io.State(), io.Err(), in, at)
	}
	got := false
	for !got {
		select {
		case d := <-inputs:
			got = bytes.Equal(d, want)
		case <-time.After(3 * time.Second):
			t.Fatal("OnInput not called with the input")
		}
	}
	if stt := io.Stats(); stt.Sent == 0 || stt.Received == 0 {
		t.Errorf("stats %+v", stt)
	}
	info := io.Info()
	if info.Class != 1 || info.OTConnID == 0 || len(info.Path) == 0 {
		t.Errorf("info %+v", info)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-io.Done():
	default:
		t.Error("Done not closed after Close")
	}
	if !errors.Is(io.Err(), ethernetip.ErrClosed) && io.Err() != nil {
		t.Errorf("Err after Close = %v", io.Err())
	}
	eventually(t, 3*time.Second, "connection closed at the target", func() bool { return len(a.srv.Connections()) == 0 })
	states := st.get()
	if len(states) != 3 || states[0] != ethernetip.StateConnecting || states[1] != ethernetip.StateConnected || states[2] != ethernetip.StateDisconnected {
		t.Errorf("states %v", states)
	}
}

func TestVariants(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)

	t.Run("class 0", func(t *testing.T) {
		cfg := owner(5 * time.Millisecond)
		cfg.ClassZero = true
		io, err := s.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = io.Close(ctx) }()
		if io.Info().Class != 0 {
			t.Errorf("class %d", io.Info().Class)
		}
		out := []byte{9, 9, 9, 9, 9, 9, 9, 9}
		_ = io.SetOutput(out)
		eventually(t, 3*time.Second, "class 0 output", func() bool { return bytes.Equal(a.out.Data(), out) })
	})
	t.Run("input only", func(t *testing.T) {
		cfg := owner(5 * time.Millisecond)
		cfg.ConfigInstance, cfg.OutputInstance, cfg.OutputSize = 0, asmInputOnly, 0
		io, err := s.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = a.in.SetData([]byte{5, 5, 5, 5, 5, 5, 5, 5})
		eventually(t, 3*time.Second, "input", func() bool { in, _, _ := io.Input(); return len(in) == ioSize && in[0] == 5 })
		_ = io.Close(ctx)
	})
	t.Run("large", func(t *testing.T) {
		cfg := IOConfig{OutputInstance: asmBigOut, InputInstance: asmBigIn, OutputSize: bigSize, InputSize: bigSize, RPI: 10 * time.Millisecond}
		io, err := s.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = io.Close(ctx)
	})
	t.Run("explicit output format refused", func(t *testing.T) {
		// The target expects the run/idle header: a modeless output has
		// the wrong size, and the target refuses the Forward_Open.
		f := implicit.FormatModeless
		cfg := owner(5 * time.Millisecond)
		cfg.OutputFormat = &f
		cfg.Key = &cip.KeySegment{}
		st := &stateRec{}
		cfg.OnState = st.on
		_, err := s.Open(ctx, cfg)
		if connStatus(err) != cip.ConnStatusInvalidOTSize {
			t.Fatalf("Open = %v, want invalid O->T size", err)
		}
		if got := st.get(); len(got) != 2 || got[1] != ethernetip.StateDisconnected {
			t.Errorf("states %v", got)
		}
	})
}

func TestExplicitOutputFormat(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0", server.WithRunIdleHeader(false, true))
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	f := implicit.FormatModeless
	cfg := owner(5 * time.Millisecond)
	cfg.OutputFormat = &f
	cfg.InputFormat = implicit.FormatHeader32
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = io.Close(ctx) }()
	out := []byte{3, 3, 3, 3, 3, 3, 3, 3}
	_ = io.SetOutput(out)
	eventually(t, 3*time.Second, "modeless output", func() bool { return bytes.Equal(a.out.Data(), out) })
	eventually(t, 3*time.Second, "input in run", func() bool { _, run, at := io.Input(); return run && !at.IsZero() })
}

func TestMulticast(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	cfg := owner(5 * time.Millisecond)
	cfg.Multicast = true
	io, err := s.Open(ctx, cfg)
	if err != nil {
		// Joining a multicast group needs a multicast route, which a test
		// host may lack; the Forward_Open itself must have succeeded.
		if errors.Is(err, ethernetip.ErrProtocol) || connStatus(err) != 0 {
			t.Fatalf("multicast Open = %v", err)
		}
		t.Skipf("multicast group not joinable here: %v", err)
	}
	defer func() { _ = io.Close(ctx) }()
	conns := a.srv.Connections()
	if len(conns) != 1 || conns[0].TOConnID != io.Info().TOConnID {
		t.Fatalf("server connections %+v", conns)
	}
	// The group comes from the reply's Sockaddr Info T->O item; the data
	// itself is not asserted: an endpoint bound to 127.0.0.1 does not
	// receive datagrams sent to a multicast group.
	// A listen-only connection of another scanner (its own endpoint: the
	// T->O connection ID of a shared production can be consumed once per
	// endpoint) joins the same production.
	s2 := newScanner(t, dial(t, a.addr))
	lo := owner(5 * time.Millisecond)
	lo.ConfigInstance, lo.OutputInstance, lo.OutputSize, lo.Multicast = 0, asmListenOnly, 0, true
	io2, err := s2.Open(ctx, lo)
	if err != nil {
		t.Fatalf("listen only: %v", err)
	}
	if io2.Info().TOConnID != io.Info().TOConnID {
		t.Error("listen-only connection on another production")
	}
	_ = io2.Close(ctx)
}

// fakeTarget answers RegisterSession and passes every Forward_Open to fo,
// which returns the reply items (nil items and nil reply refuse).
type fakeTarget struct {
	ln net.Listener
	wg sync.WaitGroup
}

func newFakeTarget(t *testing.T, fo func(req cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item)) *fakeTarget {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTarget{ln: ln}
	var mu sync.Mutex
	var conns []net.Conn
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer func() { _ = conn.Close() }()
				f.serve(t, conn, fo)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		f.wg.Wait()
	})
	return f
}

func (f *fakeTarget) serve(t *testing.T, conn net.Conn, fo func(cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item)) {
	var buf []byte
	for {
		pkt, nb, err := encap.ReadPacket(conn, buf, 0)
		buf = nb
		if err != nil {
			return
		}
		var data []byte
		switch pkt.Command {
		case encap.CommandRegisterSession:
			pkt.Session = 0x55
			data = pkt.Data
		case encap.CommandSendRRData:
			rr, _ := encap.DecodeRRData(pkt.Data)
			it, _ := encap.Find(rr.Items, encap.ItemUnconnectedData)
			req, err := cip.DecodeRequest(it.Data)
			if err != nil {
				t.Error(err)
				return
			}
			var resp cip.Response
			var items []encap.Item
			switch req.Service {
			case cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen:
				r, err := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
				if err != nil {
					t.Error(err)
					return
				}
				reply, it := fo(r)
				b, _ := reply.Encode()
				resp, items = cip.Response{Service: req.Service, Data: b}, it
			case cip.ServiceForwardClose:
				fc, _ := cip.DecodeForwardClose(req.Data)
				b, _ := cip.ForwardCloseReply{Triad: fc.Triad}.Encode()
				resp = cip.Response{Service: req.Service, Data: b}
			default:
				// Other services do not occur in this test.
			}
			msg, _ := resp.Encode()
			data, _ = encap.RRData{Items: append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}, items...)}.Encode()
		default:
			continue
		}
		out, _ := encap.Packet{Header: pkt.Header, Data: data}.Encode()
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func okReply(fo cip.ForwardOpen) cip.ForwardOpenReply {
	return cip.ForwardOpenReply{OTConnID: 0x77, TOConnID: fo.TOConnID, Triad: fo.Triad, OTAPI: fo.OTRPI, TOAPI: fo.TORPI}
}

func TestMulticastWithoutGroup(t *testing.T) {
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		// A malformed item and a unicast T->O address: no group.
		return okReply(fo), []encap.Item{
			{Type: encap.ItemSockaddrTO, Data: []byte{1}},
			{Type: encap.ItemSockaddrTO, Data: encap.SockaddrOf(netip.MustParseAddrPort("127.0.0.1:2222")).Encode()},
		}
	})
	c := dial(t, f.ln.Addr().String())
	s := newScanner(t, c)
	cfg := owner(5 * time.Millisecond)
	cfg.Multicast = true
	if _, err := s.Open(ctxT(t), cfg); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("Open = %v, want ErrProtocol", err)
	}
}

func TestTimeoutWithoutReconnect(t *testing.T) {
	// The fake target never produces: the connection times out.
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		return okReply(fo), []encap.Item{{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.MustParseAddrPort("127.0.0.1:9")).Encode()}}
	})
	c := dial(t, f.ln.Addr().String())
	s := newScanner(t, c)
	ctx := ctxT(t)
	st := &stateRec{}
	cfg := owner(5 * time.Millisecond)
	cfg.OnState = st.on
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-io.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after the timeout")
	}
	if !errors.Is(io.Err(), ethernetip.ErrTimeout) || io.State() != ethernetip.StateTimedOut {
		t.Fatalf("Err = %v, state %v", io.Err(), io.State())
	}
	if err := io.Close(ctx); err != nil {
		t.Fatalf("Close after timeout = %v", err)
	}
	if st.count(ethernetip.StateTimedOut) != 1 {
		t.Errorf("states %v", st.get())
	}
	// The same T->O ID again: the endpoint cannot register it, and the
	// target's connection is closed.
	fixed := uint32(0x4242)
	f2 := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		r := okReply(fo)
		r.TOConnID = fixed
		return r, nil
	})
	c2 := dial(t, f2.ln.Addr().String())
	s2 := newScanner(t, c2)
	cfg2 := owner(time.Second)
	if _, err := s2.Open(ctx, cfg2); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Open(ctx, cfg2); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("second Open with the same ID = %v", err)
	}
}

func TestReconnect(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	addr := a.addr
	c := dial(t, addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	st := &stateRec{}
	cfg := owner(5 * time.Millisecond)
	cfg.Reconnect = &Reconnect{MinDelay: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond}
	cfg.OnState = st.on
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := io.Info()
	a.stop(t)
	// Reconnect attempts fail while the target is down.
	eventually(t, 10*time.Second, "failed reconnect attempts", func() bool { return st.count(ethernetip.StateTimedOut) >= 3 })
	select {
	case <-io.Done():
		t.Fatal("Done closed while reconnecting")
	default:
	}
	b := startAdapter(t, addr)
	eventually(t, 10*time.Second, "reconnected", func() bool { return io.State() == ethernetip.StateConnected })
	if io.Info().OTConnID == before.OTConnID {
		t.Error("same connection after reconnect")
	}
	if len(b.srv.Connections()) != 1 {
		t.Errorf("target connections %d", len(b.srv.Connections()))
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "closed at the target", func() bool { return len(b.srv.Connections()) == 0 })
}

func TestCloseDuringReconnect(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	st := &stateRec{}
	cfg := owner(5 * time.Millisecond)
	cfg.Reconnect = &Reconnect{MinDelay: time.Millisecond}
	cfg.OnState = st.on
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.stop(t)
	eventually(t, 10*time.Second, "reconnecting", func() bool { return st.count(ethernetip.StateConnecting) >= 2 })
	done := make(chan error, 1)
	go func() { done <- s.Close(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return during reconnect")
	}
	select {
	case <-io.Done():
	default:
		t.Fatal("Done not closed")
	}
	// After Close no reconnect attempt runs any more: the state stays.
	if io.State() != ethernetip.StateDisconnected {
		t.Errorf("state after Close %v", io.State())
	}
}

func TestSharedEndpoint(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	c := dial(t, a.addr)
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	s, err := New(c, WithEndpoint(ep))
	if err != nil {
		t.Fatal(err)
	}
	if s.Endpoint() != ep {
		t.Fatal("Endpoint is not the shared one")
	}
	ctx := ctxT(t)
	io, err := s.Open(ctx, owner(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-io.Done():
	default:
		t.Error("Scanner.Close did not close its connections")
	}
	eventually(t, 3*time.Second, "closed at the target", func() bool { return len(a.srv.Connections()) == 0 })
	// The shared endpoint stays open.
	cn, err := ep.Open(implicit.Config{ConsumedID: 0x1234})
	if err != nil {
		t.Fatalf("shared endpoint closed by the scanner: %v", err)
	}
	cn.Close()
}

// waitUntil polls cond until it holds or d passes, and reports whether it
// held.
func waitUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}
