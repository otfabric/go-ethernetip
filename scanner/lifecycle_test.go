// SPDX-License-Identifier: MIT

package scanner

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

// TestForwardOpenReplyChecks: a Forward_Open reply whose actual packet
// interval is 0, whose O->T connection ID is 0 or whose O->T Sockaddr Info
// item names a unicast address other than the target's is refused with
// ErrProtocol, the connection is closed at the target with Forward_Close,
// and nothing is left on the endpoint. An unspecified address and the
// target's own address are taken, with the item's port.
func TestForwardOpenReplyChecks(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	port := strconv.Itoa(sink.LocalAddr().(*net.UDPAddr).Port)
	ot := func(addr string) []encap.Item {
		return []encap.Item{{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.MustParseAddrPort(addr)).Encode()}}
	}
	for _, tc := range []struct {
		name   string
		mangle func(*cip.ForwardOpenReply)
		items  []encap.Item
		ok     bool
	}{
		{"O->T interval 0", func(r *cip.ForwardOpenReply) { r.OTAPI = 0 }, nil, false},
		{"T->O interval 0", func(r *cip.ForwardOpenReply) { r.TOAPI = 0 }, nil, false},
		{"both intervals 0", func(r *cip.ForwardOpenReply) { r.OTAPI, r.TOAPI = 0, 0 }, nil, false},
		{"O->T connection ID 0", func(r *cip.ForwardOpenReply) { r.OTConnID = 0 }, nil, false},
		{"another unicast O->T address", nil, ot("192.0.2.1:" + port), false},
		{"broadcast O->T address", nil, ot("255.255.255.255:" + port), false},
		{"unspecified O->T address", nil, ot("0.0.0.0:" + port), true},
		{"the target's O->T address", nil, ot("127.0.0.1:" + port), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
				r := okReply(fo)
				if tc.mangle != nil {
					tc.mangle(&r)
				}
				return r, tc.items
			})
			s := newScanner(t, dial(t, f.ln.Addr().String()))
			ctx := ctxT(t)
			io, err := s.Open(ctx, owner(5*time.Millisecond))
			if !tc.ok {
				if !errors.Is(err, ethernetip.ErrProtocol) {
					t.Fatalf("Open = %v, want ErrProtocol", err)
				}
				if n := f.fcs.Load(); n != 1 {
					t.Errorf("%d Forward_Close requests, want 1", n)
				}
				if n := s.Endpoint().Connections(); n != 0 {
					t.Errorf("%d connections left on the endpoint", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open = %v", err)
			}
			defer func() { _ = io.Close(ctx) }()
			// The output arrives at the item's port.
			buf := make([]byte, 1500)
			_ = sink.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := sink.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("no output at the item's port: %v", err)
			}
			m, err := implicit.Decode(buf[:n])
			if err != nil || m.ConnID != 0x77 {
				t.Fatalf("output %+v, %v", m, err)
			}
		})
	}
}

// TestOnStateCallsClose (L10): an OnState handler that calls IO.Close or
// Scanner.Close returns, with Reconnect set or not, for a timeout and for
// the states the reopen loop reports; the connection is then closed.
func TestOnStateCallsClose(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reconnect bool
		on        ethernetip.State
		nth       int // the report of on that calls Close
		scanner   bool
		refuse    bool // the target refuses to reopen
	}{
		{"IO.Close on timed-out", false, ethernetip.StateTimedOut, 1, false, false},
		{"IO.Close on timed-out, reconnecting", true, ethernetip.StateTimedOut, 1, false, false},
		{"IO.Close on connecting, reconnecting", true, ethernetip.StateConnecting, 2, false, false},
		{"IO.Close on connected, reconnecting", true, ethernetip.StateConnected, 2, false, false},
		{"IO.Close on a failed reopen", true, ethernetip.StateTimedOut, 2, false, true},
		{"Scanner.Close on timed-out, reconnecting", true, ethernetip.StateTimedOut, 1, true, false},
		{"Scanner.Close on connecting, reconnecting", true, ethernetip.StateConnecting, 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The target never produces: the connection times out.
			var opens atomic.Int32
			f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
				if opens.Add(1) > 1 && tc.refuse {
					return cip.ForwardOpenReply{}, nil
				}
				return okReply(fo), nil
			})
			s := newScanner(t, dial(t, f.ln.Addr().String()))
			ready := make(chan struct{})
			returned := make(chan error, 1)
			var io *IO
			var mu sync.Mutex
			seen := 0
			cfg := owner(5 * time.Millisecond)
			if tc.reconnect {
				cfg.Reconnect = &Reconnect{MinDelay: time.Millisecond, MaxDelay: time.Millisecond}
			}
			cfg.OnState = func(st ethernetip.State, _ error) {
				if st != tc.on {
					return
				}
				mu.Lock()
				seen++
				fire := seen == tc.nth
				mu.Unlock()
				if !fire {
					return
				}
				<-ready
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if tc.scanner {
					returned <- s.Close(ctx)
				} else {
					returned <- io.Close(ctx)
				}
			}
			var err error
			io, err = s.Open(ctxT(t), cfg)
			if err != nil {
				t.Fatal(err)
			}
			close(ready)
			select {
			case err := <-returned:
				if err != nil {
					t.Fatalf("Close from OnState = %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("an OnState handler that calls Close has not returned")
			}
			select {
			case <-io.Done():
			default:
				t.Fatal("Done not closed")
			}
			if st := io.State(); st != ethernetip.StateDisconnected {
				t.Errorf("state %v after Close", st)
			}
		})
	}
}

// TestClosedIOReportsNothing: once an IO is closed, a timeout or a state
// of the reopen loop that comes late changes and reports nothing. Stats of
// an IO without an implicit connection is zero.
func TestClosedIOReportsNothing(t *testing.T) {
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) { return okReply(fo), nil })
	s := newScanner(t, dial(t, f.ln.Addr().String()))
	var reports atomic.Int32
	cfg := owner(time.Second)
	cfg.Reconnect = &Reconnect{}
	cfg.OnState = func(ethernetip.State, error) { reports.Add(1) }
	ctx := ctxT(t)
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	n := reports.Load()
	io.timedOut()
	io.wg.Add(1) // as the reopen loop holds it
	if io.report(ethernetip.StateConnecting, nil) {
		t.Error("report on a closed IO returned true")
	}
	io.wg.Wait()
	if reports.Load() != n || io.State() != ethernetip.StateDisconnected {
		t.Errorf("%d reports after Close, state %v", reports.Load()-n, io.State())
	}
	if st := (&IO{}).Stats(); st != (implicit.Stats{}) {
		t.Errorf("Stats without a connection = %+v", st)
	}
}

// TestOpenRacingClose (L16): a Scanner.Close while Open waits for the
// Forward_Open reply leaves nothing running: Open fails with ErrClosed,
// the target gets a Forward_Close and the shared endpoint holds no
// connection.
func TestOpenRacingClose(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		once.Do(func() { close(arrived) })
		<-release
		return okReply(fo), nil
	})
	c := dial(t, f.ln.Addr().String())
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	s, err := New(c, WithEndpoint(ep))
	if err != nil {
		t.Fatal(err)
	}
	ctx := ctxT(t)
	done := make(chan error, 1)
	go func() { _, err := s.Open(ctx, owner(5*time.Millisecond)); done <- err }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("no Forward_Open at the target")
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, ethernetip.ErrClosed) {
			t.Fatalf("Open = %v, want ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open has not returned")
	}
	if n := f.fcs.Load(); n != 1 {
		t.Errorf("%d Forward_Close requests, want 1", n)
	}
	if n := ep.Connections(); n != 0 {
		t.Errorf("%d connections on the endpoint", n)
	}
}

// TestConcurrentClose (L2): IO.Close and Scanner.Close called by several
// goroutines at once: every call returns nil and the target's connections
// are closed.
func TestConcurrentClose(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	s := newScanner(t, dial(t, a.addr))
	ctx := ctxT(t)
	io, err := s.Open(ctx, owner(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	cfg := owner(5 * time.Millisecond)
	cfg.ConfigInstance, cfg.OutputInstance, cfg.OutputSize = 0, asmInputOnly, 0
	other, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeAll := func(f func() error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() { errs <- f() })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent Close = %v", err)
			}
		}
	}
	closeAll(func() error { return io.Close(ctx) })
	eventually(t, 3*time.Second, "one connection left at the target", func() bool { return len(a.srv.Connections()) == 1 })
	closeAll(func() error { return s.Close(ctx) })
	<-other.Done()
	eventually(t, 3*time.Second, "no connection at the target", func() bool { return len(a.srv.Connections()) == 0 })
}

// TestCallbacksCallMethods (L9): OnInput and OnState may call the methods
// of the IO.
func TestCallbacksCallMethods(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	s := newScanner(t, dial(t, a.addr))
	ctx := ctxT(t)
	var cur atomic.Pointer[IO]
	called := make(chan struct{})
	var once sync.Once
	want := []byte{4, 4, 4, 4, 4, 4, 4, 4}
	cfg := owner(5 * time.Millisecond)
	cfg.OnState = func(ethernetip.State, error) {
		if io := cur.Load(); io != nil {
			_, _, _ = io.State(), io.Info(), io.Err()
		}
	}
	cfg.OnInput = func([]byte, bool) {
		io := cur.Load()
		if io == nil {
			return
		}
		_, _, _ = io.Input()
		_, _, _ = io.State(), io.Info(), io.Stats()
		io.SetRun(true)
		if err := io.SetOutput(want); err != nil {
			t.Error(err)
		}
		once.Do(func() { close(called) })
	}
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cur.Store(io)
	_ = a.in.SetData([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("OnInput not called")
	}
	eventually(t, 3*time.Second, "output set from OnInput at the target", func() bool { return bytes.Equal(a.out.Data(), want) })
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
