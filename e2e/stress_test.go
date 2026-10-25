// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

// TestStressManyClients runs many clients at once, each with its own
// session, doing single and multiple service requests.
func TestStressManyClients(t *testing.T) {
	a := startAdapter(t, server.WithMaxSessions(100))
	const clients, requests = 40, 40
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := client.Dial(ctx, a.addr)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			for j := 0; j < requests; j++ {
				if j%4 == 0 {
					resps, err := c.MultipleService(ctx, []cip.Request{
						{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 3)},
						{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 6)},
					})
					if err != nil || len(resps) != 2 {
						errs <- err
						return
					}
					continue
				}
				id, err := c.Identity(ctx)
				if err != nil || id.SerialNumber != testIdentity.SerialNumber {
					errs <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "sessions released", func() bool { return a.srv.Sessions() == 0 })
}

// TestStressSharedSession issues concurrent requests over one session with
// several outstanding at a time: replies must find their requests.
func TestStressSharedSession(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr, client.WithMaxPending(8))
	ctx := ctxT(t)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// Each goroutine reads an attribute whose value tells it apart.
			attr := []uint16{1, 2, 3, 6}[g%4]
			want := map[uint16]int{1: 2, 2: 2, 3: 2, 6: 4}[attr]
			for i := 0; i < 100; i++ {
				b, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, attr)
				if err != nil || len(b) != want {
					bad.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d wrong replies", n)
	}
}

// TestStressSessionLimit registers more sessions than the server allows,
// concurrently: exactly the limit succeeds, the others are refused with
// insufficient memory, and after closing all of them there is room again.
func TestStressSessionLimit(t *testing.T) {
	const limit = 10
	a := startAdapter(t, server.WithMaxSessions(limit))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok []*client.Client
	refused := 0
	for i := 0; i < 3*limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := client.Dial(ctxT(t), a.addr)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok = append(ok, c)
				return
			}
			var ee *ethernetip.EncapError
			if errors.As(err, &ee) && ee.Status == encap.StatusInsufficientMemory && errors.Is(err, ethernetip.ErrConnectFailed) {
				refused++
				return
			}
			t.Errorf("unexpected error %v", err)
		}()
	}
	wg.Wait()
	if len(ok) != limit || refused != 2*limit {
		t.Fatalf("%d sessions, %d refused", len(ok), refused)
	}
	for _, c := range ok {
		_ = c.Close()
	}
	eventually(t, 5*time.Second, "sessions released", func() bool { return a.srv.Sessions() == 0 })
	if c, err := client.Dial(ctxT(t), a.addr); err != nil {
		t.Fatal(err)
	} else {
		_ = c.Close()
	}
}

// TestStressConnections opens many I/O and Class 3 connections at once:
// input-only connections share the input assembly; each exchanges data.
func TestStressConnections(t *testing.T) {
	a := startAdapter(t, server.WithMaxConnections(64))
	c := dial(t, a.addr, client.WithMaxPending(4))
	s := newScanner(t, c)
	ctx := ctxT(t)
	in := bytes.Repeat([]byte{0x42}, ioSize)
	_ = a.in.SetData(in)
	var wg sync.WaitGroup
	ios := make([]*scanner.IO, 20)
	errs := make([]error, len(ios))
	for i := range ios {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := exclusiveOwner(10 * time.Millisecond)
			cfg.OutputInstance, cfg.OutputSize = asmInputOnly, 0
			ios[i], errs[i] = s.Open(ctx, cfg)
		}(i)
	}
	conns := make([]*client.Conn, 10)
	cerrs := make([]error, len(conns))
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], cerrs[i] = c.OpenConnection(ctx, client.ConnectionOptions{})
		}(i)
	}
	wg.Wait()
	for _, err := range append(errs, cerrs...) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := len(a.srv.Connections()); n != 30 {
		t.Fatalf("%d connections", n)
	}
	for _, io := range ios {
		io := io
		eventually(t, 3*time.Second, "input", func() bool { d, _, _ := io.Input(); return bytes.Equal(d, in) })
	}
	for _, cn := range conns {
		wg.Add(1)
		go func(cn *client.Conn) {
			defer wg.Done()
			if _, err := cn.Identity(ctx); err != nil {
				t.Error(err)
			}
		}(cn)
	}
	wg.Wait()
	for _, io := range ios {
		wg.Add(1)
		go func(io *scanner.IO) {
			defer wg.Done()
			if err := io.Close(ctx); err != nil {
				t.Error(err)
			}
		}(io)
	}
	for _, cn := range conns {
		wg.Add(1)
		go func(cn *client.Conn) {
			defer wg.Done()
			if err := cn.Close(ctx); err != nil {
				t.Error(err)
			}
		}(cn)
	}
	wg.Wait()
	eventually(t, 5*time.Second, "connections closed", func() bool { return len(a.srv.Connections()) == 0 })
}

// TestStressReconnectStorm restarts the server while clients with
// auto-reconnect keep sending: requests fail only with connection errors
// and all clients work again after the last restart.
func TestStressReconnectStorm(t *testing.T) {
	a := startAdapter(t)
	addr := a.addr
	const clients = 10
	cs := make([]*client.Client, clients)
	for i := range cs {
		cs[i] = dial(t, addr, client.WithAutoReconnect(), client.WithTimeout(500*time.Millisecond))
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var unexpected atomic.Value
	for _, c := range cs {
		wg.Add(1)
		go func(c *client.Client) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				_, err := c.Identity(ctx)
				cancel()
				if err != nil && !allowedChaosError(err) && !errors.Is(err, context.DeadlineExceeded) {
					unexpected.Store(err)
				}
			}
		}(c)
	}
	srv := a.srv
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		_ = srv.Close()
		srv = startAdapterAt(t, addr).srv
	}
	close(stop)
	wg.Wait()
	if err, _ := unexpected.Load().(error); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range cs {
		var err error
		for i := 0; i < 5; i++ {
			if _, err = c.Identity(ctxT(t)); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("client did not recover: %v", err)
		}
	}
}

// TestStressConnectCycles connects and disconnects quickly, many times,
// with sessions abandoned without UnRegisterSession too.
func TestStressConnectCycles(t *testing.T) {
	a := startAdapter(t)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		c, err := client.Dial(ctxT(t), a.addr)
		if err != nil {
			t.Fatal(err)
		}
		if rng.Intn(2) == 0 {
			if _, err := c.ListIdentity(ctxT(t)); err != nil {
				t.Fatal(err)
			}
		}
		_ = c.Close()
	}
	eventually(t, 5*time.Second, "sessions released", func() bool { return a.srv.Sessions() == 0 })
}

// TestStressShutdownUnderLoad closes the server while clients hammer it:
// Close returns promptly and the clients fail with connection errors.
func TestStressShutdownUnderLoad(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr, client.WithMaxPending(4))
	s := newScanner(t, c)
	if _, err := s.Open(ctxT(t), exclusiveOwner(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var unexpected atomic.Value
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err := c.Identity(ctx)
				cancel()
				if err != nil && !allowedChaosError(err) {
					unexpected.Store(err)
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	_ = a.srv.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v", d)
	}
	close(stop)
	wg.Wait()
	if err, _ := unexpected.Load().(error); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStressCancellation cancels requests at random points: the client
// stays usable and later replies do not reach the wrong request.
func TestStressCancellation(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr, client.WithMaxPending(4))
	rng := rand.New(rand.NewSource(2))
	var wg sync.WaitGroup
	var mu sync.Mutex
	delays := make([]time.Duration, 400)
	for i := range delays {
		delays[i] = time.Duration(rng.Intn(400)) * time.Microsecond
	}
	var bad atomic.Int32
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := g; i < len(delays); i += 4 {
				mu.Lock()
				d := delays[i]
				mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), d)
				b, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7)
				cancel()
				if err == nil && string(b[1:]) != testIdentity.ProductName {
					bad.Add(1)
				}
				if err != nil && !errors.Is(err, ethernetip.ErrTimeout) && !errors.Is(err, context.Canceled) {
					if bad.Add(1) == 1 {
						t.Logf("first unexpected error: %v", err)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d wrong outcomes", n)
	}
	if _, err := c.Identity(ctxT(t)); err != nil {
		t.Fatalf("client unusable after cancellations: %v", err)
	}
}
