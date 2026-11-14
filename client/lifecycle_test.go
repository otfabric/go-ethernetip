// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Contract tests of Client and Conn (TESTING.md, "Lifecycle contracts"):
// rows L2 (concurrent Close), L3 (Close during a blocked read) and L4
// (Close during a write).

// gateConn holds one write behind a gate while armed: the write reports on
// entered and then waits for release, which fails it with the error sent
// (nil lets it through).
type gateConn struct {
	net.Conn
	armed   *atomic.Bool
	entered chan struct{}
	release chan error
}

func (c gateConn) Write(b []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		c.entered <- struct{}{}
		if err := <-c.release; err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// gate is a dialer of gateConns sharing one gate.
type gate struct {
	armed   *atomic.Bool
	entered chan struct{}
	release chan error
}

func newGate() *gate {
	return &gate{armed: &atomic.Bool{}, entered: make(chan struct{}, 1), release: make(chan error, 1)}
}

func (g *gate) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return gateConn{Conn: c, armed: g.armed, entered: g.entered, release: g.release}, nil
}

// waitEntered waits for the gated write to start.
func (g *gate) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the write did not start")
	}
}

// returnsWithin waits for the result of a call running in another
// goroutine.
func returnsWithin(t *testing.T, d time.Duration, what string, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("%s has not returned after %v", what, d)
		return nil
	}
}

// silentConnTarget is a target that opens and closes Class 3 connections
// and never answers on them.
func silentConnTarget(t *testing.T) *fakeTarget {
	return fakeConnTarget(t, nil, func(*peer, encap.Packet, uint32, uint16, cip.Request) {})
}

// TestConnCloseDuringRead (L3): Close fails the request waiting for its
// reply with ErrClosed at once, not at the client's timeout.
func TestConnCloseDuringRead(t *testing.T) {
	f := silentConnTarget(t)
	c := dialT(t, f.addr(), WithTimeout(10*time.Second))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := cn.Identity(ctx); done <- err }()
	eventually(t, 2*time.Second, "request pending", func() bool {
		cn.mu.Lock()
		defer cn.mu.Unlock()
		return cn.pending != nil
	})
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := returnsWithin(t, 2*time.Second, "Conn.Do", done); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request in flight = %v, want ErrClosed", err)
	}
	if _, err := cn.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request after Close = %v, want ErrClosed", err)
	}
}

// TestConnCloseDuringWrite (L4): Close while the request's write is held;
// the write then fails. The request ends with ErrClosed, within the
// client's timeout, and later requests fail at once.
func TestConnCloseDuringWrite(t *testing.T) {
	_, addr := startServer(t)
	g := newGate()
	c := dialT(t, addr, WithDialer(g), WithTimeout(3*time.Second))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g.armed.Store(true)
	done := make(chan error, 1)
	go func() { _, err := cn.Identity(ctx); done <- err }()
	g.waitEntered(t)
	closed := make(chan error, 1)
	go func() { closed <- cn.Close(ctx) }()
	// Close has ended the connection and taken it from the session; its
	// Forward_Close waits for the held write.
	eventually(t, 2*time.Second, "Close started", func() bool {
		cn.mu.Lock()
		ended := cn.err != nil
		cn.mu.Unlock()
		cn.s.mu.Lock()
		_, registered := cn.s.conns[cn.info.OTConnID]
		cn.s.mu.Unlock()
		return ended && !registered
	})
	g.release <- timeoutErr{}
	if err := returnsWithin(t, 3*time.Second, "Conn.Do", done); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request in flight = %v, want ErrClosed", err)
	}
	_ = returnsWithin(t, 5*time.Second, "Conn.Close", closed)
	start := time.Now()
	if _, err := cn.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request after Close = %v, want ErrClosed", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("request after Close took %v", d)
	}
}

// TestConnWriteFailureBoundedByContext: a request whose write fails
// returns when its context ends even when nothing else fails it, and
// leaves no request pending on the connection.
func TestConnWriteFailureBoundedByContext(t *testing.T) {
	_, addr := startServer(t)
	g := newGate()
	c := dialT(t, addr, WithDialer(g), WithTimeout(3*time.Second))
	cn, err := c.OpenConnection(ctxT(t), ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g.armed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := cn.Identity(ctx); done <- err }()
	g.waitEntered(t)
	// The connection leaves the session, so that the session's end does
	// not reach it, and the request's context ends.
	cn.s.mu.Lock()
	delete(cn.s.conns, cn.info.OTConnID)
	cn.s.mu.Unlock()
	cancel()
	g.release <- timeoutErr{}
	if err := returnsWithin(t, 3*time.Second, "Conn.Do", done); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("request = %v, want ErrConnectionLost", err)
	}
	cn.mu.Lock()
	pending := cn.pending
	cn.mu.Unlock()
	if pending != nil {
		t.Error("request still pending")
	}
}

// TestClientCloseDuringRead (L3): Client.Close fails the request waiting
// for its reply with ErrClosed at once.
func TestClientCloseDuringRead(t *testing.T) {
	f := newFakeTarget(t, nil) // registers, then never answers
	c := dialT(t, f.addr(), WithTimeout(10*time.Second))
	done := make(chan error, 1)
	go func() { _, err := c.Identity(context.Background()); done <- err }()
	eventually(t, 2*time.Second, "request pending", func() bool {
		c.mu.Lock()
		s := c.sess
		c.mu.Unlock()
		if s == nil {
			return false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.pending) == 1
	})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := returnsWithin(t, 2*time.Second, "the request", done); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request in flight = %v, want ErrClosed", err)
	}
}

// TestClientCloseDuringWrite (L4): Client.Close while a request's write is
// held. Close waits for the write (at most the client's timeout); the
// request fails with ErrClosed, as Close's documentation says.
func TestClientCloseDuringWrite(t *testing.T) {
	f := newFakeTarget(t, nil)
	g := newGate()
	c := dialT(t, f.addr(), WithDialer(g), WithTimeout(3*time.Second))
	s := c.sess
	g.armed.Store(true)
	done := make(chan error, 1)
	go func() { _, err := c.Identity(context.Background()); done <- err }()
	g.waitEntered(t)
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	eventually(t, 2*time.Second, "Close started", s.closing.Load)
	g.release <- timeoutErr{}
	if err := returnsWithin(t, 3*time.Second, "the request", done); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request in flight = %v, want ErrClosed", err)
	}
	if err := returnsWithin(t, 5*time.Second, "Client.Close", closed); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(context.Background()); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("request after Close = %v, want ErrClosed", err)
	}
}

// TestConcurrentClose (L2): Close of a Client and of a Conn called by
// several goroutines at once: every call returns nil, the Forward_Close is
// sent once, and the objects stay closed.
func TestConcurrentClose(t *testing.T) {
	srv, addr := startServer(t)
	c := dialT(t, addr)
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
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
	closeAll(func() error { return cn.Close(ctx) })
	if n := len(srv.Connections()); n != 0 {
		t.Errorf("%d connections at the server after Conn.Close", n)
	}
	closeAll(c.Close)
	if c.State() != ethernetip.StateDisconnected {
		t.Errorf("state after Close %v", c.State())
	}
	if _, err := cn.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Conn after Close = %v", err)
	}
	if _, err := c.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Client after Close = %v", err)
	}
}
