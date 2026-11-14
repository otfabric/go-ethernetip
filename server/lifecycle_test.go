// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// Contract tests of Server (TESTING.md, "Lifecycle contracts"): rows L2
// (concurrent Close), L9 (a handler calls a method) and L10 (a handler
// calls Close).

// TestConcurrentClose (L2): Server.Close called by several goroutines at
// once, with a session open: every call returns nil, the session is
// closed and Serve returns ErrClosed.
func TestConcurrentClose(t *testing.T) {
	s, err := New(WithIOAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	p := dialPeer(t, s)
	p.register()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.Close() })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Close = %v", err)
		}
	}
	if err := <-served; !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Serve = %v, want ErrClosed", err)
	}
	p.expectClosed()
	if n := s.Sessions(); n != 0 {
		t.Errorf("%d sessions after Close", n)
	}
}

// TestHandlerCallsServer (L9): a service handler may call the server's
// methods while it serves a request.
func TestHandlerCallsServer(t *testing.T) {
	s := startServer(t)
	o := NewObject(0x65, 1)
	o.AddInstance(1)
	o.HandleService(0x4B, func(context.Context, *Request) cip.Response {
		_ = s.Identity()
		_ = s.Classes()
		_ = s.Object(cip.ClassIdentity)
		_ = s.Connections()
		s.SetIdentityStatus(s.Identity().Status)
		return cip.Response{Data: []byte{byte(s.Sessions())}}
	})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	r := p.do(cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)})
	if r.Status != cip.StatusSuccess || len(r.Data) != 1 || r.Data[0] != 1 {
		t.Fatalf("response %+v, want one session", r)
	}
}

// serving returns a server that serves on loopback addresses, and the
// channel that receives what Serve returns.
func serving(t *testing.T) (*Server, <-chan error) {
	t.Helper()
	s, err := New(WithIOAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s, served
}

// sendRequest sends req on the session of p, unconnected or on a Class 3
// connection it opens first, and does not wait for the reply.
func sendRequest(t *testing.T, p *peer, req cip.Request, connected bool) {
	t.Helper()
	msg := mustEncode(t, req)
	cmd, items := encap.CommandSendRRData, []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}
	if connected {
		reply, _ := p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
		cmd, items = encap.CommandSendUnitData, []encap.Item{encap.ConnectedAddress(reply.OTConnID), {Type: encap.ItemConnectedData, Data: append([]byte{1, 0}, msg...)}}
	}
	data, err := encap.RRData{Items: items}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p.send(cmd, p.handle, data)
}

// expectServed checks that Serve returned ErrClosed.
func expectServed(t *testing.T, served <-chan error) {
	t.Helper()
	select {
	case err := <-served:
		if !errors.Is(err, ethernetip.ErrClosed) {
			t.Errorf("Serve = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve has not returned after Close")
	}
}

// TestHandlerCallsClose (L10): a request's handler may call Server.Close,
// which waits for the server's goroutines except the handler's session
// goroutine; the call returns, Serve returns ErrClosed, and the session's
// goroutine ends once the handler returned.
func TestHandlerCallsClose(t *testing.T) {
	for _, connected := range []bool{false, true} {
		name := "unconnected request"
		if connected {
			name = "Class 3 request"
		}
		t.Run(name, func(t *testing.T) {
			s, served := serving(t)
			returned := make(chan error, 1)
			o := NewObject(0x65, 1)
			o.AddInstance(1)
			o.HandleService(0x4B, func(context.Context, *Request) cip.Response {
				returned <- s.Close()
				return cip.Response{}
			})
			s.RegisterObject(o)
			p := dialPeer(t, s)
			p.register()
			sendRequest(t, p, cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)}, connected)
			select {
			case err := <-returned:
				if err != nil {
					t.Fatalf("Close from a handler = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close called from a handler has not returned")
			}
			expectServed(t, served)
			p.expectClosed()
			testenv.NoGoroutine(t, "server.(*Server).serveConn")
			if n := s.Sessions(); n != 0 {
				t.Errorf("%d sessions after Close", n)
			}
		})
	}
}

// TestCloseWaitsForHandler (contract of Close): a Server.Close on another
// goroutine waits for a request's handler in progress, and one from a
// handler waits for the handler in progress on another session. Each
// returns only once that handler returned; Serve returns ErrClosed and no
// session goroutine is left.
func TestCloseWaitsForHandler(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connected bool // the handler in progress serves a Class 3 request
		handler   bool // Close is called from the handler of another session
	}{
		{"unconnected request", false, false},
		{"Class 3 request", true, false},
		{"Close from a handler on another session", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, served := serving(t)
			b := testenv.NewBlocking()
			o := NewObject(0x65, 1)
			o.AddInstance(1)
			o.HandleService(0x4B, func(context.Context, *Request) cip.Response {
				b.Call()
				return cip.Response{}
			})
			o.HandleService(0x4C, func(context.Context, *Request) cip.Response {
				_ = s.Close()
				b.Closed()
				return cip.Response{}
			})
			s.RegisterObject(o)
			p, x := dialPeer(t, s), dialPeer(t, s)
			p.register()
			x.register()
			sendRequest(t, p, cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)}, tc.connected)
			start := func() {
				go func() {
					_ = s.Close()
					b.Closed()
				}()
			}
			var in []string
			if tc.handler {
				start = func() { sendRequest(t, x, cip.Request{Service: 0x4C, Path: cip.ObjectPath(0x65, 1)}, false) }
				in = []string{"server.(*session).serve"}
			}
			b.Check(t, start, "server.(*Server).Close", in...)
			expectServed(t, served)
			p.expectClosed()
			x.expectClosed()
			testenv.NoGoroutine(t, "server.(*Server).serveConn")
			if n := s.Sessions(); n != 0 {
				t.Errorf("%d sessions after Close", n)
			}
		})
	}
}
