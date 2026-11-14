// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
)

// Contract tests of Server (TESTING.md, "Lifecycle contracts"): rows L2
// (concurrent Close) and L9 (a handler calls a method).

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
