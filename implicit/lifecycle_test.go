// SPDX-License-Identifier: MIT

package implicit

import (
	"sync"
	"testing"
	"time"
)

// Contract tests of Endpoint and Connection (TESTING.md, "Lifecycle
// contracts"): rows L2 (concurrent Close), L9 (a callback calls a method)
// and L10 (a callback calls Close).

// closeAll calls f from several goroutines at once and waits for them.
func closeAll(f func()) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(f)
	}
	wg.Wait()
}

// TestConcurrentClose (L2): Connection.Close and Endpoint.Close called by
// several goroutines at once all return, and the objects are closed.
func TestConcurrentClose(t *testing.T) {
	e, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink := listen(t)
	cfg := Config{Class: 1, ProducedID: 0x10, Destination: sink.LocalAddr(), ProduceRPI: time.Millisecond, ProduceSize: 2,
		ConsumedID: 0x20, ConsumeSize: 2, Timeout: time.Hour}
	c, err := e.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ProducedID, cfg.ConsumedID = 0x11, 0x21
	other, err := e.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeAll(c.Close)
	select {
	case <-c.Done():
	default:
		t.Fatal("Done not closed")
	}
	if n := e.Connections(); n != 1 {
		t.Errorf("%d connections after closing one of two", n)
	}
	errs := make(chan error, 8)
	closeAll(func() { errs <- e.Close() })
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Endpoint.Close = %v", err)
		}
	}
	<-other.Done()
	if n := e.Connections(); n != 0 {
		t.Errorf("%d connections after Endpoint.Close", n)
	}
}

// TestCallbacksCallConnection (L9, L10): OnData and OnTimeout may call the
// connection's methods, Close included; the calls return and the
// connection is closed.
func TestCallbacksCallConnection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout bool // close from OnTimeout instead of OnData
	}{
		{"OnData", false},
		{"OnTimeout", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := listen(t)
			p := newPeer(t, e.LocalAddr())
			returned := make(chan struct{})
			var c *Connection
			ready := make(chan struct{})
			call := func() {
				<-ready
				_, _ = c.Stats(), c.TimedOut()
				c.Trigger()
				c.Close()
				close(returned)
			}
			cfg := Config{Class: 1, ProducedID: 0x30, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
				ConsumedID: 0x31, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour}
			if tc.timeout {
				cfg.Timeout = 20 * time.Millisecond
				cfg.OnTimeout = call
			} else {
				cfg.OnData = func([]byte, bool) { call() }
			}
			var err error
			c, err = e.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			close(ready)
			if !tc.timeout {
				p.send(0x31, 1, []byte{1, 0, 7})
			}
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatalf("Close called from %s has not returned", tc.name)
			}
			select {
			case <-c.Done():
			default:
				t.Fatal("Done not closed")
			}
			if n := e.Connections(); n != 0 {
				t.Errorf("%d connections left", n)
			}
		})
	}
}
