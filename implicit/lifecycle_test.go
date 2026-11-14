// SPDX-License-Identifier: MIT

package implicit

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/internal/testenv"
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

// TestCloseFromProduceAndOnData (L10): Produce may call Connection.Close
// or Endpoint.Close, at the first production, at a cyclic one and at a
// triggered one, and OnData Endpoint.Close, although each waits for
// goroutines that include the one the callback runs on; the call returns,
// the objects are closed, and nothing is sent after Close returned.
func TestCloseFromProduceAndOnData(t *testing.T) {
	type when int
	const (
		first   when = iota // the first production, when the connection starts
		cyclic              // the second, at the RPI
		trigger             // the second, by Trigger
	)
	for _, tc := range []struct {
		name     string
		produce  bool // close from Produce instead of OnData
		at       when // the production of Produce that closes
		endpoint bool // Endpoint.Close instead of Connection.Close
	}{
		{"Produce calls Connection.Close", true, first, false},
		{"Produce calls Connection.Close at the RPI", true, cyclic, false},
		{"Produce calls Connection.Close at a trigger", true, trigger, false},
		{"Produce calls Endpoint.Close", true, first, true},
		{"OnData calls Endpoint.Close", false, first, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRecMetrics()
			e := listen(t, WithMetrics(m))
			p := newPeer(t, e.LocalAddr())
			ready := make(chan struct{})
			returned := make(chan error, 1)
			var c *Connection
			closeIt := func() {
				<-ready
				if tc.endpoint {
					returned <- e.Close()
					return
				}
				c.Close()
				returned <- nil
			}
			var once sync.Once
			cfg := Config{Class: 1, ConsumedID: 0x41, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
				OnData: func([]byte, bool) { once.Do(closeIt) }}
			sent := 0 // the datagrams sent before Close
			if tc.produce {
				cfg.OnData = nil
				cfg.ProducedID, cfg.Destination, cfg.ProduceRPI, cfg.ProduceSize = 0x40, p.addr(), time.Hour, 1
				calls := 0 // on the connection's goroutine only
				var nth int
				switch tc.at {
				case first:
					nth = 1
				case cyclic:
					cfg.ProduceRPI, nth = time.Millisecond, 2
				case trigger:
					nth = 2
				}
				sent = nth - 1
				cfg.Produce = func() ([]byte, bool) {
					if calls++; calls == nth {
						closeIt()
					}
					return []byte{9}, true
				}
			}
			var err error
			c, err = e.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			close(ready)
			switch {
			case !tc.produce:
				p.send(0x41, 1, []byte{1, 0, 7})
			case tc.at == trigger:
				// The first production is sent before the trigger is
				// taken.
				p.recv()
				c.Trigger()
			}
			select {
			case err := <-returned:
				if err != nil {
					t.Fatalf("Close = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: the call has not returned", tc.name)
			}
			select {
			case <-c.Done():
			default:
				t.Fatal("Done not closed")
			}
			if n := e.Connections(); n != 0 {
				t.Errorf("%d connections left", n)
			}
			// The callback's goroutine ends once the callback returned.
			testenv.NoGoroutine(t, "implicit.(*Connection).run")
			if tc.endpoint {
				testenv.NoGoroutine(t, "implicit.(*Endpoint).receive")
			}
			if s, _ := m.counts(); s != sent || c.Stats().Sent != uint64(sent) {
				t.Errorf("%d datagrams sent (metrics %d), want the %d before Close", c.Stats().Sent, s, sent)
			}
		})
	}
}

// TestCloseWaitsForCallback (L10 and the contract of Close): a Close on
// another goroutine waits for a Produce or OnData call in progress, and an
// Endpoint.Close from a callback waits for the callback in progress on the
// other goroutine. Each Close returns only once that call returned, and no
// goroutine of the connections or of the endpoint is left.
func TestCloseWaitsForCallback(t *testing.T) {
	const produced, consumed = 0x40, 0x41
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking)
	}{
		{"Connection.Close waits for Produce", func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking) {
			c := open(t, e, Config{Class: 1, ProducedID: produced, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
				Produce: func() ([]byte, bool) { b.Call(); return []byte{9}, true }})
			b.Check(t, func() {
				go func() { c.Close(); b.Closed() }()
			}, "implicit.(*Connection).", "implicit.(*Connection).Close")
			// What the call in progress returned is sent before Close
			// returns.
			if n := c.Stats().Sent; n != 1 {
				t.Errorf("%d datagrams sent, want 1", n)
			}
		}},
		{"Endpoint.Close waits for Produce", func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking) {
			c := open(t, e, Config{Class: 1, ProducedID: produced, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
				Produce: func() ([]byte, bool) { b.Call(); return []byte{9}, true }})
			b.Check(t, func() {
				go func() { _ = e.Close(); b.Closed() }()
			}, "implicit.(*Connection).", "implicit.(*Endpoint).Close")
			if n := c.Stats().Sent; n != 1 {
				t.Errorf("%d datagrams sent, want 1", n)
			}
		}},
		{"Endpoint.Close waits for OnData", func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking) {
			open(t, e, Config{Class: 1, ConsumedID: consumed, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
				OnData: func([]byte, bool) { b.Call() }})
			p.send(consumed, 1, []byte{1, 0, 7})
			b.Check(t, func() {
				go func() { _ = e.Close(); b.Closed() }()
			}, "implicit.(*Endpoint).Close")
		}},
		{"Endpoint.Close from OnData waits for Produce", func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking) {
			open(t, e, Config{Class: 1, ProducedID: produced, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
				Produce: func() ([]byte, bool) { b.Call(); return []byte{9}, true }})
			// The datagram that calls OnData is sent after Open returned, an
			// order the race detector does not see: OnData waits for opened.
			opened := make(chan struct{})
			var once sync.Once
			open(t, e, Config{Class: 1, ConsumedID: consumed, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
				OnData: func([]byte, bool) {
					once.Do(func() {
						<-opened
						_ = e.Close()
						b.Closed()
					})
				}})
			close(opened)
			b.Check(t, func() { p.send(consumed, 1, []byte{1, 0, 7}) },
				"implicit.(*Connection).", "implicit.(*Endpoint).Close", "implicit.(*Endpoint).receive")
		}},
		{"Endpoint.Close from Produce waits for OnData", func(t *testing.T, e *Endpoint, p *peer, b *testenv.Blocking) {
			open(t, e, Config{Class: 1, ConsumedID: consumed, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
				OnData: func([]byte, bool) { b.Call() }})
			calls := 0 // on the connection's goroutine only
			c := open(t, e, Config{Class: 1, ProducedID: produced, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
				Produce: func() ([]byte, bool) {
					if calls++; calls == 2 {
						_ = e.Close()
						b.Closed()
					}
					return []byte{9}, true
				}})
			p.send(consumed, 1, []byte{1, 0, 7})
			// The second production, by Trigger, closes the endpoint.
			b.Check(t, c.Trigger, "implicit.(*Endpoint).Close", "implicit.(*Connection).produce")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := listen(t)
			p := newPeer(t, e.LocalAddr())
			tc.run(t, e, p, testenv.NewBlocking())
			if n := e.Connections(); n != 0 {
				t.Errorf("%d connections left", n)
			}
			testenv.NoGoroutine(t, "implicit.(*Connection).run")
			if !strings.HasPrefix(tc.name, "Connection.") {
				testenv.NoGoroutine(t, "implicit.(*Endpoint).receive")
			}
		})
	}
}
