// SPDX-License-Identifier: MIT

package implicit

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// The application's code that does not return normally: each call site
// logs it with its stack at Error level and goes on as documented.

var errStopped = errors.New("stopped by test")

// stopAbnormally ends the application's code that calls it without a
// normal return.
func stopAbnormally() { panic(errStopped) }

// failed reports whether log has the Error entry, with its stack, of the
// application's code named name that did not return normally.
func failed(log *recLogger, name string) bool {
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, l := range log.lines {
		if strings.HasPrefix(l, "ERROR ") && strings.Contains(l, "application code did not return normally callback="+name+" ") &&
			strings.Contains(l, "value=stopped by test") && strings.Contains(l, "stopAbnormally") {
			return true
		}
	}
	return false
}

// TestProduceDoesNotReturnNormally: that production sends nothing, the
// failure is logged, and the next production is sent.
func TestProduceDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	e := listen(t, WithLogger(log))
	p := newPeer(t, e.LocalAddr())
	var calls atomic.Int32
	c := open(t, e, Config{Class: 1, ProducedID: 0x50, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
		Produce: func() ([]byte, bool) {
			if calls.Add(1) == 1 {
				stopAbnormally()
			}
			return []byte{2}, true
		}})
	c.Trigger()
	m := p.recv()
	// The first datagram is the second production's: the first one took
	// no sequence number.
	if m.ConnID != 0x50 || m.EncapSeq != 1 || len(m.Payload) != 3 || m.Payload[2] != 2 {
		t.Fatalf("datagram %+v, want the second production's with sequence 1", m)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("Produce called %d times, want 2", n)
	}
	if !failed(log, "Produce") {
		t.Errorf("no Error entry for Produce")
	}
}

// TestOnDataDoesNotReturnNormally: the failure is logged and the endpoint
// goes on with the next datagram.
func TestOnDataDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	e := listen(t, WithLogger(log))
	p := newPeer(t, e.LocalAddr())
	got := make(chan byte, 1)
	var calls atomic.Int32
	c := open(t, e, Config{Class: 1, ConsumedID: 0x51, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
		OnData: func(b []byte, _ bool) {
			if calls.Add(1) == 1 {
				stopAbnormally()
			}
			got <- b[0]
		}})
	p.send(0x51, 1, []byte{1, 0, 7})
	p.send(0x51, 2, []byte{2, 0, 8})
	select {
	case b := <-got:
		if b != 8 {
			t.Errorf("OnData got %d, want the second datagram's 8", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnData not called for the datagram after the one whose OnData did not return normally")
	}
	if !failed(log, "OnData") {
		t.Errorf("no Error entry for OnData")
	}
	if st := c.Stats(); st.Received != 2 {
		t.Errorf("Received = %d, want 2", st.Received)
	}
}

// TestOnTimeoutDoesNotReturnNormally: the failure is logged and the
// connection is closed as after any timeout.
func TestOnTimeoutDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	e := listen(t, WithLogger(log))
	c := open(t, e, Config{Class: 1, ConsumedID: 0x52, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Timeout: 10 * time.Millisecond, OnTimeout: stopAbnormally})
	<-c.Done()
	// The connection's goroutine ends after OnTimeout.
	testenv.NoGoroutine(t, "implicit.(*Connection).run")
	if !c.TimedOut() {
		t.Error("TimedOut = false")
	}
	if !failed(log, "OnTimeout") {
		t.Errorf("no Error entry for OnTimeout")
	}
	if n := e.Connections(); n != 0 {
		t.Errorf("%d connections left", n)
	}
}

// stoppingMetrics is IOMetrics whose every method does not return
// normally; OnIOSent first reports each call on sends.
type stoppingMetrics struct {
	recMetrics
	sends chan struct{}
}

func (m *stoppingMetrics) OnIOSent(uint32, int) {
	m.sends <- struct{}{}
	stopAbnormally()
}
func (*stoppingMetrics) OnIOReceived(uint32, int)     { stopAbnormally() }
func (*stoppingMetrics) OnIODropped(net.Addr, string) { stopAbnormally() }

// TestIOMetricsDoNotReturnNormally: each failure is logged, and sending,
// receiving and dropping go on.
func TestIOMetricsDoNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	mt := &stoppingMetrics{sends: make(chan struct{}, 8)}
	e := listen(t, WithLogger(log), WithMetrics(mt))
	p := newPeer(t, e.LocalAddr())
	got := make(chan byte, 1)
	c := open(t, e, Config{Class: 1, ProducedID: 0x53, Destination: p.addr(), ProduceRPI: time.Hour, ProduceSize: 1,
		ConsumedID: 0x54, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: time.Hour,
		OnData: func(b []byte, _ bool) { got <- b[0] }})
	// The first production's OnIOSent is logged before the second
	// production.
	p.recv()
	c.Trigger()
	if m := p.recv(); m.EncapSeq != 2 {
		t.Errorf("second datagram with sequence %d", m.EncapSeq)
	}
	// A datagram is counted in Stats after it is sent and before
	// OnIOSent: the peer may receive it first. Wait for both calls.
	for i := range 2 {
		select {
		case <-mt.sends:
		case <-time.After(5 * time.Second):
			t.Fatalf("OnIOSent called %d times, want 2", i)
		}
	}
	// A datagram for no connection is dropped before the next is handled.
	p.send(0x99, 1, []byte{1, 0, 7})
	p.send(0x54, 1, []byte{1, 0, 7})
	select {
	case b := <-got:
		if b != 7 {
			t.Errorf("OnData got %d", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnData not called after OnIOReceived did not return normally")
	}
	for _, name := range []string{"IOMetrics.OnIOSent", "IOMetrics.OnIODropped", "IOMetrics.OnIOReceived"} {
		if !failed(log, name) {
			t.Errorf("no Error entry for %s", name)
		}
	}
	if st := c.Stats(); st.Sent != 2 || st.Received != 1 {
		t.Errorf("stats %+v, want 2 sent and 1 received", st)
	}
}
