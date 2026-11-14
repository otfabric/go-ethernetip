// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// The application's code that does not return normally: the client logs
// it with its stack at Error level and goes on.

// stopAbnormally ends the application's code that calls it without a
// normal return.
func stopAbnormally() { panic(errors.New("stopped by test")) }

// recLogger records the entries of a client; errs, when set, receives
// each Error entry as it is written.
type recLogger struct {
	mu    sync.Mutex
	lines []string
	errs  chan string
}

func newRecLogger() *recLogger { return &recLogger{errs: make(chan string, 64)} }

func (l *recLogger) add(level, f string, a []any) {
	e := level + " " + fmt.Sprintf(f, a...)
	l.mu.Lock()
	l.lines = append(l.lines, e)
	l.mu.Unlock()
	if level == "ERROR" && l.errs != nil {
		l.errs <- e
	}
}
func (l *recLogger) Debugf(f string, a ...any) { l.add("DEBUG", f, a) }
func (l *recLogger) Infof(f string, a ...any)  { l.add("INFO", f, a) }
func (l *recLogger) Warnf(f string, a ...any)  { l.add("WARN", f, a) }
func (l *recLogger) Errorf(f string, a ...any) { l.add("ERROR", f, a) }

// failed returns the number of Error entries, with their stack, of the
// application's code named name that did not return normally.
func (l *recLogger) failed(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.lines {
		if strings.HasPrefix(e, "ERROR ") && strings.Contains(e, "application code did not return normally callback="+name+" ") &&
			strings.Contains(e, "value=stopped by test") && strings.Contains(e, "stopAbnormally") {
			n++
		}
	}
	return n
}

// TestStateHandlerDoesNotReturnNormally: each failure is logged and the
// state change stands, when the client connects and when it loses the
// session.
func TestStateHandlerDoesNotReturnNormally(t *testing.T) {
	srv, addr := startServer(t)
	log := newRecLogger()
	var mu sync.Mutex
	var states []ethernetip.State
	c := dialT(t, addr, WithLogger(log), WithStateHandler(func(s ethernetip.State, _ error) {
		mu.Lock()
		states = append(states, s)
		mu.Unlock()
		stopAbnormally()
	}))
	if st := c.State(); st != ethernetip.StateConnected {
		t.Fatalf("state %v after Dial, want connected", st)
	}
	_ = srv.Close()
	for range 3 {
		select {
		case <-log.errs:
		case <-time.After(5 * time.Second):
			t.Fatal("no Error entry for the state handler after the session was lost")
		}
	}
	if st := c.State(); st != ethernetip.StateDisconnected {
		t.Errorf("state %v after the session was lost, want disconnected", st)
	}
	mu.Lock()
	got := append([]ethernetip.State(nil), states...)
	mu.Unlock()
	want := []ethernetip.State{ethernetip.StateConnecting, ethernetip.StateConnected, ethernetip.StateDisconnected}
	if !slices.Equal(got, want) {
		t.Errorf("states %v, want %v", got, want)
	}
	if n := log.failed("state handler"); n != 3 {
		t.Errorf("%d Error entries for the state handler, want 3", n)
	}
}

// stoppingMetrics implements Metrics and RequestMetrics; each method
// records its call and does not return normally.
type stoppingMetrics struct {
	mu    sync.Mutex
	calls map[string]int
}

func (m *stoppingMetrics) stop(name string) {
	m.mu.Lock()
	m.calls[name]++
	m.mu.Unlock()
	stopAbnormally()
}

func (m *stoppingMetrics) called(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[name]
}

func (m *stoppingMetrics) OnConnect(net.Addr)                        { m.stop("Metrics.OnConnect") }
func (m *stoppingMetrics) OnDisconnect(net.Addr, error)              { m.stop("Metrics.OnDisconnect") }
func (m *stoppingMetrics) OnPacketSent(net.Addr, encap.Command, int) { m.stop("Metrics.OnPacketSent") }
func (m *stoppingMetrics) OnPacketReceived(net.Addr, encap.Command, int) {
	m.stop("Metrics.OnPacketReceived")
}
func (m *stoppingMetrics) OnDecodeError(net.Addr, error)   { m.stop("Metrics.OnDecodeError") }
func (m *stoppingMetrics) OnRequest(net.Addr, cip.Service) { m.stop("RequestMetrics.OnRequest") }
func (m *stoppingMetrics) OnRequestDone(net.Addr, cip.Service, time.Duration, error) {
	m.stop("RequestMetrics.OnRequestDone")
}

// TestMetricsDoNotReturnNormally: every metrics hook of the client that
// does not return normally is logged, and the client works as without
// metrics: it connects, opens a connection, has its request answered past
// a malformed SendUnitData, reports a malformed reply as before, and
// closes.
func TestMetricsDoNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	m := &stoppingMetrics{calls: map[string]int{}}
	ctx := ctxT(t)

	f := fakeConnTarget(t, nil, func(p *peer, pkt encap.Packet, toID uint32, seq uint16, req cip.Request) {
		ok, _ := cip.Response{Service: req.Service, Data: []byte{7, 0}}.Encode()
		p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: pkt.Session}, Data: []byte{1}})
		unitReply(t, p, pkt, toID, seq, ok)
	})
	c, err := Dial(ctx, f.addr(), WithMetrics(m), WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil || !bytes.Equal(v, []byte{7, 0}) {
		t.Fatalf("GetAttributeSingle = %x, %v", v, err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// A malformed reply is a protocol error, reported to OnDecodeError.
	bad := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		rrReply(t, p, pkt, cip.Response{Service: cip.ServiceGetAttributeList, Data: []byte{9, 0}})
	})
	c2 := dialT(t, bad.addr(), WithMetrics(m), WithLogger(log))
	if _, err := c2.GetAttributeList(ctx, cip.ClassIdentity, 1, []uint16{1}, []int{2}); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("malformed list reply = %v, want ErrProtocol", err)
	}

	for _, name := range []string{
		"Metrics.OnConnect", "Metrics.OnDisconnect", "Metrics.OnPacketSent", "Metrics.OnPacketReceived",
		"Metrics.OnDecodeError", "RequestMetrics.OnRequest", "RequestMetrics.OnRequestDone",
	} {
		called, logged := m.called(name), log.failed(name)
		if called == 0 || logged != called {
			t.Errorf("%s: called %d times, %d Error entries", name, called, logged)
		}
	}
	if n := m.called("Metrics.OnDecodeError"); n != 2 {
		t.Errorf("OnDecodeError called %d times, want 2: the SendUnitData and the list reply", n)
	}
}
