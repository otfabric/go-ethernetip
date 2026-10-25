// SPDX-License-Identifier: MIT

package implicit

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
)

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// recMetrics records the I/O metrics of an endpoint.
type recMetrics struct {
	ethernetip.NopMetrics
	mu       sync.Mutex
	sent     int
	received int
	dropped  map[string]int
}

func newRecMetrics() *recMetrics { return &recMetrics{dropped: map[string]int{}} }

func (m *recMetrics) OnIOSent(uint32, int) {
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()
}

func (m *recMetrics) OnIOReceived(uint32, int) {
	m.mu.Lock()
	m.received++
	m.mu.Unlock()
}

func (m *recMetrics) OnIODropped(_ net.Addr, reason string) {
	m.mu.Lock()
	m.dropped[reason]++
	m.mu.Unlock()
}

func (m *recMetrics) drops(reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped[reason]
}

func (m *recMetrics) counts() (sent, received int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent, m.received
}

// recLogger records log lines.
type recLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLogger) add(level, f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(f, a...))
	l.mu.Unlock()
}
func (l *recLogger) Debugf(f string, a ...any) { l.add("DEBUG", f, a...) }
func (l *recLogger) Infof(f string, a ...any)  { l.add("INFO", f, a...) }
func (l *recLogger) Warnf(f string, a ...any)  { l.add("WARN", f, a...) }
func (l *recLogger) Errorf(f string, a ...any) { l.add("ERROR", f, a...) }

func (l *recLogger) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}

func listen(t *testing.T, opts ...EndpointOption) *Endpoint {
	t.Helper()
	e, err := Listen("127.0.0.1:0", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func open(t *testing.T, e *Endpoint, cfg Config) *Connection {
	t.Helper()
	c, err := e.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// peer is a raw UDP socket that injects datagrams into an endpoint.
type peer struct {
	t    *testing.T
	conn *net.UDPConn
	to   netip.AddrPort
}

func newPeer(t *testing.T, to netip.AddrPort) *peer {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &peer{t: t, conn: c, to: to}
}

func (p *peer) addr() netip.AddrPort { return p.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (p *peer) raw(b []byte) {
	p.t.Helper()
	if _, err := p.conn.WriteToUDPAddrPort(b, p.to); err != nil {
		p.t.Fatal(err)
	}
}

func (p *peer) send(connID, encapSeq uint32, payload []byte) {
	p.t.Helper()
	b, err := Message{ConnID: connID, EncapSeq: encapSeq, Payload: payload}.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	p.raw(b)
}

// recv reads one datagram with a deadline.
func (p *peer) recv() Message {
	p.t.Helper()
	buf := make([]byte, 2048)
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := p.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		p.t.Fatal(err)
	}
	m, err := Decode(buf[:n])
	if err != nil {
		p.t.Fatal(err)
	}
	return m
}

// dataLog records OnData calls.
type dataLog struct {
	mu    sync.Mutex
	data  [][]byte
	runs  []bool
	calls atomic.Int64
}

func (d *dataLog) onData(b []byte, run bool) {
	d.mu.Lock()
	d.data = append(d.data, append([]byte(nil), b...))
	d.runs = append(d.runs, run)
	d.mu.Unlock()
	d.calls.Add(1)
}

func (d *dataLog) last() ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.data) == 0 {
		return nil, false
	}
	return d.data[len(d.data)-1], d.runs[len(d.runs)-1]
}

func (d *dataLog) n() int { return int(d.calls.Load()) }

func TestExchange(t *testing.T) {
	ma, mb := newRecMetrics(), newRecMetrics()
	a := listen(t, WithMetrics(ma))
	b := listen(t, WithMetrics(mb))

	var aCount, bCount atomic.Uint32
	var aGot, bGot dataLog
	// a is the originator: O->T with the run/idle header, T->O modeless.
	open(t, a, Config{
		Class:         1,
		ProducedID:    0x100,
		Destination:   b.LocalAddr(),
		ProduceRPI:    2 * time.Millisecond,
		ProduceFormat: FormatHeader32,
		ProduceSize:   4,
		Produce: func() ([]byte, bool) {
			n := aCount.Add(1)
			return []byte{byte(n), byte(n >> 8), 0xA0, 0xA1}, true
		},
		ConsumedID:    0x200,
		Timeout:       5 * time.Second,
		ConsumeFormat: FormatModeless,
		ConsumeSize:   2,
		Source:        netip.MustParseAddr("127.0.0.1"),
		OnData:        aGot.onData,
	})
	cb := open(t, b, Config{
		Class:         1,
		ProducedID:    0x200,
		Destination:   a.LocalAddr(),
		ProduceRPI:    2 * time.Millisecond,
		ProduceFormat: FormatModeless,
		ProduceSize:   2,
		Produce: func() ([]byte, bool) {
			n := bCount.Add(1)
			return []byte{0xB0, byte(n)}, true
		},
		ConsumedID:    0x100,
		Timeout:       5 * time.Second,
		ConsumeFormat: FormatHeader32,
		ConsumeSize:   4,
		OnData:        bGot.onData,
	})

	waitFor(t, "data both ways", func() bool { return aGot.n() >= 5 && bGot.n() >= 5 })
	if d, run := bGot.last(); len(d) != 4 || d[2] != 0xA0 || d[3] != 0xA1 || !run {
		t.Errorf("b got % X run %v", d, run)
	}
	if d, run := aGot.last(); len(d) != 2 || d[0] != 0xB0 || !run {
		t.Errorf("a got % X run %v", d, run)
	}
	st := cb.Stats()
	if st.Sent == 0 || st.Received == 0 || st.LastSent.IsZero() || st.LastReceived.IsZero() {
		t.Errorf("Stats = %+v", st)
	}
	if s, r := ma.counts(); s == 0 || r == 0 {
		t.Errorf("metrics a: sent %d received %d", s, r)
	}
	if a.Connections() != 1 || b.Connections() != 1 {
		t.Errorf("Connections = %d, %d", a.Connections(), b.Connections())
	}
	if cb.TimedOut() {
		t.Error("TimedOut with traffic")
	}
}

func TestDuplicatesAndRunIdle(t *testing.T) {
	a := listen(t)
	b := listen(t)
	var got dataLog
	cons := open(t, b, Config{Class: 1, ConsumedID: 7, ConsumeFormat: FormatHeader32, ConsumeSize: 3, OnData: got.onData})

	// A nil Produce sends the same zeros every time: the sequence count
	// does not change, so the consumer gets the data once and counts the
	// repeats as duplicates.
	open(t, a, Config{Class: 1, ProducedID: 7, Destination: b.LocalAddr(), ProduceRPI: time.Millisecond, ProduceFormat: FormatHeader32, ProduceSize: 3})
	waitFor(t, "duplicates", func() bool { return cons.Stats().Duplicates >= 5 })
	if got.n() != 1 {
		t.Errorf("OnData called %d times for unchanged data", got.n())
	}
	if d, run := got.last(); !bytes.Equal(d, []byte{0, 0, 0}) || !run {
		t.Errorf("data % X run %v", d, run)
	}
	st := cons.Stats()
	if st.Received < st.Duplicates+1 || st.Dropped != 0 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestRunIdleChangeBumpsSequence(t *testing.T) {
	a := listen(t)
	p := newPeer(t, a.LocalAddr())
	var run atomic.Bool
	run.Store(true)
	c := open(t, a, Config{
		Class: 1, ProducedID: 3, Destination: p.addr(), ProduceRPI: time.Hour,
		ProduceFormat: FormatHeader32, ProduceSize: 1,
		Produce: func() ([]byte, bool) { return []byte{9}, run.Load() },
	})
	m1 := p.recv()
	c.Trigger()
	m2 := p.recv()
	run.Store(false)
	c.Trigger()
	m3 := p.recv()

	seqs := []uint16{}
	for i, m := range []Message{m1, m2, m3} {
		if m.ConnID != 3 || m.EncapSeq != uint32(i+1) {
			t.Errorf("datagram %d: conn %d encap seq %d", i, m.ConnID, m.EncapSeq)
		}
		pl, err := SplitPayload(m.Payload, 1, FormatHeader32)
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, pl.SeqCount)
		if pl.Run(FormatHeader32) != (i < 2) {
			t.Errorf("datagram %d run = %v", i, pl.Run(FormatHeader32))
		}
	}
	// The first datagram has count 1; same data keeps it; idle bumps it.
	if seqs[0] != 1 || seqs[1] != 1 || seqs[2] != 2 {
		t.Errorf("sequence counts = %v, want [1 1 2]", seqs)
	}
	waitFor(t, "sent count", func() bool { return c.Stats().Sent == 3 })
}

func TestConsumeFiltering(t *testing.T) {
	m := newRecMetrics()
	e := listen(t, WithMetrics(m))
	p := newPeer(t, e.LocalAddr())
	var got dataLog
	c := open(t, e, Config{Class: 1, ConsumedID: 0x55, ConsumeFormat: FormatHeader32, ConsumeSize: 2, OnData: got.onData})

	payload := func(count uint16, header uint32, data ...byte) []byte {
		return AppendPayload(nil, 1, FormatHeader32, Payload{SeqCount: count, Header: header, Data: data})
	}

	p.send(0x55, 10, payload(1, RunBit, 0xAA, 0xBB))
	waitFor(t, "first data", func() bool { return got.n() == 1 })
	if d, run := got.last(); !bytes.Equal(d, []byte{0xAA, 0xBB}) || !run {
		t.Errorf("data % X run %v", d, run)
	}

	// The same encapsulation sequence number again: dropped.
	p.send(0x55, 10, payload(2, RunBit, 1, 2))
	waitFor(t, "old sequence drop", func() bool { return m.drops("old encapsulation sequence") == 1 })

	// An older one too.
	p.send(0x55, 9, payload(3, RunBit, 1, 2))
	waitFor(t, "older sequence drop", func() bool { return m.drops("old encapsulation sequence") == 2 })

	// A newer datagram with the same sequence count: a duplicate.
	p.send(0x55, 11, payload(1, RunBit, 0xAA, 0xBB))
	waitFor(t, "duplicate", func() bool { return c.Stats().Duplicates == 1 })

	// New count, idle.
	p.send(0x55, 12, payload(2, 0, 0xCC, 0xDD))
	waitFor(t, "idle data", func() bool { return got.n() == 2 })
	if d, run := got.last(); !bytes.Equal(d, []byte{0xCC, 0xDD}) || run {
		t.Errorf("data % X run %v", d, run)
	}

	// Wrong size, fixed connection: too long and too short.
	p.send(0x55, 13, payload(3, RunBit, 1, 2, 3))
	p.send(0x55, 14, payload(4, RunBit, 1))
	waitFor(t, "wrong size drops", func() bool { return m.drops("wrong size") == 2 })

	// Shorter than the sequence count and header.
	p.send(0x55, 15, []byte{1, 0, 1})
	waitFor(t, "short payload drop", func() bool { return m.drops("malformed") == 1 })

	// Not an I/O datagram at all.
	p.raw([]byte{0xFF})
	waitFor(t, "malformed drop", func() bool { return m.drops("malformed") == 2 })

	// A connection ID nobody consumes.
	p.send(0x56, 1, payload(1, RunBit, 1, 2))
	waitFor(t, "unknown connection drop", func() bool { return m.drops("unknown connection") == 1 })

	// A sequence count far ahead and wrapping: still newer.
	p.send(0x55, 16, payload(0x8001, RunBit, 0xEE, 0xEE))
	waitFor(t, "data after drops", func() bool { return got.n() == 3 })

	st := c.Stats()
	if st.Received != 4 || st.Duplicates != 1 || st.Dropped != 5 {
		t.Errorf("Stats = %+v, want 4 received, 1 duplicate, 5 dropped", st)
	}
}

func TestConsumeVariableSize(t *testing.T) {
	m := newRecMetrics()
	e := listen(t, WithMetrics(m))
	p := newPeer(t, e.LocalAddr())
	var got dataLog
	open(t, e, Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 4, ConsumeVariable: true, OnData: got.onData})

	p.send(1, 1, []byte{1, 0, 0xAA})
	waitFor(t, "short data", func() bool { return got.n() == 1 })
	p.send(1, 2, []byte{2, 0})
	waitFor(t, "empty data", func() bool { return got.n() == 2 })
	if d, _ := got.last(); len(d) != 0 {
		t.Errorf("data % X", d)
	}
	p.send(1, 3, []byte{3, 0, 1, 2, 3, 4, 5})
	waitFor(t, "too long drop", func() bool { return m.drops("wrong size") == 1 })
	p.send(1, 4, []byte{4, 0, 1, 2, 3, 4})
	waitFor(t, "maximum size", func() bool { return got.n() == 3 })
}

func TestConsumeClass0AndHeartbeat(t *testing.T) {
	e := listen(t)
	p := newPeer(t, e.LocalAddr())

	// Class 0 has no sequence count: every new datagram is new data, even
	// when it repeats.
	var got dataLog
	open(t, e, Config{Class: 0, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1, OnData: got.onData})
	for i := uint32(1); i <= 3; i++ {
		p.send(1, i, []byte{7})
		waitFor(t, "class 0 data", func() bool { return got.n() == int(i) })
	}

	// A heartbeat connection accepts any datagram with its count, and its
	// data is empty whatever the size.
	var hb dataLog
	c := open(t, e, Config{Class: 1, ConsumedID: 2, ConsumeFormat: FormatHeartbeat, ConsumeSize: 0, OnData: hb.onData})
	p.send(2, 1, []byte{1, 0})
	waitFor(t, "heartbeat", func() bool { return hb.n() == 1 })
	if d, run := hb.last(); len(d) != 0 || !run {
		t.Errorf("heartbeat data % X run %v", d, run)
	}
	if c.Stats().Received != 1 {
		t.Errorf("Stats = %+v", c.Stats())
	}
}

func TestWrongSource(t *testing.T) {
	m := newRecMetrics()
	e := listen(t, WithMetrics(m))
	p := newPeer(t, e.LocalAddr())
	var got dataLog
	c := open(t, e, Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Source: netip.MustParseAddr("127.0.0.2"), OnData: got.onData})
	p.send(1, 1, []byte{1, 0, 5})
	waitFor(t, "wrong source drop", func() bool { return m.drops("wrong source") == 1 })
	if got.n() != 0 || c.Stats().Dropped != 1 || c.Stats().Received != 0 {
		t.Errorf("OnData %d, Stats %+v", got.n(), c.Stats())
	}

	// The IPv4-mapped form of the right address is accepted.
	var ok dataLog
	open(t, e, Config{Class: 1, ConsumedID: 2, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Source: netip.MustParseAddr("::ffff:127.0.0.1"), OnData: ok.onData})
	p.send(2, 1, []byte{1, 0, 5})
	waitFor(t, "mapped source", func() bool { return ok.n() == 1 })
}

func TestTimeout(t *testing.T) {
	e := listen(t)
	timedOut := make(chan struct{})
	var calls atomic.Int32
	c := open(t, e, Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1, Timeout: 30 * time.Millisecond,
		OnTimeout: func() { calls.Add(1); close(timedOut) }})
	select {
	case <-timedOut:
	case <-time.After(5 * time.Second):
		t.Fatal("no timeout")
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed")
	}
	if !c.TimedOut() {
		t.Error("TimedOut = false")
	}
	if e.Connections() != 0 {
		t.Errorf("Connections = %d after timeout", e.Connections())
	}
	// Close after a timeout does nothing more.
	c.Close()
	c.Close()
	if calls.Load() != 1 {
		t.Errorf("OnTimeout called %d times", calls.Load())
	}
	// The connection ID is free again.
	open(t, e, Config{ConsumedID: 1})
}

func TestFirstTimeout(t *testing.T) {
	e := listen(t)
	p := newPeer(t, e.LocalAddr())

	// FirstTimeout replaces Timeout before the first datagram.
	start := time.Now()
	c1 := open(t, e, Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Timeout: time.Hour, FirstTimeout: 20 * time.Millisecond})
	select {
	case <-c1.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("FirstTimeout did not fire")
	}
	if !c1.TimedOut() || time.Since(start) > time.Minute {
		t.Error("not timed out by FirstTimeout")
	}

	// After the first datagram the connection uses Timeout.
	var got dataLog
	c2 := open(t, e, Config{Class: 1, ConsumedID: 2, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Timeout: 30 * time.Millisecond, FirstTimeout: time.Hour, OnData: got.onData})
	p.send(2, 1, []byte{1, 0, 5})
	waitFor(t, "data", func() bool { return got.n() == 1 })
	select {
	case <-c2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout did not fire after the first datagram")
	}
	if !c2.TimedOut() {
		t.Error("TimedOut = false")
	}
}

func TestTrafficKeepsAlive(t *testing.T) {
	e := listen(t)
	p := newPeer(t, e.LocalAddr())
	var got dataLog
	c := open(t, e, Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Timeout: 200 * time.Millisecond, OnData: got.onData})
	// Datagrams over about three timeouts, each well within one.
	end := time.Now().Add(600 * time.Millisecond)
	for seq := uint32(1); time.Now().Before(end); seq++ {
		p.send(1, seq, []byte{byte(seq), byte(seq >> 8), 1})
		waitFor(t, "data", func() bool { return got.n() == int(seq) })
		if c.TimedOut() {
			t.Fatal("timed out despite traffic")
		}
		time.Sleep(10 * time.Millisecond) // pacing of the producer, not a wait
	}
	select {
	case <-c.Done():
		t.Fatal("closed despite traffic")
	default:
	}
}

func TestTrigger(t *testing.T) {
	e := listen(t)
	p := newPeer(t, e.LocalAddr())
	var n atomic.Int32
	c := open(t, e, Config{Class: 1, ProducedID: 9, Destination: p.addr(), ProduceRPI: time.Hour, ProduceFormat: FormatModeless, ProduceSize: 1,
		Produce: func() ([]byte, bool) { return []byte{byte(n.Add(1))}, true }})
	// The first datagram is produced at once, the next on Trigger, without
	// waiting for the hour-long RPI.
	for i := 1; i <= 3; i++ {
		if i > 1 {
			c.Trigger()
		}
		m := p.recv()
		pl, err := SplitPayload(m.Payload, 1, FormatModeless)
		if err != nil {
			t.Fatal(err)
		}
		if m.EncapSeq != uint32(i) || pl.SeqCount != uint16(i) || !bytes.Equal(pl.Data, []byte{byte(i)}) {
			t.Errorf("datagram %d: encap %d count %d data % X", i, m.EncapSeq, pl.SeqCount, pl.Data)
		}
	}

	// Trigger on a connection that does not produce does nothing.
	cons := open(t, e, Config{ConsumedID: 4})
	cons.Trigger()
	cons.Trigger()
	cons.Close()
	if cons.Stats().Sent != 0 {
		t.Errorf("consumer sent %d", cons.Stats().Sent)
	}
}

func TestCloseStopsCallbacks(t *testing.T) {
	m := newRecMetrics()
	e := listen(t, WithMetrics(m))
	p := newPeer(t, e.LocalAddr())
	var got dataLog
	var timeouts atomic.Int32
	c, err := e.Open(Config{Class: 1, ConsumedID: 1, ConsumeFormat: FormatModeless, ConsumeSize: 1,
		Timeout: 50 * time.Millisecond, OnData: got.onData, OnTimeout: func() { timeouts.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	p.send(1, 1, []byte{1, 0, 1})
	waitFor(t, "data", func() bool { return got.n() == 1 })
	c.Close()
	c.Close() // idempotent
	select {
	case <-c.Done():
	default:
		t.Fatal("Done not closed by Close")
	}
	if c.TimedOut() || e.Connections() != 0 {
		t.Errorf("TimedOut %v, Connections %d", c.TimedOut(), e.Connections())
	}
	before := got.n()
	// Datagrams after Close reach the endpoint but no connection.
	p.send(1, 2, []byte{2, 0, 2})
	waitFor(t, "unknown connection drop", func() bool { return m.drops("unknown connection") == 1 })
	if got.n() != before {
		t.Errorf("OnData called after Close")
	}
	// Close waits for the connection's goroutine, which owns the
	// watchdog: OnTimeout can no longer run.
	if timeouts.Load() != 0 {
		t.Error("OnTimeout called after Close")
	}
}

func TestOpenErrors(t *testing.T) {
	e := listen(t)
	dst := mustAddrPort("127.0.0.1:2222")
	bad := []Config{
		{Class: 2},
		{Class: 3, ConsumedID: 1},
		{ProducedID: 1, Destination: dst},
		{ProducedID: 1, ProduceRPI: time.Millisecond},
		{ProducedID: 1, ProduceRPI: -time.Millisecond, Destination: dst},
		{ProduceSize: -1},
		{ConsumeSize: -1},
		{ProduceSize: 65001},
		{ConsumeSize: 65001},
	}
	for _, cfg := range bad {
		if _, err := e.Open(cfg); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("Open(%+v) = %v, want ErrInvalidOption", cfg, err)
		}
	}
	if e.Connections() != 0 {
		t.Errorf("Connections = %d", e.Connections())
	}

	c := open(t, e, Config{ConsumedID: 5})
	if _, err := e.Open(Config{ConsumedID: 5}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("ID in use: %v", err)
	}
	c.Close()
	c2 := open(t, e, Config{ConsumedID: 5})
	// Connections that only produce do not take an ID.
	open(t, e, Config{ProducedID: 5, ProduceRPI: time.Hour, Destination: dst})
	open(t, e, Config{ProducedID: 5, ProduceRPI: time.Hour, Destination: dst})
	if e.Connections() != 1 {
		t.Errorf("Connections = %d", e.Connections())
	}
	_ = c2

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Open(Config{ConsumedID: 6}); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Open on closed endpoint: %v", err)
	}
}

func TestEndpointClose(t *testing.T) {
	e, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var timeouts atomic.Int32
	c1, err := e.Open(Config{ConsumedID: 1, Timeout: time.Hour, OnTimeout: func() { timeouts.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.Open(Config{ConsumedID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Connection{c1, c2} {
		select {
		case <-c.Done():
		default:
			t.Error("connection not closed with the endpoint")
		}
	}
	if e.Connections() != 0 || timeouts.Load() != 0 {
		t.Errorf("Connections %d, timeouts %d", e.Connections(), timeouts.Load())
	}
	if err := e.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	c1.Close()
}

func TestListenErrors(t *testing.T) {
	if _, err := Listen("not an address"); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("bad address: %v", err)
	}
	e := listen(t)
	if _, err := Listen(e.LocalAddr().String()); err == nil {
		t.Error("Listen on a port in use succeeded")
	}
}

func TestProduceFailuresAreLogged(t *testing.T) {
	log := &recLogger{}
	m := newRecMetrics()
	e := listen(t, WithLogger(log), WithMetrics(m))

	// Data that does not fit a CPF item is not sent.
	c := open(t, e, Config{ProducedID: 1, Destination: mustAddrPort("127.0.0.1:9"), ProduceRPI: time.Hour,
		Produce: func() ([]byte, bool) { return make([]byte, 70000), true }})
	waitFor(t, "encode warning", func() bool { return log.has("not encoded") })
	if c.Stats().Sent != 0 {
		t.Errorf("Sent = %d", c.Stats().Sent)
	}

	// The limited broadcast address needs SO_BROADCAST: the send fails.
	c2 := open(t, e, Config{ProducedID: 2, Destination: mustAddrPort("255.255.255.255:2222"), ProduceRPI: time.Hour, ProduceSize: 1})
	waitFor(t, "send failure", func() bool { return log.has("send failed") })
	if c2.Stats().Sent != 0 {
		t.Errorf("Sent = %d", c2.Stats().Sent)
	}
	if s, _ := m.counts(); s != 0 {
		t.Errorf("metrics sent = %d", s)
	}
}

func TestWithMetricsIgnoresPlainMetrics(t *testing.T) {
	// A Metrics without the I/O extension is not used (and not called).
	e := listen(t, WithMetrics(ethernetip.NopMetrics{}))
	if e.metrics != nil {
		t.Error("NopMetrics used as IOMetrics")
	}
}

func TestMulticastJoinLeave(t *testing.T) {
	e := listen(t)
	group := netip.MustParseAddr("239.192.13.37")
	c1, err := e.Open(Config{ConsumedID: 1, Group: group})
	if err != nil {
		t.Skipf("multicast not available: %v", err)
	}
	c2, err := e.Open(Config{ConsumedID: 2, Group: group})
	if err != nil {
		t.Fatal(err)
	}
	users := func() int {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.groups[group]
	}
	if users() != 2 {
		t.Errorf("users = %d, want 2", users())
	}
	c1.Close()
	if users() != 1 {
		t.Errorf("users = %d after one close, want 1", users())
	}
	c2.Close()
	if users() != 0 {
		t.Errorf("users = %d after both closed", users())
	}

	// A connection that times out leaves its group too.
	c3, err := e.Open(Config{ConsumedID: 3, Group: group, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	<-c3.Done()
	waitFor(t, "group left after timeout", func() bool { return users() == 0 })

	// Endpoint.Close closes the group sockets of open connections.
	if _, err := e.Open(Config{ConsumedID: 4, Group: group}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if users() != 0 {
		t.Errorf("users = %d after endpoint close", users())
	}
	// Joining on a closed endpoint fails.
	if err := e.join(group, nil); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("join on closed endpoint: %v", err)
	}
}

func TestMulticastJoinFailure(t *testing.T) {
	e := listen(t)
	// A unicast address is not a group: joining fails and the connection
	// ID is released.
	_, err := e.Open(Config{ConsumedID: 1, Group: netip.MustParseAddr("127.0.0.1")})
	if err == nil {
		t.Skip("the system accepted a unicast group")
	}
	if e.Connections() != 0 {
		t.Errorf("Connections = %d after failed join", e.Connections())
	}
	open(t, e, Config{ConsumedID: 1})
}
