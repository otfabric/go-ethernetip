// SPDX-License-Identifier: MIT

package implicit

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
)

// Config describes one I/O connection as seen from one end. "Produce" is
// the direction this end sends, "consume" the one it receives: for an
// originator O->T and T->O, for a target the reverse.
type Config struct {
	// Class is the transport class, 0 or 1.
	Class uint8

	// ProducedID is the connection ID of the datagrams this end sends;
	// zero when it sends none.
	ProducedID uint32
	// Destination is where the datagrams are sent: the peer's address and
	// I/O port, or a multicast group.
	Destination netip.AddrPort
	// ProduceRPI is the interval of production; required when ProducedID
	// is set.
	ProduceRPI time.Duration
	// ProduceFormat and ProduceSize are the real-time format and the size
	// of the application data produced (without sequence count and
	// header).
	ProduceFormat Format
	ProduceSize   int
	// Produce returns the data to send and whether to send run (true) or
	// idle; it is called at every production. The slice is copied. A nil
	// Produce sends ProduceSize zero octets, run.
	Produce func() (data []byte, run bool)

	// ConsumedID is the connection ID of the datagrams this end receives;
	// zero when it receives none.
	ConsumedID uint32
	// Timeout is the inactivity timeout of consumption: without a valid
	// datagram for this long the connection times out. Zero disables it.
	Timeout time.Duration
	// FirstTimeout, when set, replaces Timeout until the first datagram
	// (some targets need longer to start producing).
	FirstTimeout time.Duration
	// ConsumeFormat and ConsumeSize are the format and the size of the
	// application data consumed; with ConsumeVariable the size is a
	// maximum.
	ConsumeFormat   Format
	ConsumeSize     int
	ConsumeVariable bool
	// Source, when valid, is the only address consumed datagrams are
	// accepted from (the port is not checked: originators send from any
	// port).
	Source netip.Addr
	// Group, when valid, is a multicast group to join for consumption,
	// on interface Interface (nil for the system's choice).
	Group     netip.Addr
	Interface *net.Interface
	// OnData is called with the data of each consumed datagram that
	// carries new data (a newer Class 1 sequence count; every datagram for
	// Class 0), and whether it says run. It runs on the endpoint's
	// receiving goroutine: it must not block. data is only valid during
	// the call.
	OnData func(data []byte, run bool)
	// OnTimeout is called once when consumption times out; the connection
	// stops producing and is closed.
	OnTimeout func()
}

// Stats are counters of a connection.
type Stats struct {
	Sent, Received, Dropped uint64
	// Duplicates are datagrams with an old sequence count: they keep the
	// connection alive but carry no new data.
	Duplicates   uint64
	LastReceived time.Time
	LastSent     time.Time
}

// Connection is one open I/O connection on an [Endpoint].
type Connection struct {
	e   *Endpoint
	cfg Config

	kick    chan struct{} // a datagram was consumed: reset the watchdog
	trigger chan struct{} // produce now
	done    chan struct{}
	wg      sync.WaitGroup

	mu        sync.Mutex
	stats     Stats
	encapSeq  uint32 // last produced
	seqCount  uint16 // last produced
	last      []byte // last produced data
	lastRun   bool   // last produced run/idle
	lastEncap uint32 // last consumed
	lastCount uint16 // last consumed
	consumed  bool   // a datagram was consumed
	closed    bool
	timedOut  bool
}

// Open opens a connection on the endpoint: it registers ConsumedID,
// joins Group, and starts producing every ProduceRPI.
func (e *Endpoint) Open(cfg Config) (*Connection, error) {
	if cfg.Class > 1 {
		return nil, fmt.Errorf("%w: I/O transport class %d", ethernetip.ErrInvalidOption, cfg.Class)
	}
	if cfg.ProducedID != 0 && (cfg.ProduceRPI <= 0 || !cfg.Destination.IsValid()) {
		return nil, fmt.Errorf("%w: production without an interval or destination", ethernetip.ErrInvalidOption)
	}
	if cfg.ProduceSize < 0 || cfg.ConsumeSize < 0 || cfg.ProduceSize > 65000 || cfg.ConsumeSize > 65000 {
		return nil, fmt.Errorf("%w: I/O size", ethernetip.ErrInvalidOption)
	}
	c := &Connection{
		e:       e,
		cfg:     cfg,
		kick:    make(chan struct{}, 1),
		trigger: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	// The sequence count of the first datagram is 1: a consumer that keeps
	// 0 as its starting point (OpENer) takes 0 for an old one.
	c.seqCount = 0
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ethernetip.ErrClosed
	}
	if cfg.ConsumedID != 0 {
		// Several connections may consume one multicast production (an
		// owner and listen-only connections of one scanner); a
		// point-to-point connection ID is the connection's alone.
		for _, o := range e.conns[cfg.ConsumedID] {
			if !cfg.Group.IsValid() || !o.cfg.Group.IsValid() {
				e.mu.Unlock()
				return nil, fmt.Errorf("%w: connection ID 0x%08X in use", ethernetip.ErrInvalidOption, cfg.ConsumedID)
			}
		}
		e.conns[cfg.ConsumedID] = append(e.conns[cfg.ConsumedID], c)
	}
	e.mu.Unlock()
	if cfg.Group.IsValid() {
		if err := e.join(cfg.Group, cfg.Interface); err != nil {
			c.unregister()
			return nil, fmt.Errorf("join %s: %w", cfg.Group, err)
		}
	}
	c.wg.Add(1)
	go c.run()
	return c, nil
}

func (c *Connection) unregister() {
	if c.cfg.ConsumedID == 0 {
		return
	}
	c.e.mu.Lock()
	list := c.e.conns[c.cfg.ConsumedID]
	for i, o := range list {
		if o == c {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(c.e.conns, c.cfg.ConsumedID)
	} else {
		c.e.conns[c.cfg.ConsumedID] = list
	}
	c.e.mu.Unlock()
}

// Close stops the connection: production ends and consumed datagrams are
// no longer accepted. OnTimeout is not called. Close is idempotent.
func (c *Connection) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.unregister()
	close(c.done)
	c.wg.Wait()
	if c.cfg.Group.IsValid() {
		c.e.leave(c.cfg.Group)
	}
}

// Done is closed when the connection is closed or has timed out.
func (c *Connection) Done() <-chan struct{} { return c.done }

// TimedOut reports whether the connection ended by timeout.
func (c *Connection) TimedOut() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timedOut
}

// Stats returns the connection's counters.
func (c *Connection) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Trigger produces a datagram now, in addition to the cyclic ones: a
// change of state or an application trigger.
func (c *Connection) Trigger() {
	select {
	case c.trigger <- struct{}{}:
	default:
	}
}

func (c *Connection) run() {
	defer c.wg.Done()
	var tick <-chan time.Time
	if c.cfg.ProducedID != 0 {
		t := time.NewTicker(c.cfg.ProduceRPI)
		defer t.Stop()
		tick = t.C
		c.produce()
	}
	var watchdog <-chan time.Time
	var timer *time.Timer
	if c.cfg.ConsumedID != 0 && c.cfg.Timeout > 0 {
		first := c.cfg.Timeout
		if c.cfg.FirstTimeout > 0 {
			first = c.cfg.FirstTimeout
		}
		timer = time.NewTimer(first)
		defer timer.Stop()
		watchdog = timer.C
	}
	for {
		select {
		case <-c.done:
			return
		case <-tick:
			c.produce()
		case <-c.trigger:
			if c.cfg.ProducedID != 0 {
				c.produce()
			}
		case <-c.kick:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(c.cfg.Timeout)
			}
		case <-watchdog:
			c.timeout()
			return
		}
	}
}

func (c *Connection) timeout() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed, c.timedOut = true, true
	c.mu.Unlock()
	c.unregister()
	close(c.done)
	if c.cfg.Group.IsValid() {
		c.e.leave(c.cfg.Group)
	}
	if c.cfg.OnTimeout != nil {
		c.cfg.OnTimeout()
	}
}

func (c *Connection) produce() {
	var data []byte
	run := true
	if c.cfg.Produce != nil {
		data, run = c.cfg.Produce()
	} else {
		data = make([]byte, c.cfg.ProduceSize)
	}
	c.mu.Lock()
	c.encapSeq++
	// The sequence count follows new data (and a change of run/idle): a
	// consumer recognises a repeat by its count.
	if c.encapSeq == 1 || run != c.lastRun || !bytes.Equal(data, c.last) {
		c.seqCount++
		c.last = append(c.last[:0], data...)
		c.lastRun = run
	}
	var header uint32
	if run {
		header = RunBit
	}
	m := Message{ConnID: c.cfg.ProducedID, EncapSeq: c.encapSeq,
		Payload: AppendPayload(nil, c.cfg.Class, c.cfg.ProduceFormat, Payload{SeqCount: c.seqCount, Header: header, Data: data})}
	c.mu.Unlock()
	b, err := m.Encode()
	if err != nil {
		c.e.log.Warn("I/O datagram not encoded", "connection", c.cfg.ProducedID, "error", err)
		return
	}
	if err := c.e.send(c.cfg.Destination, b); err != nil {
		c.e.log.Debug("I/O send failed", "connection", c.cfg.ProducedID, "error", err)
		return
	}
	c.mu.Lock()
	c.stats.Sent++
	c.stats.LastSent = time.Now()
	c.mu.Unlock()
	if c.e.metrics != nil {
		c.e.metrics.OnIOSent(c.cfg.ProducedID, len(b))
	}
}

// consume handles a datagram for this connection; it runs on the
// endpoint's receiving goroutine.
func (c *Connection) consume(from netip.AddrPort, m Message) {
	if c.cfg.Source.IsValid() && from.Addr().Unmap() != c.cfg.Source.Unmap() {
		c.dropped(from, "wrong source")
		return
	}
	p, err := SplitPayload(m.Payload, c.cfg.Class, c.cfg.ConsumeFormat)
	if err != nil {
		c.dropped(from, "malformed")
		return
	}
	hasData := c.cfg.ConsumeFormat != FormatHeartbeat && c.cfg.ConsumeFormat != FormatZeroLength
	if hasData && (len(p.Data) > c.cfg.ConsumeSize || (!c.cfg.ConsumeVariable && len(p.Data) != c.cfg.ConsumeSize)) {
		c.dropped(from, "wrong size")
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.consumed && !SeqNewer(m.EncapSeq, c.lastEncap) {
		c.stats.Dropped++
		c.mu.Unlock()
		c.dropped(from, "old encapsulation sequence")
		return
	}
	fresh := !c.consumed || c.cfg.Class == 0 || SeqNewer16(p.SeqCount, c.lastCount)
	c.consumed = true
	c.lastEncap = m.EncapSeq
	c.lastCount = p.SeqCount
	c.stats.Received++
	c.stats.LastReceived = time.Now()
	if !fresh {
		c.stats.Duplicates++
	}
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	if c.e.metrics != nil {
		c.e.metrics.OnIOReceived(m.ConnID, len(m.Payload))
	}
	if fresh && c.cfg.OnData != nil {
		c.cfg.OnData(p.Data, p.Run(c.cfg.ConsumeFormat))
	}
}

func (c *Connection) dropped(from netip.AddrPort, reason string) {
	if reason != "old encapsulation sequence" {
		c.mu.Lock()
		c.stats.Dropped++
		c.mu.Unlock()
	}
	c.e.drop(from, reason)
}
