// SPDX-License-Identifier: MIT

// Package scanner is the originator (scanner) of EtherNet/IP implicit I/O
// connections: it opens Class 1 (or Class 0) connections to a target's
// assemblies with Forward_Open over a client session, exchanges their data
// cyclically over UDP, detects their timeout and, when asked to, reopens
// them.
//
//	c, _ := client.Dial(ctx, "192.168.1.10")
//	s, _ := scanner.New(c)
//	io, _ := s.Open(ctx, scanner.IOConfig{
//		ConfigInstance: 151, OutputInstance: 150, InputInstance: 100,
//		OutputSize: 32, InputSize: 32, RPI: 10 * time.Millisecond,
//	})
//	io.SetOutput(out)
//	in, run, at := io.Input()
//
// The scanner's I/O endpoint listens on UDP port 2222 by default, the port
// targets send to; WithLocalAddr picks another, which Forward_Open then
// announces in a Sockaddr Info item (not every target honours it).
package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/internal/logx"
)

// Scanner opens I/O connections to the target of a client. It is safe for
// concurrent use.
type Scanner struct {
	c     *client.Client
	ep    *implicit.Endpoint
	ownEP bool
	log   *logx.Logger

	mu     sync.Mutex
	ios    map[*IO]bool
	closed bool
}

// Option configures a [Scanner].
type Option func(*options) error

type options struct {
	ep     *implicit.Endpoint
	local  string
	logger ethernetip.Logger
}

// WithEndpoint makes the scanner use an I/O endpoint it does not own, for
// example one shared by the scanners of several targets.
func WithEndpoint(ep *implicit.Endpoint) Option {
	return func(o *options) error {
		if ep == nil {
			return fmt.Errorf("%w: nil endpoint", ethernetip.ErrInvalidOption)
		}
		o.ep = ep
		return nil
	}
}

// WithLocalAddr sets the UDP address of the scanner's own endpoint;
// default ":2222".
func WithLocalAddr(addr string) Option {
	return func(o *options) error { o.local = addr; return nil }
}

// WithLogger sets the logger.
func WithLogger(l ethernetip.Logger) Option {
	return func(o *options) error { o.logger = l; return nil }
}

// New returns a scanner of the target of c. Unless WithEndpoint is given,
// it opens its own I/O endpoint, which Close closes.
func New(c *client.Client, opts ...Option) (*Scanner, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ethernetip.ErrInvalidOption)
	}
	o := options{local: fmt.Sprintf(":%d", encap.IOPort)}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	s := &Scanner{c: c, ep: o.ep, log: logx.New(o.logger, "scanner", "remote", c.Addr()), ios: map[*IO]bool{}}
	if s.ep == nil {
		ep, err := implicit.Listen(o.local, implicit.WithLogger(o.logger))
		if err != nil {
			return nil, fmt.Errorf("I/O endpoint: %w", err)
		}
		s.ep, s.ownEP = ep, true
	}
	return s, nil
}

// Endpoint returns the scanner's I/O endpoint.
func (s *Scanner) Endpoint() *implicit.Endpoint { return s.ep }

// Close closes every connection of the scanner (with Forward_Close, within
// ctx) and its own endpoint.
func (s *Scanner) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ios := make([]*IO, 0, len(s.ios))
	for io := range s.ios {
		ios = append(ios, io)
	}
	s.mu.Unlock()
	for _, io := range ios {
		_ = io.Close(ctx)
	}
	if s.ownEP {
		return s.ep.Close()
	}
	return nil
}

// Reconnect configures the reopening of a connection that timed out or
// whose Forward_Open failed transiently.
type Reconnect struct {
	// MinDelay is the delay before the first attempt; it doubles after
	// each failure. Zero means 100 ms.
	MinDelay time.Duration
	// MaxDelay caps the delay. Zero means 10 seconds.
	MaxDelay time.Duration
}

// IOConfig describes an I/O connection.
type IOConfig struct {
	// ConfigInstance is the configuration assembly; 0 leaves it out of the
	// path. ConfigData, when set, is sent in the connection path.
	ConfigInstance uint32
	ConfigData     []byte
	// OutputInstance is the O->T connection point (the target's output or
	// heartbeat assembly); InputInstance the T->O point (its input
	// assembly).
	OutputInstance uint32
	InputInstance  uint32
	// OutputSize and InputSize are the sizes of the application data,
	// without sequence count and header.
	OutputSize int
	InputSize  int
	// RPI is the requested packet interval of both directions; OTRPI and
	// TORPI, when set, replace it per direction.
	RPI   time.Duration
	OTRPI time.Duration
	TORPI time.Duration
	// OutputFormat is the O->T real-time format: the zero value means the
	// 32-bit run/idle header, or heartbeat when OutputSize is 0.
	// InputFormat is the T->O format: the zero value is modeless.
	OutputFormat *implicit.Format
	InputFormat  implicit.Format
	// Class is the transport class, 1 (the zero value) or 0 (set
	// ClassZero).
	ClassZero bool
	// Multicast asks for the T->O data by multicast.
	Multicast bool
	// TimeoutMultiplier: the connections time out after RPI × 4 << n.
	// Default 0 (×4); at most 7.
	TimeoutMultiplier uint8
	// Large uses Large_Forward_Open; it is chosen automatically when a
	// connection size exceeds 511.
	Large bool
	// Key is the electronic key to put in the path; nil sends none.
	Key *cip.KeySegment
	// Reconnect, when set, reopens the connection after a timeout.
	Reconnect *Reconnect
	// Output is the output data sent from the first datagram on, OutputSize
	// octets; nil sends zeros until SetOutput. Idle starts the connection
	// in idle (FormatHeader32 only), so that a device does not act on
	// outputs before the application sets them and calls SetRun(true).
	Output []byte
	Idle   bool
	// OnInput is called with each new input (T->O) data and its run
	// state, on the endpoint's goroutine: it must not block. data is only
	// valid during the call.
	OnInput func(data []byte, run bool)
	// OnState is called when the connection's state changes.
	OnState func(ethernetip.State, error)
}

func (c IOConfig) class() uint8 {
	if c.ClassZero {
		return 0
	}
	return 1
}

func (c IOConfig) outputFormat() implicit.Format {
	if c.OutputFormat != nil {
		return *c.OutputFormat
	}
	if c.OutputSize == 0 {
		return implicit.FormatHeartbeat
	}
	return implicit.FormatHeader32
}

func (c IOConfig) rpis() (ot, to time.Duration) {
	ot, to = c.RPI, c.RPI
	if c.OTRPI > 0 {
		ot = c.OTRPI
	}
	if c.TORPI > 0 {
		to = c.TORPI
	}
	return ot, to
}

func (c IOConfig) path() (cip.Path, error) {
	var p cip.Path
	if c.Key != nil {
		p = append(p, *c.Key)
	}
	p = append(p, cip.ClassSegment(cip.ClassAssembly))
	if c.ConfigInstance != 0 {
		p = append(p, cip.InstanceSegment(c.ConfigInstance))
	}
	p = append(p, cip.ConnectionPointSegment(c.OutputInstance), cip.ConnectionPointSegment(c.InputInstance))
	if len(c.ConfigData) > 0 {
		if len(c.ConfigData)%2 != 0 {
			return nil, fmt.Errorf("%w: configuration data of %d octets (must be even)", ethernetip.ErrInvalidOption, len(c.ConfigData))
		}
		p = append(p, cip.DataSegment{Data: c.ConfigData})
	}
	return p, nil
}

// maxRPI is the largest RPI Forward_Open carries: 2^32-1 microseconds.
const maxRPI = time.Duration(1<<32-1) * time.Microsecond

func (c IOConfig) validate() error {
	ot, to := c.rpis()
	switch {
	case c.OutputInstance == 0 || c.InputInstance == 0:
		return fmt.Errorf("%w: output and input instances are required", ethernetip.ErrInvalidOption)
	case ot <= 0 || to <= 0:
		return fmt.Errorf("%w: RPI is required", ethernetip.ErrInvalidOption)
	case ot > maxRPI || to > maxRPI:
		return fmt.Errorf("%w: RPI above %v", ethernetip.ErrInvalidOption, maxRPI)
	case c.OutputSize < 0 || c.InputSize < 0 || c.OutputSize > 65000 || c.InputSize > 65000:
		return fmt.Errorf("%w: I/O sizes", ethernetip.ErrInvalidOption)
	case c.Output != nil && len(c.Output) != c.OutputSize:
		return fmt.Errorf("%w: %d octets of initial output for size %d", ethernetip.ErrInvalidOption, len(c.Output), c.OutputSize)
	case c.TimeoutMultiplier > 7:
		return fmt.Errorf("%w: timeout multiplier %d", ethernetip.ErrInvalidOption, c.TimeoutMultiplier)
	}
	return nil
}

// IO is an open I/O connection. It is safe for concurrent use.
type IO struct {
	s   *Scanner
	cfg IOConfig

	mu       sync.Mutex
	conn     *implicit.Connection
	info     ethernetip.ConnectionInfo
	state    ethernetip.State
	err      error
	out      []byte
	run      bool
	in       []byte
	inRun    bool
	inAt     time.Time
	closed   bool
	done     chan struct{}
	stopping chan struct{}
	wg       sync.WaitGroup
}

// Open opens an I/O connection with Forward_Open and starts exchanging
// data: the output is OutputSize zero octets with run until SetOutput.
func (s *Scanner) Open(ctx context.Context, cfg IOConfig) (*IO, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	io := &IO{s: s, cfg: cfg, out: make([]byte, cfg.OutputSize), run: !cfg.Idle, done: make(chan struct{}), stopping: make(chan struct{})}
	copy(io.out, cfg.Output)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ethernetip.ErrClosed
	}
	s.mu.Unlock()
	io.setState(ethernetip.StateConnecting, nil)
	if err := io.open(ctx); err != nil {
		io.setState(ethernetip.StateDisconnected, err)
		return nil, err
	}
	s.mu.Lock()
	s.ios[io] = true
	s.mu.Unlock()
	return io, nil
}

func (io *IO) setState(st ethernetip.State, err error) {
	io.mu.Lock()
	changed := io.state != st
	io.state, io.err = st, err
	f := io.cfg.OnState
	io.mu.Unlock()
	if changed && f != nil {
		f(st, err)
	}
}

// open sends the Forward_Open and starts the implicit connection.
func (io *IO) open(ctx context.Context) error {
	cfg := io.cfg
	class := cfg.class()
	otFmt, toFmt := cfg.outputFormat(), cfg.InputFormat
	otRPI, toRPI := cfg.rpis()
	otSize := cfg.OutputSize + otFmt.Overhead(class)
	toSize := cfg.InputSize + toFmt.Overhead(class)
	if otFmt == implicit.FormatHeartbeat || otFmt == implicit.FormatZeroLength {
		otSize = otFmt.Overhead(class)
	}
	large := cfg.Large || otSize > 0x1FF || toSize > 0x1FF
	path, err := cfg.path()
	if err != nil {
		return err
	}
	toType := cip.ConnectionPointToPoint
	if cfg.Multicast {
		toType = cip.ConnectionMulticast
	}
	c := io.s.c
	if err := c.Connect(ctx); err != nil {
		return err
	}
	toID := client.NewConnectionID()
	fo := cip.ForwardOpen{
		Large:             large,
		TOConnID:          toID,
		Triad:             c.NewTriad(),
		TimeoutMultiplier: cfg.TimeoutMultiplier,
		OTRPI:             uint32(otRPI / time.Microsecond),
		OTParams:          cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: uint16(otSize)},
		TORPI:             uint32(toRPI / time.Microsecond),
		TOParams:          cip.NetworkParams{Type: toType, Priority: cip.PriorityScheduled, Size: uint16(toSize)},
		Transport:         cip.NewTransportTrigger(class, cip.TriggerCyclic, false),
		Path:              path,
	}
	ep := io.s.ep
	var items []encap.Item
	local := ep.LocalAddr()
	if local.Port() != encap.IOPort {
		items = append(items, encap.Item{Type: encap.ItemSockaddrTO,
			Data: encap.SockaddrOf(netip.AddrPortFrom(netip.IPv4Unspecified(), local.Port())).Encode()})
	}
	reply, rItems, err := c.ForwardOpen(ctx, fo, items...)
	if err != nil {
		return err
	}
	target := targetIP(c.RemoteAddr())
	dst := netip.AddrPortFrom(target, encap.IOPort)
	var group netip.Addr
	for _, it := range rItems {
		sa, derr := encap.DecodeSockaddr(it.Data)
		if derr != nil {
			continue
		}
		switch it.Type {
		case encap.ItemSockaddrOT:
			if sa.Port != 0 {
				dst = netip.AddrPortFrom(dst.Addr(), sa.Port)
			}
			if a := netip.AddrFrom4(sa.Addr); !a.IsUnspecified() {
				dst = netip.AddrPortFrom(a, dst.Port())
			}
		case encap.ItemSockaddrTO:
			if a := netip.AddrFrom4(sa.Addr); a.IsMulticast() {
				group = a
			}
		default:
			// Other items carry nothing for the I/O connection.
		}
	}
	if cfg.Multicast && !group.IsValid() {
		_ = c.ForwardClose(ctx, cip.ForwardClose{Triad: fo.Triad, Path: path})
		return fmt.Errorf("%w: multicast connection without a T->O multicast address", ethernetip.ErrProtocol)
	}
	timeout := cip.ConnectionTimeout(time.Duration(reply.TOAPI)*time.Microsecond, cfg.TimeoutMultiplier)
	conn, err := ep.Open(implicit.Config{
		Class:         class,
		ProducedID:    reply.OTConnID,
		Destination:   dst,
		ProduceRPI:    time.Duration(reply.OTAPI) * time.Microsecond,
		ProduceFormat: otFmt,
		ProduceSize:   cfg.OutputSize,
		Produce:       io.output,
		ConsumedID:    reply.TOConnID,
		Timeout:       timeout,
		ConsumeFormat: toFmt,
		ConsumeSize:   cfg.InputSize,
		Source:        target,
		Group:         group,
		OnData:        io.input,
		OnTimeout:     io.timedOut,
	})
	if err != nil {
		_ = c.ForwardClose(ctx, cip.ForwardClose{Triad: fo.Triad, Path: path})
		return err
	}
	io.mu.Lock()
	io.conn = conn
	io.info = ethernetip.ConnectionInfo{
		Class: class, OTConnID: reply.OTConnID, TOConnID: reply.TOConnID,
		Serial: fo.Serial, VendorID: fo.VendorID, OriginatorSerial: fo.OriginatorSerial,
		OTRPI: time.Duration(reply.OTAPI) * time.Microsecond, TORPI: time.Duration(reply.TOAPI) * time.Microsecond,
		Path: path,
	}
	io.mu.Unlock()
	io.setState(ethernetip.StateConnected, nil)
	io.s.log.Info("I/O connection opened", "ot", reply.OTConnID, "to", reply.TOConnID, "rpi", otRPI)
	return nil
}

func targetIP(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func (io *IO) output() ([]byte, bool) {
	io.mu.Lock()
	defer io.mu.Unlock()
	return append([]byte(nil), io.out...), io.run
}

func (io *IO) input(data []byte, run bool) {
	io.mu.Lock()
	io.in = append(io.in[:0], data...)
	io.inRun, io.inAt = run, time.Now()
	f := io.cfg.OnInput
	io.mu.Unlock()
	if f != nil {
		f(data, run)
	}
}

func (io *IO) timedOut() {
	err := fmt.Errorf("%w: no input for the connection timeout", ethernetip.ErrTimeout)
	io.s.log.Warn("I/O connection timed out")
	io.mu.Lock()
	if io.closed {
		io.mu.Unlock()
		return
	}
	reconnect := io.cfg.Reconnect != nil
	if reconnect {
		// Added under the lock that Close takes before it waits.
		io.wg.Add(1)
	}
	io.mu.Unlock()
	io.setState(ethernetip.StateTimedOut, err)
	if !reconnect {
		io.finish(err)
		return
	}
	go io.reopen()
}

// reopen retries Forward_Open with backoff until it succeeds or the
// connection is closed.
func (io *IO) reopen() {
	defer io.wg.Done()
	d, maxD := io.cfg.Reconnect.MinDelay, io.cfg.Reconnect.MaxDelay
	if d <= 0 {
		d = 100 * time.Millisecond
	}
	if maxD <= 0 {
		maxD = 10 * time.Second
	}
	for {
		select {
		case <-io.stopping:
			return
		case <-time.After(d):
		}
		// The target may still hold the timed-out connection: close it
		// first, ignoring the outcome.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		io.mu.Lock()
		old := io.info
		io.mu.Unlock()
		_ = io.s.c.ForwardClose(ctx, cip.ForwardClose{Triad: cip.Triad{Serial: old.Serial, VendorID: old.VendorID, OriginatorSerial: old.OriginatorSerial}, Path: old.Path})
		io.setState(ethernetip.StateConnecting, nil)
		err := io.open(ctx)
		cancel()
		if err == nil {
			return
		}
		io.s.log.Warn("I/O reconnect failed", "error", err)
		io.setState(ethernetip.StateTimedOut, err)
		d = min(2*d, maxD)
	}
}

func (io *IO) finish(err error) {
	io.mu.Lock()
	if io.closed {
		io.mu.Unlock()
		return
	}
	io.closed = true
	io.err = err
	close(io.stopping)
	io.mu.Unlock()
	close(io.done)
	io.s.mu.Lock()
	delete(io.s.ios, io)
	io.s.mu.Unlock()
}

// SetOutput sets the output (O->T) data, sent from the next interval on.
// It must be exactly OutputSize octets.
func (io *IO) SetOutput(data []byte) error {
	if len(data) != io.cfg.OutputSize {
		return fmt.Errorf("%w: %d octets of output, the connection has %d", ethernetip.ErrInvalidOption, len(data), io.cfg.OutputSize)
	}
	io.mu.Lock()
	copy(io.out, data)
	io.mu.Unlock()
	return nil
}

// SetRun sets the run/idle state the output carries (formats with the
// 32-bit header). New connections start in run.
func (io *IO) SetRun(run bool) {
	io.mu.Lock()
	io.run = run
	io.mu.Unlock()
}

// Input returns a copy of the last input (T->O) data, whether it said run,
// and when it arrived; zero time before the first.
func (io *IO) Input() ([]byte, bool, time.Time) {
	io.mu.Lock()
	defer io.mu.Unlock()
	return append([]byte(nil), io.in...), io.inRun, io.inAt
}

// State returns the connection's state.
func (io *IO) State() ethernetip.State {
	io.mu.Lock()
	defer io.mu.Unlock()
	return io.state
}

// Err returns why the connection ended or last failed, or nil.
func (io *IO) Err() error {
	io.mu.Lock()
	defer io.mu.Unlock()
	return io.err
}

// Done is closed when the connection ends: by Close, or by a timeout
// without Reconnect.
func (io *IO) Done() <-chan struct{} { return io.done }

// Info returns the connection's IDs, triad and actual intervals.
func (io *IO) Info() ethernetip.ConnectionInfo {
	io.mu.Lock()
	defer io.mu.Unlock()
	return io.info
}

// Stats returns the counters of the current implicit connection.
func (io *IO) Stats() implicit.Stats {
	io.mu.Lock()
	c := io.conn
	io.mu.Unlock()
	if c == nil {
		return implicit.Stats{}
	}
	return c.Stats()
}

// Close stops the exchange and closes the connection with Forward_Close
// (bounded by ctx). Close is idempotent.
func (io *IO) Close(ctx context.Context) error {
	io.mu.Lock()
	if io.closed {
		io.mu.Unlock()
		return nil
	}
	io.mu.Unlock()
	io.finish(ethernetip.ErrClosed)
	// A reopen in progress ends first; what it opened is closed below.
	io.wg.Wait()
	io.mu.Lock()
	c, info, state := io.conn, io.info, io.state
	io.mu.Unlock()
	if c != nil {
		c.Close()
	}
	io.setState(ethernetip.StateDisconnected, nil)
	if state != ethernetip.StateConnected {
		return nil
	}
	return io.s.c.ForwardClose(ctx, cip.ForwardClose{
		Triad: cip.Triad{Serial: info.Serial, VendorID: info.VendorID, OriginatorSerial: info.OriginatorSerial},
		Path:  info.Path,
	})
}
