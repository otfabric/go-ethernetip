// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/logx"
)

// Client is an EtherNet/IP originator of explicit messages: one TCP
// connection and one encapsulation session with a target. Create it with
// [New] or [Dial].
//
// A Client is safe for concurrent use. Unconnected requests of several
// goroutines are sent one after the other, or up to WithMaxPending at a
// time, and their replies are matched by sender context. Connected requests
// of a [Conn] are matched by connection ID and sequence count.
type Client struct {
	addr string
	opts options
	log  *logx.Logger
	rm   ethernetip.RequestMetrics

	// turn admits WithMaxPending unconnected requests at a time.
	turn chan struct{}
	// connMu serialises Connect, so that two requests reconnecting at once
	// dial once.
	connMu sync.Mutex
	ctxSeq atomic.Uint64
	serial atomic.Uint32

	mu      sync.Mutex
	sess    *session
	state   ethernetip.State
	closed  bool
	lastErr error
}

// session is one TCP connection with its registered session handle and the
// reader goroutine that serves it.
type session struct {
	c      *Client
	conn   net.Conn
	handle uint32
	remote net.Addr

	wmu sync.Mutex // serialises writes

	mu      sync.Mutex
	pending map[uint64]chan reply // by sender context
	conns   map[uint32]*Conn      // connected messaging, by both connection IDs
	err     error                 // set when the session ended
	done    chan struct{}

	// closing is set by Client.Close before UnRegisterSession: the target
	// then closes the connection, which is not a lost connection.
	closing atomic.Bool
}

type reply struct {
	pkt encap.Packet
	err error
}

// New returns a client for the target at addr ("host:port"; the port
// defaults to 44818, or 2221 with WithTLS). The client is not connected
// until Connect.
func New(addr string, opts ...Option) (*Client, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := encap.TCPPort
		if o.tls != nil {
			port = encap.SecurePort
		}
		addr = net.JoinHostPort(addr, strconv.Itoa(port))
	}
	if o.origSerial == 0 {
		var b [4]byte
		_, _ = rand.Read(b[:])
		o.origSerial = binary.LittleEndian.Uint32(b[:]) | 1
	}
	c := &Client{
		addr: addr,
		opts: o,
		log:  logx.New(o.logger, "client", "remote", addr),
		turn: make(chan struct{}, o.maxPending),
	}
	c.rm, _ = o.metrics.(ethernetip.RequestMetrics)
	var b [2]byte
	_, _ = rand.Read(b[:])
	c.serial.Store(uint32(binary.LittleEndian.Uint16(b[:])))
	return c, nil
}

// Dial creates a client and connects it: [New] followed by
// [Client.Connect].
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error) {
	c, err := New(addr, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Addr returns the address of the target.
func (c *Client) Addr() string { return c.addr }

// State returns the state of the session.
func (c *Client) State() ethernetip.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Session returns the session handle the target assigned, and 0 when not
// connected.
func (c *Client) Session() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return 0
	}
	return c.sess.handle
}

func (c *Client) setState(s ethernetip.State, err error) {
	c.mu.Lock()
	changed := c.state != s
	c.state = s
	c.mu.Unlock()
	if changed && c.opts.stateChange != nil {
		c.opts.stateChange(s, err)
	}
}

// Connect dials the target and registers a session. It does nothing when
// the client is connected. It fails with an error that matches
// ErrConnectFailed and wraps the cause.
func (c *Client) Connect(ctx context.Context) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ethernetip.ErrClosed
	}
	if c.sess != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	c.setState(ethernetip.StateConnecting, nil)
	s, err := c.dial(ctx)
	if err != nil {
		c.setState(ethernetip.StateDisconnected, err)
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.close(ethernetip.ErrClosed)
		return ethernetip.ErrClosed
	}
	c.sess = s
	c.lastErr = nil
	c.mu.Unlock()
	c.setState(ethernetip.StateConnected, nil)
	c.log.Info("session registered", "session", s.handle)
	go c.readLoop(s)
	return nil
}

func (c *Client) dial(ctx context.Context) (*session, error) {
	ctx, cancel := c.deadline(ctx)
	defer cancel()
	conn, err := c.opts.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrConnectFailed, err)
	}
	if c.opts.tls != nil {
		tc := tls.Client(conn, c.opts.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: TLS handshake: %w", ethernetip.ErrConnectFailed, err)
		}
		conn = tc
	}
	if m := c.opts.metrics; m != nil {
		m.OnConnect(conn.RemoteAddr())
	}
	s := &session{
		c:       c,
		conn:    conn,
		remote:  conn.RemoteAddr(),
		pending: make(map[uint64]chan reply),
		conns:   make(map[uint32]*Conn),
		done:    make(chan struct{}),
	}
	// RegisterSession is answered before the reader runs: read it here,
	// bounded by the context's deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	reg := encap.Packet{Header: encap.Header{Command: encap.CommandRegisterSession},
		Data: encap.Register{ProtocolVersion: encap.ProtocolVersion}.Encode()}
	if err := s.write(reg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: RegisterSession: %w", ethernetip.ErrConnectFailed, err)
	}
	pkt, _, err := encap.ReadPacket(conn, nil, c.opts.maxPacket)
	if err != nil {
		_ = conn.Close()
		// The read deadline is the context's: it may expire before the
		// context reports it.
		var ne net.Error
		if ctx.Err() != nil {
			err = fmt.Errorf("%w: %w", ethernetip.ErrTimeout, ctx.Err())
		} else if errors.As(err, &ne) && ne.Timeout() {
			err = fmt.Errorf("%w: %w", ethernetip.ErrTimeout, err)
		}
		return nil, fmt.Errorf("%w: RegisterSession reply: %w", ethernetip.ErrConnectFailed, err)
	}
	c.onReceived(s.remote, pkt)
	switch {
	case pkt.Command != encap.CommandRegisterSession:
		err = fmt.Errorf("%w: %s in reply to RegisterSession", ethernetip.ErrProtocol, pkt.Command)
	case pkt.Status != encap.StatusSuccess:
		err = &ethernetip.EncapError{Command: pkt.Command, Status: pkt.Status}
	case pkt.Session == 0:
		err = fmt.Errorf("%w: RegisterSession reply without a session handle", ethernetip.ErrProtocol)
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrConnectFailed, err)
	}
	s.handle = pkt.Session
	_ = conn.SetDeadline(time.Time{})
	return s, nil
}

// deadline bounds ctx by the client's timeout.
func (c *Client) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= c.opts.timeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.opts.timeout)
}

func (c *Client) onReceived(remote net.Addr, pkt encap.Packet) {
	if m := c.opts.metrics; m != nil {
		m.OnPacketReceived(remote, pkt.Command, encap.HeaderSize+len(pkt.Data))
	}
}

// Close unregisters the session and closes the connection. Pending
// requests fail with ErrClosed. Close is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	s := c.sess
	c.sess = nil
	c.mu.Unlock()
	if s != nil {
		s.closing.Store(true)
		_, _ = s.writeBy(encap.Packet{Header: encap.Header{Command: encap.CommandUnRegisterSession, Session: s.handle}}, time.Now().Add(time.Second))
		s.close(ethernetip.ErrClosed)
		<-s.done
	}
	c.setState(ethernetip.StateDisconnected, nil)
	return nil
}

// current returns the session, connecting first with auto-reconnect.
func (c *Client) current(ctx context.Context) (*session, error) {
	c.mu.Lock()
	s, closed, err := c.sess, c.closed, c.lastErr
	c.mu.Unlock()
	if closed {
		return nil, ethernetip.ErrClosed
	}
	if s != nil {
		return s, nil
	}
	if !c.opts.reconnect {
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ethernetip.ErrNotConnected, err)
		}
		return nil, ethernetip.ErrNotConnected
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return nil, ethernetip.ErrNotConnected
	}
	return c.sess, nil
}

func (c *Client) readLoop(s *session) {
	var buf []byte
	var err error
	for {
		var pkt encap.Packet
		pkt, buf, err = encap.ReadPacket(s.conn, buf, c.opts.maxPacket)
		if err != nil {
			break
		}
		c.onReceived(s.remote, pkt)
		if pkt.Session != s.handle && pkt.Command != encap.CommandListIdentity &&
			pkt.Command != encap.CommandListServices && pkt.Command != encap.CommandListInterfaces {
			c.log.Warn("packet of another session dropped", "command", pkt.Command, "session", pkt.Session)
			continue
		}
		switch pkt.Command {
		case encap.CommandSendUnitData:
			s.dispatchConnected(pkt)
		case encap.CommandNOP:
		default:
			s.dispatch(pkt)
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = fmt.Errorf("%w: peer closed the connection", ethernetip.ErrConnectionLost)
	} else if errors.Is(err, encap.ErrTooLarge) {
		err = fmt.Errorf("%w: %w", ethernetip.ErrProtocol, err)
	} else {
		err = fmt.Errorf("%w: %w", ethernetip.ErrConnectionLost, err)
	}
	if s.closing.Load() {
		err = ethernetip.ErrClosed
	}
	s.close(err)
	c.mu.Lock()
	ended := c.sess == s
	if ended {
		c.sess = nil
		c.lastErr = s.err
	}
	c.mu.Unlock()
	if ended {
		c.log.Warn("session lost", "error", s.err)
		c.setState(ethernetip.StateDisconnected, s.err)
	}
	if m := c.opts.metrics; m != nil {
		var cause error
		if !errors.Is(s.err, ethernetip.ErrClosed) {
			cause = s.err
		}
		m.OnDisconnect(s.remote, cause)
	}
	close(s.done)
}

// dispatch delivers a reply to the request with its sender context.
func (s *session) dispatch(pkt encap.Packet) {
	id := binary.LittleEndian.Uint64(pkt.Context[:])
	s.mu.Lock()
	ch := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	if ch == nil {
		s.c.log.Debug("reply without a pending request dropped", "command", pkt.Command)
		return
	}
	pkt.Data = append([]byte(nil), pkt.Data...)
	ch <- reply{pkt: pkt}
}

// close ends the session: the connection is closed and every pending
// request fails with err.
func (s *session) close(err error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.err = err
	pending := s.pending
	s.pending = map[uint64]chan reply{}
	conns := s.conns
	s.conns = map[uint32]*Conn{}
	s.mu.Unlock()
	_ = s.conn.Close()
	for _, ch := range pending {
		ch <- reply{err: err}
	}
	seen := map[*Conn]bool{}
	for _, cn := range conns {
		if !seen[cn] {
			seen[cn] = true
			cn.lost(err)
		}
	}
}

// write writes pkt. The write deadline is the client's timeout, never a
// request's deadline: the stream is shared, and a write that cannot
// complete within the timeout means the peer stopped reading, which ends
// the session.
func (s *session) write(pkt encap.Packet) error {
	_, err := s.writeBy(pkt, time.Now().Add(s.c.opts.timeout))
	return err
}

// writeBy writes pkt with the write deadline dl (none when zero), set in
// the same critical section as the write. It returns the number of octets
// written.
func (s *session) writeBy(pkt encap.Packet, dl time.Time) (int, error) {
	b, err := pkt.AppendTo(make([]byte, 0, encap.HeaderSize+len(pkt.Data)))
	if err != nil {
		return 0, err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if !dl.IsZero() {
		_ = s.conn.SetWriteDeadline(dl)
	}
	n, err := s.conn.Write(b)
	if err != nil {
		return n, err
	}
	if m := s.c.opts.metrics; m != nil {
		m.OnPacketSent(s.remote, pkt.Command, len(b))
	}
	return n, nil
}

// roundTrip sends an encapsulation packet with a fresh sender context and
// waits for the reply with that context.
func (c *Client) roundTrip(ctx context.Context, cmd encap.Command, data []byte) (encap.Packet, error) {
	ctx, cancel := c.deadline(ctx)
	defer cancel()
	s, err := c.current(ctx)
	if err != nil {
		return encap.Packet{}, err
	}
	select {
	case c.turn <- struct{}{}:
	case <-ctx.Done():
		return encap.Packet{}, ctxErr(ctx)
	}
	defer func() { <-c.turn }()

	if ctx.Err() != nil {
		// Expired while waiting for a turn: nothing was sent.
		return encap.Packet{}, ctxErr(ctx)
	}
	id := c.ctxSeq.Add(1)
	ch := make(chan reply, 1)
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return encap.Packet{}, err
	}
	s.pending[id] = ch
	s.mu.Unlock()

	h := encap.Header{Command: cmd, Session: s.handle}
	binary.LittleEndian.PutUint64(h.Context[:], id)
	if err := s.write(encap.Packet{Header: h, Data: data}); err != nil {
		s.close(fmt.Errorf("%w: write: %w", ethernetip.ErrConnectionLost, err))
		r := <-ch
		return encap.Packet{}, r.err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return encap.Packet{}, r.err
		}
		if r.pkt.Status != encap.StatusSuccess {
			return r.pkt, &ethernetip.EncapError{Command: r.pkt.Command, Status: r.pkt.Status}
		}
		if r.pkt.Command != cmd {
			return r.pkt, fmt.Errorf("%w: %s in reply to %s", ethernetip.ErrProtocol, r.pkt.Command, cmd)
		}
		return r.pkt, nil
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return encap.Packet{}, ctxErr(ctx)
	}
}

// ctxErr maps the end of a request's context: a deadline is a timeout.
func ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ethernetip.ErrTimeout, ctx.Err())
	}
	return ctx.Err()
}

func (c *Client) nextSerial() uint16 { return uint16(c.serial.Add(1)) }

// RemoteAddr returns the address of the target's end of the session's TCP
// connection, or nil when not connected.
func (c *Client) RemoteAddr() net.Addr { return c.remote() }

// LocalAddr returns the local end of the session's TCP connection, or nil
// when not connected.
func (c *Client) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return nil
	}
	return c.sess.conn.LocalAddr()
}
