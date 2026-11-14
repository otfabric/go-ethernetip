// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/internal/logx"
)

// Server is an EtherNet/IP target (adapter): it accepts sessions on TCP,
// answers ListIdentity and ListServices on UDP, routes explicit requests to
// its objects through the Message Router, and opens Class 0, 1 and 3
// connections for originators through its Connection Manager.
//
// Create it with [New], add assemblies and objects, then call
// [Server.ListenAndServe] (or [Server.Listen] and [Server.Serve]). A Server
// is safe for concurrent use; objects and assemblies can be changed while
// it serves.
type Server struct {
	opts options
	log  *logx.Logger
	sm   ethernetip.ServerMetrics

	jitterState atomic.Uint64 // see jitter

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	objects   map[cip.Class]Object
	symbols   SymbolHandler
	sessions  map[uint32]*session
	conns     map[*session]bool // every TCP connection, registered or not
	tcp       net.Listener
	udp       *net.UDPConn
	io        *implicit.Endpoint
	ownIO     bool
	listening bool
	closed    bool
	wg        sync.WaitGroup

	identity   *identityObject
	assemblies *assemblyObject
	cm         *connectionManager
	tcpip      *StandardObject
	ttl        uint8
	inactivity time.Duration

	// pendingDiscovery counts the delayed UDP replies waiting in timers.
	pendingDiscovery atomic.Int32
	// delayed are the timers of the delayed UDP replies, by a sequence
	// number; under mu. Close stops them.
	delayed    map[uint64]*time.Timer
	delayedSeq uint64
}

// New returns a server with the standard objects: Identity, Message Router,
// Assembly (without instances), Connection Manager, Port, TCP/IP Interface
// and Ethernet Link.
func New(opts ...Option) (*Server, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	s := &Server{
		opts:       o,
		log:        logx.New(o.logger, "server"),
		ctx:        ctx,
		cancel:     cancel,
		objects:    map[cip.Class]Object{},
		sessions:   map[uint32]*session{},
		conns:      map[*session]bool{},
		ttl:        1,
		inactivity: o.inactivity,
	}
	s.sm, _ = o.metrics.(ethernetip.ServerMetrics)
	s.identity = newIdentityObject(s)
	s.assemblies = newAssemblyObject(s)
	s.cm = newConnectionManager(s)
	s.objects[cip.ClassIdentity] = s.identity
	s.objects[cip.ClassMessageRouter] = newMessageRouter(s)
	s.objects[cip.ClassAssembly] = s.assemblies
	s.objects[cip.ClassConnectionManager] = s.cm
	s.objects[cip.ClassPort] = newPortObject(s)
	s.tcpip = newTCPIPObject(s)
	s.objects[cip.ClassTCPIPInterface] = s.tcpip
	s.objects[cip.ClassEthernetLink] = newEthernetLinkObject(s)
	s.jitterState.Store(binary.LittleEndian.Uint64(seed[:]))
	return s, nil
}

// RegisterObject adds an object class, or replaces the one with the same
// class code (the standard objects too).
func (s *Server) RegisterObject(o Object) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[o.Class()] = o
}

// Object returns the object of class c, or nil.
func (s *Server) Object(c cip.Class) Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[c]
}

// Classes returns the class codes of the registered objects, sorted.
func (s *Server) Classes() []cip.Class {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]cip.Class, 0, len(s.objects))
	for c := range s.objects {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// HandleSymbols sets the handler of requests whose path starts with a
// symbol segment; without one they are refused with path destination
// unknown.
func (s *Server) HandleSymbols(h SymbolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.symbols = h
}

// Identity returns the identity the server reports.
func (s *Server) Identity() cip.Identity { return s.identity.get() }

// SetIdentityStatus sets the status word of the Identity object.
func (s *Server) SetIdentityStatus(st cip.IdentityStatus) { s.identity.setStatus(st) }

// ListenAndServe listens on addr for TCP sessions, on the same host and
// port over UDP for ListIdentity and ListServices (44818 by default), and on the I/O address
// (WithIOAddress, default UDP port 2222 of the same host), and serves
// until Close. addr defaults to port 44818 (2221 with WithTLS) when it has
// no port. It returns ethernetip.ErrClosed after Close.
func (s *Server) ListenAndServe(addr string) error {
	if err := s.Listen(addr); err != nil {
		return err
	}
	return s.Serve()
}

// Listen opens the server's sockets without serving them yet: the TCP
// listener on addr, a UDP socket on the same host and port (no error when
// it is taken, as by another server on the same host; ListIdentity is then
// served over TCP only), and the I/O endpoint.
func (s *Server) Listen(addr string) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := encap.TCPPort
		if s.opts.tls != nil {
			port = encap.SecurePort
		}
		addr = net.JoinHostPort(addr, strconv.Itoa(port))
	}
	host, _, _ := net.SplitHostPort(addr)
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	if s.opts.tls != nil {
		l = tls.NewListener(l, s.opts.tls)
	}
	// The UDP socket of the explicit port first, then the I/O endpoint: an
	// I/O endpoint on an ephemeral port could otherwise take the explicit
	// port's number (Windows hands out the same numbers for TCP and UDP),
	// and ListIdentity over UDP would be off for no visible reason.
	_, tcpPort, _ := net.SplitHostPort(l.Addr().String())
	var udp *net.UDPConn
	if ua, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, tcpPort)); err == nil {
		if udp, err = net.ListenUDP("udp4", ua); err != nil {
			s.log.Warn("UDP explicit port not available: ListIdentity over UDP disabled", "error", err)
			udp = nil
		}
	}
	ioAddr := s.opts.ioAddr
	if ioAddr == "" {
		ioAddr = net.JoinHostPort(host, strconv.Itoa(encap.IOPort))
	}
	ep, err := implicit.Listen(ioAddr, implicit.WithLogger(s.opts.logger), implicit.WithMetrics(s.opts.metrics))
	if err != nil {
		_ = l.Close()
		if udp != nil {
			_ = udp.Close()
		}
		return fmt.Errorf("I/O endpoint: %w", err)
	}
	return s.serveOn(l, udp, ep, true)
}

// UseListeners makes the server serve sockets the application opened: a
// TCP (or TLS) listener, an optional UDP socket for ListIdentity, and the
// I/O endpoint, which the server shares with others (it is not closed by
// the server). Call Serve next.
func (s *Server) UseListeners(l net.Listener, udp *net.UDPConn, io *implicit.Endpoint) error {
	if l == nil || io == nil {
		return invalidOption("nil listener or I/O endpoint")
	}
	return s.serveOn(l, udp, io, false)
}

func (s *Server) serveOn(l net.Listener, udp *net.UDPConn, ep *implicit.Endpoint, ownIO bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.listening {
		_ = l.Close()
		if udp != nil {
			_ = udp.Close()
		}
		if ownIO {
			_ = ep.Close()
		}
		if s.closed {
			return ethernetip.ErrClosed
		}
		return invalidOption("server already listening")
	}
	s.tcp, s.udp, s.io, s.ownIO, s.listening = l, udp, ep, ownIO, true
	return nil
}

// Serve serves the sockets opened by Listen or UseListeners until Close,
// and returns ethernetip.ErrClosed.
func (s *Server) Serve() error {
	s.mu.Lock()
	l, udp := s.tcp, s.udp
	if s.closed {
		// Close may already be waiting for the goroutines: none may start.
		s.mu.Unlock()
		return ethernetip.ErrClosed
	}
	if !s.listening {
		s.mu.Unlock()
		return invalidOption("Serve before Listen")
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	if udp != nil {
		s.wg.Add(1)
		go s.serveUDP(udp)
	}
	s.log.Info("serving", "tcp", l.Addr().String(), "io", s.io.LocalAddr().String())
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return ethernetip.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		s.wg.Add(1)
		go s.serveConn(c)
	}
}

// Addr returns the TCP address the server listens on, or nil before
// Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcp == nil {
		return nil
	}
	return s.tcp.Addr()
}

// UDPAddr returns the address of the UDP explicit socket, or nil.
func (s *Server) UDPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

// IOAddr returns the address of the I/O endpoint.
func (s *Server) IOAddr() netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.io == nil {
		return netip.AddrPort{}
	}
	return s.io.LocalAddr()
}

// Close stops the server: listeners close, sessions end, every connection
// is closed. It waits for the server's goroutines to end. Close is
// idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	l, udp, ep, own := s.tcp, s.udp, s.io, s.ownIO
	// Every TCP connection, not only the registered ones: one that never
	// registers would otherwise hold Close until its inactivity timeout.
	sessions := make([]*session, 0, len(s.conns))
	for ss := range s.conns {
		sessions = append(sessions, ss)
	}
	delayed := s.delayed
	s.delayed = nil
	s.mu.Unlock()
	for _, t := range delayed {
		// A timer that already fired is sending its reply; Close waits for
		// it below.
		if t.Stop() {
			s.pendingDiscovery.Add(-1)
			s.wg.Done()
		}
	}
	if l != nil {
		_ = l.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	for _, ss := range sessions {
		ss.close()
	}
	s.cm.closeAll(ethernetip.ErrClosed)
	if ep != nil && own {
		_ = ep.Close()
	}
	s.wg.Wait()
	return nil
}

// maxTCPConns returns the limit of open TCP connections: room for the
// registered sessions, as many connections again that have not registered
// (ListIdentity over TCP, a session being refused or closing) and some
// headroom for small limits.
func (s *Server) maxTCPConns() int {
	n := s.opts.maxSessions
	if n > (math.MaxInt-16)/2 {
		return math.MaxInt
	}
	return 2*n + 16
}

// Sessions returns the number of registered sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Connections returns the open CIP connections.
func (s *Server) Connections() []ethernetip.ConnectionInfo { return s.cm.list() }

// dispatch routes an explicit request through the Message Router.
func (s *Server) dispatch(ctx context.Context, req cip.Request, remote net.Addr, connected bool) cip.Response {
	start := time.Now()
	resp := s.route(ctx, req, remote, connected)
	if resp.Service == 0 {
		// Unconnected_Send answers with the embedded service; everything
		// else with the request's.
		resp.Service = req.Service
	}
	if s.sm != nil {
		s.sm.OnHandled(remote, req.Service, resp.Status, time.Since(start))
	}
	return resp
}

func (s *Server) route(ctx context.Context, req cip.Request, remote net.Addr, connected bool) cip.Response {
	r := &Request{Request: req, Remote: remote, Connected: connected}
	if e := exchangeOf(ctx); e != nil && connected {
		r.MaxReply = e.maxReply
	}
	if req.Path.Symbolic() {
		s.mu.Lock()
		h := s.symbols
		s.mu.Unlock()
		if h == nil {
			return cip.Response{Status: cip.StatusPathDestinationUnknown}
		}
		return h.ServeSymbol(ctx, r)
	}
	var class uint32
	i := 0
	var ok bool
	if class, ok = logicalAt(req.Path, &i, cip.LogicalClass); !ok {
		return cip.Response{Status: cip.StatusPathSegmentError}
	}
	if v, ok := logicalAt(req.Path, &i, cip.LogicalInstance); ok {
		r.Instance = v
	}
	if v, ok := logicalAt(req.Path, &i, cip.LogicalAttribute); ok {
		if v > 0xFFFF {
			return cip.Response{Status: cip.StatusPathSegmentError}
		}
		r.Attribute, r.HasAttribute = uint16(v), true
	}
	if class > math.MaxUint16 {
		// Class codes are 16-bit: a 32-bit class segment beyond them
		// addresses no object (truncated, it would address another one).
		return cip.Response{Status: cip.StatusPathDestinationUnknown}
	}
	r.Rest = req.Path[i:]
	s.mu.Lock()
	o := s.objects[cip.Class(class)]
	s.mu.Unlock()
	if o == nil {
		return cip.Response{Status: cip.StatusPathDestinationUnknown}
	}
	return o.ServeCIP(ctx, r)
}

// logicalAt returns the value of the logical segment of type t at p[*i]
// and advances *i past it.
func logicalAt(p cip.Path, i *int, t cip.LogicalType) (uint32, bool) {
	if *i >= len(p) {
		return 0, false
	}
	l, ok := p[*i].(cip.LogicalSegment)
	if !ok || l.Type != t {
		return 0, false
	}
	*i++
	return l.Value, true
}

// localIP returns the address the server reports for itself.
func (s *Server) localIP(fallback net.Addr) netip.Addr {
	if s.opts.iface.IP.IsValid() {
		return s.opts.iface.IP
	}
	if ta, ok := fallback.(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok && !a.Unmap().IsUnspecified() {
			return a.Unmap()
		}
	}
	if ua, ok := fallback.(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(ua.IP); ok && !a.Unmap().IsUnspecified() {
			return a.Unmap()
		}
	}
	return netip.IPv4Unspecified()
}
