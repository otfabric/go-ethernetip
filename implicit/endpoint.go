// SPDX-License-Identifier: MIT

package implicit

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/internal/logx"
)

// Endpoint is a UDP socket of I/O messages: it receives datagrams and
// hands each to the [Connection] whose consumed connection ID it carries,
// and sends the datagrams of its connections. Several connections share
// one endpoint. An Endpoint is safe for concurrent use.
type Endpoint struct {
	conn    *net.UDPConn
	log     *logx.Logger
	metrics ethernetip.IOMetrics

	mu     sync.Mutex
	conns  map[uint32]*Connection
	groups map[netip.Addr]*groupSocket
	closed bool

	wg sync.WaitGroup
}

type groupSocket struct {
	conn  *net.UDPConn
	users int
}

// EndpointOption configures an [Endpoint].
type EndpointOption func(*Endpoint)

// WithLogger sets the endpoint's logger.
func WithLogger(l ethernetip.Logger) EndpointOption {
	return func(e *Endpoint) { e.log = logx.New(l, "io") }
}

// WithMetrics sets the endpoint's metrics; only a value that implements
// [ethernetip.IOMetrics] is used.
func WithMetrics(m ethernetip.Metrics) EndpointOption {
	return func(e *Endpoint) { e.metrics, _ = m.(ethernetip.IOMetrics) }
}

// Listen opens an endpoint on a UDP address, "host:2222" or ":0" for any
// port.
func Listen(addr string, opts ...EndpointOption) (*Endpoint, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: I/O address %q: %w", ethernetip.ErrInvalidOption, addr, err)
	}
	c, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, err
	}
	return NewEndpoint(c, opts...), nil
}

// NewEndpoint returns an endpoint serving an open UDP socket. The endpoint
// owns it and closes it on Close.
func NewEndpoint(c *net.UDPConn, opts ...EndpointOption) *Endpoint {
	e := &Endpoint{conn: c, conns: map[uint32]*Connection{}, groups: map[netip.Addr]*groupSocket{}}
	for _, o := range opts {
		o(e)
	}
	e.wg.Add(1)
	go e.receive(c)
	return e
}

// LocalAddr returns the address the endpoint is bound to.
func (e *Endpoint) LocalAddr() netip.AddrPort {
	return e.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Close closes the endpoint and every connection on it.
func (e *Endpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	conns := make([]*Connection, 0, len(e.conns))
	for _, c := range e.conns {
		conns = append(conns, c)
	}
	groups := e.groups
	e.groups = map[netip.Addr]*groupSocket{}
	e.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	err := e.conn.Close()
	for _, g := range groups {
		_ = g.conn.Close()
	}
	e.wg.Wait()
	return err
}

func (e *Endpoint) receive(c *net.UDPConn) {
	defer e.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Errors such as ICMP port unreachable reported on the socket do
			// not end the endpoint.
			e.log.Debug("I/O receive error", "error", err)
			time.Sleep(time.Millisecond)
			continue
		}
		e.handle(from, buf[:n])
	}
}

func (e *Endpoint) handle(from netip.AddrPort, b []byte) {
	m, err := Decode(b)
	if err != nil {
		e.drop(from, "malformed")
		return
	}
	e.mu.Lock()
	c := e.conns[m.ConnID]
	e.mu.Unlock()
	if c == nil {
		e.drop(from, "unknown connection")
		return
	}
	c.consume(from, m)
}

func (e *Endpoint) drop(from netip.AddrPort, reason string) {
	if e.metrics != nil {
		e.metrics.OnIODropped(net.UDPAddrFromAddrPort(from), reason)
	}
}

func (e *Endpoint) send(dst netip.AddrPort, b []byte) error {
	_, err := e.conn.WriteToUDPAddrPort(b, dst)
	return err
}

// join makes the endpoint receive datagrams to a multicast group on the
// endpoint's port. Joins are counted: the group is left when the last
// connection that joined it closes.
func (e *Endpoint) join(group netip.Addr, ifi *net.Interface) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ethernetip.ErrClosed
	}
	if g := e.groups[group]; g != nil {
		g.users++
		return nil
	}
	ua := &net.UDPAddr{IP: group.AsSlice(), Port: int(e.LocalAddr().Port())}
	c, err := net.ListenMulticastUDP("udp4", ifi, ua)
	if err != nil {
		return err
	}
	e.groups[group] = &groupSocket{conn: c, users: 1}
	e.wg.Add(1)
	go e.receive(c)
	return nil
}

func (e *Endpoint) leave(group netip.Addr) {
	e.mu.Lock()
	g := e.groups[group]
	if g != nil {
		g.users--
		if g.users == 0 {
			delete(e.groups, group)
		} else {
			g = nil
		}
	}
	e.mu.Unlock()
	if g != nil {
		_ = g.conn.Close()
	}
}

// Connections returns the number of open connections on the endpoint.
func (e *Endpoint) Connections() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.conns)
}
