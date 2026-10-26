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

	mu      sync.Mutex
	conns   map[uint32][]*Connection // consumers by consumed connection ID
	groups  map[netip.Addr]int       // multicast memberships, counted
	local   netip.Addr               // the default multicast interface address
	mcastIf *net.Interface
	closed  bool

	// faults, when set (by the package's chaos tests), decides the fate of
	// each datagram sent: it returns the datagrams to send now, which may
	// be none (dropped), the datagram twice (duplicated) or older ones
	// (reordered). It is called with the endpoint's send lock held.
	faults func(b []byte) [][]byte
	sendMu sync.Mutex

	wg sync.WaitGroup
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

// WithMulticastInterface sets the interface the endpoint sends multicast
// from and joins groups on, when a connection does not name one
// (Config.Interface). By default an endpoint bound to one address uses
// that address's interface, and one bound to the wildcard address leaves
// the choice to the system (the interface of the default route). Note that
// an endpoint bound to a unicast address does not receive multicast on
// most systems: a consuming endpoint binds the wildcard address.
func WithMulticastInterface(ifi *net.Interface) EndpointOption {
	return func(e *Endpoint) { e.mcastIf = ifi }
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
	e := &Endpoint{conn: c, conns: map[uint32][]*Connection{}, groups: map[netip.Addr]int{}}
	for _, o := range opts {
		o(e)
	}
	// An endpoint bound to one address sends and joins multicast on that
	// address's interface rather than the one of the default route.
	ip := e.LocalAddr().Addr().Unmap()
	if e.mcastIf != nil {
		ip = interfaceAddr(e.mcastIf)
	}
	if ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() {
		if err := multicastInterface(c, ip); err != nil {
			e.log.Warn("multicast interface not set", "addr", ip, "err", err)
		} else {
			e.local = ip
		}
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
	for _, cs := range e.conns {
		conns = append(conns, cs...)
	}
	e.groups = map[netip.Addr]int{}
	e.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	err := e.conn.Close()
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
	cs := append([]*Connection(nil), e.conns[m.ConnID]...)
	e.mu.Unlock()
	if len(cs) == 0 {
		e.drop(from, "unknown connection")
		return
	}
	for _, c := range cs {
		c.consume(from, m)
	}
}

func (e *Endpoint) drop(from netip.AddrPort, reason string) {
	if e.metrics != nil {
		e.metrics.OnIODropped(net.UDPAddrFromAddrPort(from), reason)
	}
}

func (e *Endpoint) send(dst netip.AddrPort, b []byte) error {
	if e.faults == nil {
		_, err := e.conn.WriteToUDPAddrPort(b, dst)
		return err
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	for _, d := range e.faults(b) {
		if _, err := e.conn.WriteToUDPAddrPort(d, dst); err != nil {
			return err
		}
	}
	return nil
}

// join makes the endpoint's socket receive datagrams to a multicast group
// (IP_ADD_MEMBERSHIP on the socket itself, so that the group's datagrams to
// the endpoint's port arrive where the unicast ones do). Joins are counted:
// the group is left when the last connection that joined it closes.
func (e *Endpoint) join(group netip.Addr, ifi *net.Interface) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ethernetip.ErrClosed
	}
	if !group.Is4() || !group.IsMulticast() {
		return fmt.Errorf("%w: %s is not an IPv4 multicast group", ethernetip.ErrInvalidOption, group)
	}
	if e.groups[group] > 0 {
		e.groups[group]++
		return nil
	}
	ifaddr := interfaceAddr(ifi)
	if ifi == nil && e.local.IsValid() {
		ifaddr = e.local
	}
	if err := membership(e.conn, group, ifaddr, true); err != nil {
		return err
	}
	e.groups[group] = 1
	return nil
}

func (e *Endpoint) leave(group netip.Addr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.groups[group] == 0 {
		return
	}
	e.groups[group]--
	if e.groups[group] == 0 {
		delete(e.groups, group)
		if !e.closed {
			_ = membership(e.conn, group, netip.IPv4Unspecified(), false)
		}
	}
}

// interfaceAddr returns the first IPv4 address of ifi, or 0.0.0.0 to let
// the system choose.
func interfaceAddr(ifi *net.Interface) netip.Addr {
	if ifi != nil {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
					return ip.Unmap()
				}
			}
		}
	}
	return netip.IPv4Unspecified()
}

// Connections returns the number of open consuming connections on the
// endpoint.
func (e *Endpoint) Connections() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, cs := range e.conns {
		n += len(cs)
	}
	return n
}
