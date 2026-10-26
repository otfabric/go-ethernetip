// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

func TestOptionValidation(t *testing.T) {
	long := strings.Repeat("x", 33)
	bad := []struct {
		name string
		opt  Option
	}{
		{"product name", WithIdentity(cip.Identity{ProductName: long})},
		{"nil TLS", WithTLS(nil)},
		{"sessions", WithMaxSessions(0)},
		{"connections", WithMaxConnections(0)},
		{"packet small", WithMaxPacket(511)},
		{"packet large", WithMaxPacket(65536)},
		{"inactivity negative", WithInactivityTimeout(-1)},
		{"inactivity large", WithInactivityTimeout(3601 * time.Second)},
		{"I/O address", WithIOAddress("nohostport")},
		{"slot negative", WithSlot(-1)},
		{"slot large", WithSlot(256)},
		{"interface IPv6", WithInterface(Interface{IP: netip.IPv6Loopback()})},
		{"host name", WithInterface(Interface{HostName: strings.Repeat("h", 65)})},
		{"domain name", WithInterface(Interface{DomainName: strings.Repeat("d", 49)})},
		{"RPI zero", WithRPIRange(0, time.Second)},
		{"RPI inverted", WithRPIRange(time.Second, time.Millisecond)},
		{"discovery negative", WithDiscoveryDelay(-1)},
		{"discovery large", WithDiscoveryDelay(3 * time.Second)},
	}
	for _, tc := range bad {
		if _, err := New(tc.opt); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("%s: New = %v, want ErrInvalidOption", tc.name, err)
		}
	}
	s, err := New(
		WithLogger(ethernetip.NopLogger()), WithMetrics(ethernetip.NopMetrics{}),
		WithTLS(&tls.Config{}), WithMaxSessions(1), WithMaxConnections(1), WithMaxPacket(65535),
		WithInactivityTimeout(0), WithIOAddress(":0"), WithSlot(255),
		WithInterface(Interface{IP: netip.MustParseAddr("10.0.0.1")}),
		WithRPIRange(time.Millisecond, time.Millisecond), WithDiscoveryDelay(2*time.Second),
		WithRunIdleHeader(false, true), WithResetHandler(func(uint8) cip.GeneralStatus { return 0 }),
	)
	if err != nil {
		t.Fatalf("valid options: %v", err)
	}
	if s.sm != nil {
		t.Error("NopMetrics taken for ServerMetrics")
	}
	if ot, to := s.formats(AssemblyOutput); ot != implicit.FormatModeless || to != implicit.FormatHeader32 {
		t.Errorf("formats %v %v", ot, to)
	}
	if ot, _ := s.formats(AssemblyListenOnly); ot != implicit.FormatHeartbeat {
		t.Errorf("listen-only format %v", ot)
	}
	if s.Addr() != nil || s.UDPAddr() != nil || s.IOAddr().IsValid() {
		t.Error("addresses before Listen")
	}
	_ = s.Close()
}

func TestLifecycle(t *testing.T) {
	m := newRecMetrics()
	s, err := New(WithIOAddress("127.0.0.1:0"), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("Serve before Listen = %v", err)
	}
	if err := s.Listen("not an address::"); err == nil {
		t.Error("Listen on a bad address succeeded")
	}
	serve(t, s, "127.0.0.1:0")
	if err := s.Listen("127.0.0.1:0"); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("second Listen = %v", err)
	}
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	if err := s.UseListeners(l, nil, ep); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("UseListeners while listening = %v", err)
	}
	if err := s.UseListeners(nil, nil, ep); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("UseListeners(nil) = %v", err)
	}
	if s.IOAddr().Port() == 0 || s.UDPAddr() == nil {
		t.Errorf("IOAddr %v UDPAddr %v", s.IOAddr(), s.UDPAddr())
	}

	// Close while serving ends sessions and connections.
	p := dialPeer(t, s)
	p.register()
	p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
	p.expectClosed()
	if s.Sessions() != 0 || len(s.Connections()) != 0 {
		t.Errorf("after Close: %d sessions, %d connections", s.Sessions(), len(s.Connections()))
	}
	if !m.with(func(m *recMetrics) bool {
		return len(m.closed) == 1 && (errors.Is(m.closed[0], ethernetip.ErrConnectionLost) || errors.Is(m.closed[0], ethernetip.ErrClosed))
	}) {
		t.Error("connection close not reported")
	}
	if err := s.Listen("127.0.0.1:0"); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Listen after Close = %v", err)
	}
	l2, _ := net.Listen("tcp4", "127.0.0.1:0")
	if err := s.UseListeners(l2, nil, ep); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("UseListeners after Close = %v", err)
	}
	// The listener given to a refused UseListeners is closed.
	if _, err := l2.Accept(); err == nil {
		t.Error("listener not closed")
	}
}

func TestListenAndServe(t *testing.T) {
	var buf safeBuffer
	s, err := New(WithIOAddress("127.0.0.1:0"), WithLogger(ethernetip.NewStdLogger(log.New(&buf, "", 0))))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe("127.0.0.1:0") }()
	waitFor(t, "listening", func() bool { return s.Addr() != nil })
	p := dialPeer(t, s)
	p.register()
	_ = s.Close()
	if err := <-done; !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("ListenAndServe = %v", err)
	}
	if !strings.Contains(buf.String(), "serving") {
		t.Errorf("log lacks the serving entry: %q", buf.String())
	}
	s2, _ := New(WithIOAddress("127.0.0.1:0"))
	if err := s2.ListenAndServe("bad address::"); err == nil {
		t.Error("ListenAndServe on a bad address succeeded")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestListenErrors(t *testing.T) {
	s, _ := New(WithIOAddress("192.0.2.1:0"))
	if err := s.Listen("127.0.0.1:0"); err == nil || !strings.Contains(err.Error(), "I/O endpoint") {
		t.Errorf("Listen with an unusable I/O address = %v", err)
	}
	// The TCP listener was released: the server can listen again.
	s.opts.ioAddr = "127.0.0.1:0"
	serve(t, s, "127.0.0.1:0")

	// UDP port taken: the server serves without UDP.
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	port := u.LocalAddr().(*net.UDPAddr).Port
	s2, _ := New(WithIOAddress("127.0.0.1:0"))
	if err := s2.Listen(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Skipf("TCP port %d not available: %v", port, err)
	}
	defer func() { _ = s2.Close() }()
	if s2.UDPAddr() != nil {
		t.Error("UDP socket despite the port being taken")
	}
}

// TestListenUDPBeforeIO checks that the explicit UDP socket is bound before
// the I/O endpoint: when both want the same port, ListIdentity over UDP
// keeps it (the I/O endpoint used to take it, and ListIdentity over UDP
// went off unnoticed, as when Windows gives an ephemeral I/O port the
// explicit port's number), Listen reports the I/O endpoint, and every
// socket is released.
func TestListenUDPBeforeIO(t *testing.T) {
	// A port free for TCP and UDP.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("UDP port %d not available: %v", port, err)
	}
	_ = u.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	s, _ := New(WithIOAddress(addr))
	err = s.Listen(addr)
	if err == nil {
		defer func() { _ = s.Close() }()
		t.Fatalf("Listen succeeded with UDPAddr %v: the I/O endpoint took the explicit UDP port", s.UDPAddr())
	}
	if !strings.Contains(err.Error(), "I/O endpoint") {
		t.Fatalf("Listen = %v, want the I/O endpoint's error", err)
	}
	// Both sockets were released.
	if l, err := net.Listen("tcp4", addr); err != nil {
		t.Errorf("TCP port not released: %v", err)
	} else {
		_ = l.Close()
	}
	if u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Errorf("UDP port not released: %v", err)
	} else {
		_ = u.Close()
	}
}

func TestListenDefaultPort(t *testing.T) {
	s, _ := New(WithIOAddress("127.0.0.1:0"), WithTLS(&tls.Config{}))
	if err := s.Listen("127.0.0.1"); err != nil {
		t.Skipf("port %d not available: %v", encap.SecurePort, err)
	}
	defer func() { _ = s.Close() }()
	if got := s.Addr().(*net.TCPAddr).Port; got != encap.SecurePort {
		t.Errorf("TLS default port %d", got)
	}
}

// flakyListener fails Accept with a timeout a few times, then with a
// permanent error once closed.
type flakyListener struct {
	net.Listener
	mu       sync.Mutex
	timeouts int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.timeouts > 0 {
		l.timeouts--
		l.mu.Unlock()
		return nil, timeoutError{}
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "accept timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestServeAcceptErrors(t *testing.T) {
	s, _ := New()
	inner, _ := net.Listen("tcp4", "127.0.0.1:0")
	l := &flakyListener{Listener: inner, timeouts: 3}
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	if err := s.UseListeners(l, nil, ep); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	// Accept timeouts are retried: a session is served after them.
	p := dialPeer(t, s)
	p.register()
	// A permanent Accept error ends Serve with it.
	_ = inner.Close()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, ethernetip.ErrClosed) {
			t.Errorf("Serve = %v, want the accept error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	_ = s.Close()
	// The shared endpoint is not closed by the server.
	if _, err := ep.Open(implicit.Config{Class: 1, ConsumedID: 1, ConsumeSize: 1, Timeout: time.Second}); err != nil {
		t.Errorf("shared endpoint closed by the server: %v", err)
	}
}

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLS(t *testing.T) {
	m := newRecMetrics()
	cert := selfSigned(t)
	s := startServer(t, WithTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), WithMetrics(m))
	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)
	c, err := tls.Dial("tcp4", s.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p := &peer{t: t, c: c}
	p.register()
	if r := p.get(cip.ClassIdentity, 1, 7); !r.OK() || !strings.Contains(string(r.Data), DefaultIdentity.ProductName) {
		t.Errorf("product name over TLS: %s %q", r.Status, r.Data)
	}
	// A peer that does not speak TLS fails the handshake and is dropped.
	plain := dialPeer(t, s)
	plain.write(bytes.Repeat([]byte{0x65}, 64))
	plain.expectClosed()
	waitFor(t, "handshake failure reported", func() bool {
		return m.with(func(m *recMetrics) bool {
			for _, err := range m.discs {
				if err != nil {
					return true
				}
			}
			return false
		})
	})
	// A clean UnRegisterSession is reported without an error.
	p.send(encap.CommandUnRegisterSession, p.handle, nil)
	waitFor(t, "clean disconnect", func() bool {
		return m.with(func(m *recMetrics) bool {
			n := 0
			for _, err := range m.discs {
				if err == nil {
					n++
				}
			}
			return n == 1
		})
	})
}

func TestReplyWriteFailure(t *testing.T) {
	s, _ := New()
	c := &failConn{}
	ss := &session{s: s, conn: c, remote: &net.TCPAddr{}}
	// A reply too large to encode is not written.
	ss.reply(encap.Header{Command: encap.CommandNOP}, encap.StatusSuccess, make([]byte, encap.MaxData+1))
	if c.writes != 0 || c.closed {
		t.Errorf("oversize reply: %d writes, closed %v", c.writes, c.closed)
	}
	// A reply that cannot be written closes the connection.
	ss.reply(encap.Header{Command: encap.CommandNOP}, encap.StatusSuccess, nil)
	if c.writes != 1 || !c.closed {
		t.Errorf("failed write: %d writes, closed %v", c.writes, c.closed)
	}
}

// failConn fails every write and records Close.
type failConn struct {
	net.Conn
	writes int
	closed bool
}

func (c *failConn) Write([]byte) (int, error)        { c.writes++; return 0, net.ErrClosed }
func (c *failConn) SetWriteDeadline(time.Time) error { return nil }
func (c *failConn) Close() error                     { c.closed = true; return nil }

// TestServeAfterClose: Serve on a closed server returns ErrClosed without
// starting anything (Close may be waiting for its goroutines).
func TestServeAfterClose(t *testing.T) {
	s, _ := New(WithIOAddress("127.0.0.1:0"))
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := s.Serve(); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("Serve after Close = %v", err)
	}
}
