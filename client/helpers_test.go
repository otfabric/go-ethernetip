// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/server"
)

// ctxT returns a context bounded for a test.
func ctxT(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// eventually polls cond until it holds or d elapses.
func eventually(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// startServer starts a real server on loopback and returns it with its
// TCP address.
func startServer(t testing.TB, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(append([]server.Option{server.WithIOAddress("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-done:
			_ = err // ErrClosed after Close
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return srv, srv.Addr().String()
}

func dialT(t testing.TB, addr string, opts ...Option) *Client {
	t.Helper()
	c, err := Dial(ctxT(t), addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// peer is one TCP connection of a fakeTarget.
type peer struct {
	conn net.Conn
	wmu  sync.Mutex
}

func (p *peer) send(t testing.TB, pkt encap.Packet) {
	b, err := pkt.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	p.sendRaw(b)
}

func (p *peer) sendRaw(b []byte) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, _ = p.conn.Write(b)
}

// fakeSession is the session handle a fakeTarget assigns.
const fakeSession = 0x11223344

// fakeTarget is a hand-written EtherNet/IP target: it registers sessions
// (unless register is false) and passes every other packet to handle.
type fakeTarget struct {
	t        testing.TB
	ln       net.Listener
	register bool
	handle   func(p *peer, pkt encap.Packet)

	mu    sync.Mutex
	peers []*peer
	wg    sync.WaitGroup
}

func newFakeTarget(t testing.TB, handle func(p *peer, pkt encap.Packet)) *fakeTarget {
	t.Helper()
	return startFake(t, true, handle)
}

// newRawTarget is a fakeTarget that passes RegisterSession to handle too.
func newRawTarget(t testing.TB, handle func(p *peer, pkt encap.Packet)) *fakeTarget {
	t.Helper()
	return startFake(t, false, handle)
}

func startFake(t testing.TB, register bool, handle func(p *peer, pkt encap.Packet)) *fakeTarget {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTarget{t: t, ln: ln, register: register, handle: handle}
	f.wg.Add(1)
	go f.accept()
	t.Cleanup(f.close)
	return f
}

func (f *fakeTarget) addr() string { return f.ln.Addr().String() }

func (f *fakeTarget) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	for _, p := range f.peers {
		_ = p.conn.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *fakeTarget) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		p := &peer{conn: c}
		f.mu.Lock()
		f.peers = append(f.peers, p)
		f.mu.Unlock()
		f.wg.Add(1)
		go f.serve(p)
	}
}

func (f *fakeTarget) serve(p *peer) {
	defer f.wg.Done()
	defer func() { _ = p.conn.Close() }()
	var buf []byte
	for {
		pkt, nb, err := encap.ReadPacket(p.conn, buf, 0)
		buf = nb
		if err != nil {
			return
		}
		pkt.Data = append([]byte(nil), pkt.Data...)
		if pkt.Command == encap.CommandRegisterSession && f.register {
			h := pkt.Header
			h.Session = fakeSession
			p.send(f.t, encap.Packet{Header: h, Data: pkt.Data})
			continue
		}
		if pkt.Command == encap.CommandUnRegisterSession {
			return
		}
		if f.handle != nil {
			f.handle(p, pkt)
		}
	}
}

// rrReply answers a SendRRData request with a CIP response.
func rrReply(t testing.TB, p *peer, req encap.Packet, resp cip.Response, extra ...encap.Item) {
	b, err := resp.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	items := append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: b}}, extra...)
	data, err := encap.RRData{Items: items}.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	p.send(t, encap.Packet{Header: req.Header, Data: data})
}

// decodeRR returns the CIP request of a SendRRData packet.
func decodeRR(t testing.TB, pkt encap.Packet) cip.Request {
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		t.Error(err)
		return cip.Request{}
	}
	it, _ := encap.Find(rr.Items, encap.ItemUnconnectedData)
	req, err := cip.DecodeRequest(it.Data)
	if err != nil {
		t.Error(err)
	}
	return req
}

// metricsData is what recMetrics recorded.
type metricsData struct {
	connects    int
	disconnects []error
	sent, recv  int
	decodeErrs  int
	requests    []cip.Service
	done        []error
}

// recMetrics records metrics callbacks.
type recMetrics struct {
	ethernetip.NopMetrics
	mu sync.Mutex
	d  metricsData
}

func (m *recMetrics) OnConnect(net.Addr) { m.mu.Lock(); m.d.connects++; m.mu.Unlock() }
func (m *recMetrics) OnDisconnect(_ net.Addr, err error) {
	m.mu.Lock()
	m.d.disconnects = append(m.d.disconnects, err)
	m.mu.Unlock()
}
func (m *recMetrics) OnPacketSent(net.Addr, encap.Command, int) {
	m.mu.Lock()
	m.d.sent++
	m.mu.Unlock()
}
func (m *recMetrics) OnPacketReceived(net.Addr, encap.Command, int) {
	m.mu.Lock()
	m.d.recv++
	m.mu.Unlock()
}
func (m *recMetrics) OnDecodeError(net.Addr, error) { m.mu.Lock(); m.d.decodeErrs++; m.mu.Unlock() }
func (m *recMetrics) OnRequest(_ net.Addr, s cip.Service) {
	m.mu.Lock()
	m.d.requests = append(m.d.requests, s)
	m.mu.Unlock()
}
func (m *recMetrics) OnRequestDone(_ net.Addr, _ cip.Service, _ time.Duration, err error) {
	m.mu.Lock()
	m.d.done = append(m.d.done, err)
	m.mu.Unlock()
}

func (m *recMetrics) snapshot() metricsData {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.d
	d.disconnects = append([]error(nil), d.disconnects...)
	d.requests = append([]cip.Service(nil), d.requests...)
	d.done = append([]error(nil), d.done...)
	return d
}

// selfSigned returns a server TLS configuration with a fresh self-signed
// certificate for 127.0.0.1 and a pool that trusts it.
func selfSigned(t testing.TB) (*tls.Config, *x509.CertPool) {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

// errDialer fails every dial.
type errDialer struct{ err error }

func (d errDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, d.err }

var errDial = errors.New("dial refused by test")
