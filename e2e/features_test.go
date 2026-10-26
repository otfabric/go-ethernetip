// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

// TestIOClassZero exchanges data on a Class 0 connection: no sequence
// count, every datagram is new data.
func TestIOClassZero(t *testing.T) {
	a := startAdapter(t)
	s := newScanner(t, dial(t, a.addr))
	cfg := exclusiveOwner(5 * time.Millisecond)
	cfg.ClassZero = true
	io, err := s.Open(ctxT(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if io.Info().Class != 0 {
		t.Fatalf("class %d", io.Info().Class)
	}
	out := bytes.Repeat([]byte{0x0C}, ioSize)
	_ = io.SetOutput(out)
	eventually(t, 3*time.Second, "class 0 echo", func() bool {
		in, _, _ := io.Input()
		return bytes.Equal(in, out)
	})
}

// selfSigned returns a TLS certificate for 127.0.0.1 and a pool that
// trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e adapter"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

// TestTLS runs explicit messaging and a Class 3 connection over TLS (the
// CIP Security transport), and checks that a client refuses a server it
// does not trust.
func TestTLS(t *testing.T) {
	cert, pool := selfSigned(t)
	a := startAdapter(t, server.WithTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	ctx := ctxT(t)

	c := dial(t, a.addr, client.WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	id, err := c.Identity(ctx)
	if err != nil || id.ProductName != testIdentity.ProductName {
		t.Fatalf("identity over TLS %+v %v", id, err)
	}
	conn, err := c.OpenConnection(ctx, client.ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := conn.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)})
	if err != nil || string(r.Data[1:]) != testIdentity.ProductName {
		t.Fatalf("Class 3 over TLS %+v %v", r, err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// An untrusted certificate fails the handshake: no session.
	_, err = client.Dial(ctx, a.addr, client.WithTLS(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}),
		client.WithTimeout(2*time.Second))
	if err == nil {
		t.Fatal("dial with an untrusted server certificate succeeded")
	}
	// A plain client cannot talk to the TLS port either.
	if _, err := client.Dial(ctx, a.addr, client.WithTimeout(time.Second)); err == nil {
		t.Fatal("plain dial to the TLS port succeeded")
	}
}

// TestDiscover finds the adapter with one ListIdentity datagram.
func TestDiscover(t *testing.T) {
	a := startAdapter(t)
	devs, err := client.Discover(ctxT(t), client.DiscoverOptions{Address: a.addr, Wait: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].Identity.Identity != testIdentity {
		t.Fatalf("devices %+v", devs)
	}
	dev, err := client.ListIdentity(ctxT(t), a.addr)
	if err != nil || dev.Identity.SerialNumber != testIdentity.SerialNumber {
		t.Fatalf("ListIdentity %+v %v", dev, err)
	}
}

// TestScannerManyAdapters drives three adapters from one I/O endpoint
// shared by their scanners, as a controller with several devices does.
func TestScannerManyAdapters(t *testing.T) {
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	ctx := ctxT(t)
	type dev struct {
		a   *adapter
		io  *scanner.IO
		out []byte
	}
	var devs []dev
	for i := 0; i < 3; i++ {
		a := startAdapter(t)
		s, err := scanner.New(dial(t, a.addr), scanner.WithEndpoint(ep))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close(ctx) })
		io, err := s.Open(ctx, exclusiveOwner(5*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		out := bytes.Repeat([]byte{byte(0xA0 + i)}, ioSize)
		_ = io.SetOutput(out)
		devs = append(devs, dev{a, io, out})
	}
	for i, d := range devs {
		eventually(t, 3*time.Second, "echo of adapter", func() bool {
			in, _, _ := d.io.Input()
			return bytes.Equal(in, d.out) && bytes.Equal(d.a.out.Data(), d.out)
		})
		if d.io.State() != ethernetip.StateConnected {
			t.Fatalf("adapter %d: %s", i, d.io.State())
		}
	}
	if n := ep.Connections(); n != 3 {
		t.Fatalf("%d connections on the shared endpoint", n)
	}
	// Closing one leaves the others running.
	if err := devs[0].io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	out := bytes.Repeat([]byte{0x5E}, ioSize)
	_ = devs[2].io.SetOutput(out)
	eventually(t, 3*time.Second, "adapter 2 after closing 0", func() bool {
		in, _, _ := devs[2].io.Input()
		return bytes.Equal(in, out)
	})
}
