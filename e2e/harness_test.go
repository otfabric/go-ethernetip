// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/internal/testenv"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

// The assemblies of the test adapter, after OpENer's sample application:
// input 100 (32 octets), output 150 (32), configuration 151 (10),
// input-only heartbeat 152, listen-only heartbeat 153.
const (
	asmInput      = 100
	asmOutput     = 150
	asmConfig     = 151
	asmInputOnly  = 152
	asmListenOnly = 153
	ioSize        = 32
	configSize    = 10
)

var testIdentity = cip.Identity{
	VendorID:     0xFFFF,
	DeviceType:   cip.DeviceTypeCommunicationsAdapter,
	ProductCode:  42,
	Revision:     cip.Revision{Major: 3, Minor: 7},
	SerialNumber: 0x12345678,
	ProductName:  "e2e adapter",
	State:        3,
}

type adapter struct {
	srv    *server.Server
	addr   string
	in     *server.Assembly
	out    *server.Assembly
	config *server.Assembly
}

// startAdapter starts a server on loopback with the test assemblies, the
// I/O endpoint on a free port, and the output copied to the input like
// OpENer's sample application does.
func startAdapter(t testing.TB, opts ...server.Option) *adapter {
	t.Helper()
	return startAdapterAt(t, "127.0.0.1:0", opts...)
}

// startAdapterAt is startAdapter on a given TCP address.
func startAdapterAt(t testing.TB, addr string, opts ...server.Option) *adapter {
	t.Helper()
	opts = append([]server.Option{
		server.WithIdentity(testIdentity),
		server.WithIOAddress("127.0.0.1:0"),
	}, opts...)
	srv, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	a := &adapter{srv: srv}
	if a.in, err = srv.AddAssembly(asmInput, server.AssemblyInput, ioSize); err != nil {
		t.Fatal(err)
	}
	if a.out, err = srv.AddAssembly(asmOutput, server.AssemblyOutput, ioSize); err != nil {
		t.Fatal(err)
	}
	if a.config, err = srv.AddAssembly(asmConfig, server.AssemblyConfig, configSize); err != nil {
		t.Fatal(err)
	}
	if _, err = srv.AddAssembly(asmInputOnly, server.AssemblyInputOnly, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = srv.AddAssembly(asmListenOnly, server.AssemblyListenOnly, 0); err != nil {
		t.Fatal(err)
	}
	a.out.OnWrite(func(data []byte, _ bool) { _ = a.in.SetData(data) })
	if err := srv.Listen(addr); err != nil {
		t.Fatal(err)
	}
	a.addr = srv.Addr().String()
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ethernetip.ErrClosed) {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
	return a
}

// startUDPAdapter is startAdapter for a test of ListIdentity over UDP. The
// server opens its UDP socket on the number of its ephemeral TCP port and
// carries on without one when that number is taken: every test package
// binds ephemeral UDP ports, and Windows hands out the same numbers for TCP
// and UDP, so the datagram of such a test would reach another socket. An
// adapter whose UDP socket was not available is replaced.
func startUDPAdapter(t testing.TB, opts ...server.Option) *adapter {
	t.Helper()
	const attempts = 20
	for range attempts {
		a := startAdapter(t, opts...)
		if a.srv.UDPAddr() != nil {
			return a
		}
		t.Logf("UDP port of %s is taken: trying another port", a.addr)
	}
	t.Fatalf("no adapter with a UDP socket in %d attempts", attempts)
	return nil
}

func dial(t testing.TB, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newScanner(t testing.TB, c *client.Client) *scanner.Scanner {
	t.Helper()
	s, err := scanner.New(c, scanner.WithLocalAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

// newMulticastScanner returns a scanner that consumes multicast from the
// test adapter: its endpoint binds the wildcard address (an endpoint bound
// to 127.0.0.1 receives no multicast) and joins on the loopback
// interface. It skips the test where loopback multicast is not delivered.
func newMulticastScanner(t testing.TB, c *client.Client) *scanner.Scanner {
	t.Helper()
	lo := loopbackMulticast(t)
	s, err := scanner.New(c, scanner.WithLocalAddr("0.0.0.0:0"), scanner.WithMulticastInterface(lo))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

// loopbackMulticast returns the loopback interface after checking that a
// multicast datagram sent on it arrives, or skips the test.
func loopbackMulticast(t testing.TB) *net.Interface {
	t.Helper()
	var lo *net.Interface
	ifs, _ := net.Interfaces()
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback != 0 && ifs[i].Flags&net.FlagUp != 0 {
			lo = &ifs[i]
			break
		}
	}
	if lo == nil {
		t.Skip("no loopback interface")
	}
	group := netip.MustParseAddr("239.192.255.254")
	rx, err := implicit.Listen("0.0.0.0:0", implicit.WithMulticastInterface(lo))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rx.Close() }()
	tx, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Close() }()
	got := make(chan struct{}, 1)
	in, err := rx.Open(implicit.Config{ConsumedID: 1, Group: group, ConsumeSize: 0, OnData: func([]byte, bool) {
		select {
		case got <- struct{}{}:
		default:
		}
	}})
	if err != nil {
		testenv.Multicast(t, "loopback multicast: %v", err)
	}
	defer in.Close()
	out, err := tx.Open(implicit.Config{ProducedID: 1, ProduceRPI: 10 * time.Millisecond,
		Destination: netip.AddrPortFrom(group, rx.LocalAddr().Port())})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	select {
	case <-got:
		return lo
	case <-time.After(time.Second):
		testenv.Multicast(t, "multicast is not delivered on the loopback interface here")
		return nil
	}
}

func ctxT(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// eventually waits for cond, polling, up to d.
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

func exclusiveOwner(rpi time.Duration) scanner.IOConfig {
	return scanner.IOConfig{
		ConfigInstance: asmConfig,
		OutputInstance: asmOutput,
		InputInstance:  asmInput,
		OutputSize:     ioSize,
		InputSize:      ioSize,
		RPI:            rpi,
		// 16 RPIs: short RPIs meet coarse timers on loaded CI runners
		// (Windows); the timeout tests set their own.
		TimeoutMultiplier: 2,
	}
}
