// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

func TestIOExchange(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)

	cfg := exclusiveOwner(5 * time.Millisecond)
	cfg.ConfigData = bytes.Repeat([]byte{7}, configSize)
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.config.Data(), cfg.ConfigData) {
		t.Fatalf("configuration %x", a.config.Data())
	}
	for i := 1; i <= 3; i++ {
		out := bytes.Repeat([]byte{byte(i)}, ioSize)
		if err := io.SetOutput(out); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Second, "output echoed to input", func() bool {
			in, _, _ := io.Input()
			return bytes.Equal(in, out)
		})
		if !a.out.Run() {
			t.Fatal("output not in run")
		}
	}
	io.SetRun(false)
	eventually(t, 3*time.Second, "idle", func() bool { return !a.out.Run() })
	if n := len(a.srv.Connections()); n != 1 {
		t.Fatalf("%d connections on the server", n)
	}
	st := io.Stats()
	if st.Sent == 0 || st.Received == 0 {
		t.Fatalf("stats %+v", st)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "server connection closed", func() bool { return len(a.srv.Connections()) == 0 })
	if _, err := s.Open(ctx, exclusiveOwner(5*time.Millisecond)); err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
}

func connStatus(err error) cip.ConnectionStatus {
	var ce *ethernetip.CIPError
	if errors.As(err, &ce) && ce.Status == cip.StatusConnectionFailure && len(ce.Extended) > 0 {
		return cip.ConnectionStatus(ce.Extended[0])
	}
	return 0
}

func TestIORefusals(t *testing.T) {
	a := startAdapter(t, server.WithMaxConnections(3))
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)

	if _, err := s.Open(ctx, exclusiveOwner(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mod  func(*scanner.IOConfig)
		want cip.ConnectionStatus
	}{
		{"ownership", func(*scanner.IOConfig) {}, cip.ConnStatusOwnershipConflict},
		{"output size", func(c *scanner.IOConfig) { c.OutputSize = 31 }, cip.ConnStatusInvalidOTSize},
		{"input size", func(c *scanner.IOConfig) { c.InputSize = 30 }, cip.ConnStatusInvalidTOSize},
		{"consuming path", func(c *scanner.IOConfig) { c.OutputInstance = asmInput }, cip.ConnStatusInvalidConsumingPath},
		{"producing path", func(c *scanner.IOConfig) { c.InputInstance = asmOutput }, cip.ConnStatusInvalidProducingPath},
		{"config size", func(c *scanner.IOConfig) { c.ConfigData = []byte{1, 2} }, cip.ConnStatusInvalidConfigurationSize},
		{"listen only without producer", func(c *scanner.IOConfig) {
			c.OutputInstance, c.OutputSize, c.Multicast = asmListenOnly, 0, true
		}, cip.ConnStatusNonListenOnlyNotOpened},
		{"rpi", func(c *scanner.IOConfig) { c.RPI = time.Hour + time.Second }, cip.ConnStatusRPINotAcceptable},
		{"key", func(c *scanner.IOConfig) { c.Key = &cip.KeySegment{VendorID: 1} }, cip.ConnStatusVendorMismatch},
		{"revision", func(c *scanner.IOConfig) { c.Key = &cip.KeySegment{Major: 9} }, cip.ConnStatusRevisionMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exclusiveOwner(10 * time.Millisecond)
			tc.mod(&cfg)
			_, err := s.Open(ctx, cfg)
			if got := connStatus(err); got != tc.want {
				t.Fatalf("got %v (%s), want %s", err, got, tc.want)
			}
		})
	}
	// Two input-only connections fill the limit of three.
	for i := 0; i < 2; i++ {
		cfg := exclusiveOwner(10 * time.Millisecond)
		cfg.OutputInstance, cfg.OutputSize = asmInputOnly, 0
		if _, err := s.Open(ctx, cfg); err != nil {
			t.Fatalf("input only %d: %v", i, err)
		}
	}
	cfg := exclusiveOwner(10 * time.Millisecond)
	cfg.OutputInstance, cfg.OutputSize = asmInputOnly, 0
	if _, err := s.Open(ctx, cfg); connStatus(err) != cip.ConnStatusOutOfConnections {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestIOTimeoutAndRecovery(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)

	states := make(chan ethernetip.State, 16)
	cfg := exclusiveOwner(5 * time.Millisecond)
	cfg.Reconnect = &scanner.Reconnect{MinDelay: 10 * time.Millisecond}
	cfg.OnState = func(st ethernetip.State, _ error) {
		select {
		case states <- st:
		default:
		}
	}
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := io.Info()
	// The target's I/O goes away: both ends time out; the scanner reopens.
	_ = a.srv.Close()
	eventually(t, 5*time.Second, "time out", func() bool { return io.State() == ethernetip.StateTimedOut })
	startAdapterAt(t, a.addr)
	eventually(t, 10*time.Second, "reconnect", func() bool { return io.State() == ethernetip.StateConnected })
	if io.Info().OTConnID == before.OTConnID {
		t.Fatal("same connection after reconnect")
	}
	out := bytes.Repeat([]byte{9}, ioSize)
	_ = io.SetOutput(out)
	eventually(t, 3*time.Second, "data after reconnect", func() bool {
		in, _, _ := io.Input()
		return bytes.Equal(in, out)
	})
	_ = io.Close(context.Background())
}

func TestTargetTimesOutOriginator(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	ctx := ctxT(t)
	if _, err := s.Open(ctx, exclusiveOwner(5*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The scanner's endpoint closes without Forward_Close: the server
	// stops receiving O->T and times the connection out.
	_ = s.Endpoint().Close()
	eventually(t, 15*time.Second, "server timeout", func() bool { return len(a.srv.Connections()) == 0 })
	if a.out.Run() {
		t.Fatal("output still in run after timeout")
	}
	ctr, err := c.GetAttributeSingle(ctx, cip.ClassConnectionManager, 1, 8)
	if err != nil || ctr[0] != 1 {
		t.Fatalf("timeouts counter %x %v", ctr, err)
	}
}

// TestIOInitialOutputIdle starts a connection with initial output in idle:
// the adapter gets the data with idle, then run after SetRun.
func TestIOInitialOutputIdle(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newScanner(t, c)
	cfg := exclusiveOwner(5 * time.Millisecond)
	cfg.Output = bytes.Repeat([]byte{0x77}, ioSize)
	cfg.Idle = true
	io, err := s.Open(ctxT(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "initial output", func() bool { return bytes.Equal(a.out.Data(), cfg.Output) })
	if a.out.Run() {
		t.Fatal("run before SetRun")
	}
	io.SetRun(true)
	eventually(t, 3*time.Second, "run", a.out.Run)
	bad := cfg
	bad.Output = []byte{1}
	if _, err := s.Open(ctxT(t), bad); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("short initial output: %v", err)
	}
}

// TestIOListenOnly opens a multicast exclusive owner and, on the same
// scanner endpoint, a listen-only connection to the same production: both
// consume the multicast data; the listen-only connection closes with its
// owner.
func TestIOListenOnly(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	s := newMulticastScanner(t, c)
	ctx := ctxT(t)

	owner := exclusiveOwner(5 * time.Millisecond)
	owner.Multicast = true
	oio, err := s.Open(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	lcfg := exclusiveOwner(5 * time.Millisecond)
	lcfg.ConfigInstance = 0
	lcfg.OutputInstance, lcfg.OutputSize, lcfg.Multicast = asmListenOnly, 0, true
	lio, err := s.Open(ctx, lcfg)
	if err != nil {
		t.Fatal(err)
	}
	if oi, li := oio.Info(), lio.Info(); oi.TOConnID != li.TOConnID || !oi.Group.IsValid() || oi.Group != li.Group {
		t.Fatalf("owner %+v, listener %+v: not one multicast production", oi, li)
	}
	out := bytes.Repeat([]byte{0x5A}, ioSize)
	if err := oio.SetOutput(out); err != nil {
		t.Fatal(err)
	}
	waitData := func(io *scanner.IO, what string) {
		t.Helper()
		eventually(t, 3*time.Second, what, func() bool {
			in, _, _ := io.Input()
			return bytes.Equal(in, out)
		})
	}
	waitData(oio, "owner input")
	waitData(lio, "listen-only input")
	if n := len(a.srv.Connections()); n != 2 {
		t.Fatalf("%d connections on the server", n)
	}

	// Closing the owner closes the listen-only connection on the target;
	// the scanner sees its data stop.
	if err := oio.Close(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "server connections closed", func() bool { return len(a.srv.Connections()) == 0 })
	eventually(t, 5*time.Second, "listen-only timed out", func() bool { return lio.State() == ethernetip.StateTimedOut })
}
