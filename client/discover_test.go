// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/server"
)

func TestDiscoverServer(t *testing.T) {
	srv, _ := startServer(t, server.WithDiscoveryDelay(50*time.Millisecond))
	udp := srv.UDPAddr()
	if udp == nil {
		t.Skip("UDP explicit port not available")
	}
	ctx := ctxT(t)
	devs, err := Discover(ctx, DiscoverOptions{Address: udp.String(), Local: "127.0.0.1:0", MaxDevices: 1, MaxDelay: 20 * time.Millisecond, Wait: 5 * time.Second})
	if err != nil || len(devs) != 1 {
		t.Fatalf("Discover = %+v, %v", devs, err)
	}
	d := devs[0]
	if d.Addr.String() != udp.String() || d.Identity.ProductName != server.DefaultIdentity.ProductName {
		t.Errorf("device %+v", d)
	}
	// A delay above 65535 ms is sent as the largest one; the server bounds it.
	if _, err := Discover(ctx, DiscoverOptions{Address: udp.String(), MaxDevices: 1, MaxDelay: time.Hour, Wait: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	dev, err := ListIdentity(context.Background(), udp.String())
	if err != nil || dev.Identity.VendorID != server.DefaultIdentity.VendorID {
		t.Fatalf("ListIdentity = %+v, %v", dev, err)
	}
}

func TestDiscoverOptions(t *testing.T) {
	ctx := ctxT(t)
	if _, err := Discover(ctx, DiscoverOptions{}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("no address = %v", err)
	}
	if _, err := Discover(ctx, DiscoverOptions{Address: "127.0.0.1:notaport"}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("bad address = %v", err)
	}
	if _, err := Discover(ctx, DiscoverOptions{Address: "127.0.0.1", Local: "127.0.0.1:notaport"}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("bad local address = %v", err)
	}
	// A local address that is in use cannot be bound.
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	if _, err := Discover(ctx, DiscoverOptions{Address: "127.0.0.1", Local: busy.LocalAddr().String()}); !errors.Is(err, ethernetip.ErrConnectFailed) {
		t.Errorf("busy local address = %v", err)
	}
}

// udpResponder answers each ListIdentity with the datagrams reply returns.
func udpResponder(t *testing.T, reply func(req encap.Packet) [][]byte) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = c.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pkt, err := encap.Decode(buf[:n])
			if err != nil {
				continue
			}
			for _, b := range reply(pkt) {
				_, _ = c.WriteToUDPAddrPort(b, from)
			}
		}
	}()
	return c.LocalAddr().String()
}

func identityReply(t *testing.T, h encap.Header, name string) []byte {
	it := encap.IdentityItem{ProtocolVersion: 1, Socket: encap.SockaddrOf(netip.MustParseAddrPort("127.0.0.1:44818")),
		Identity: cip.Identity{VendorID: 7, ProductName: name, State: 3}}
	b, err := it.Encode()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := encap.AppendCPF(nil, []encap.Item{{Type: encap.ItemListIdentity, Data: b}})
	out, _ := encap.Packet{Header: h, Data: data}.Encode()
	return out
}

func TestDiscoverFiltersReplies(t *testing.T) {
	addr := udpResponder(t, func(req encap.Packet) [][]byte {
		wrongCtx := req.Header
		wrongCtx.Context[7] ^= 1
		failed := req.Header
		failed.Status = encap.StatusInvalidCommand
		other := req.Header
		other.Command = encap.CommandListServices
		bad, _ := encap.Packet{Header: req.Header, Data: []byte{1}}.Encode()
		return [][]byte{
			{1, 2, 3}, // not a packet
			identityReply(t, wrongCtx, "wrong context"),
			identityReply(t, failed, "failed"),
			identityReply(t, other, "other command"),
			bad,
			identityReply(t, req.Header, "good"),
			identityReply(t, req.Header, "duplicate"),
		}
	})
	devs, err := Discover(ctxT(t), DiscoverOptions{Address: addr, Wait: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].Identity.ProductName != "good" {
		t.Fatalf("devices %+v, want only the good reply", devs)
	}
}

func TestDiscoverTimeoutAndCancel(t *testing.T) {
	silent := udpResponder(t, func(encap.Packet) [][]byte { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := ListIdentity(ctx, silent); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("ListIdentity of a silent device = %v, want ErrTimeout", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel2)
	start := time.Now()
	devs, err := Discover(ctx2, DiscoverOptions{Address: silent, Wait: 10 * time.Second})
	if !errors.Is(err, context.Canceled) || len(devs) != 0 {
		t.Fatalf("canceled Discover = %v, %v", devs, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("Discover did not stop at cancellation")
	}
	if _, err := ListIdentity(context.Background(), ""); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("ListIdentity without address = %v", err)
	}
}
