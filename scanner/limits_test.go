// SPDX-License-Identifier: MIT

package scanner

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// The Forward_Open fields never wrap, whatever validate let through.
func TestFields(t *testing.T) {
	for d, want := range map[time.Duration]uint32{
		time.Microsecond:          1,
		maxRPI:                    math.MaxUint32,
		maxRPI + time.Microsecond: math.MaxUint32,
		-time.Second:              0,
		999 * time.Nanosecond:     0,
	} {
		if got := rpiField(d); got != want {
			t.Errorf("rpiField(%v) = %d, want %d", d, got, want)
		}
	}
	for n, want := range map[int]uint16{0: 0, 0xFFFF: 0xFFFF, 0x10000: 0xFFFF, -1: 0} {
		if got := sizeField(n); got != want {
			t.Errorf("sizeField(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestMinOTAPI(t *testing.T) {
	for rpi, want := range map[time.Duration]time.Duration{
		100 * time.Millisecond: 25 * time.Millisecond,
		time.Millisecond:       250 * time.Microsecond,
		200 * time.Microsecond: 100 * time.Microsecond,
		50 * time.Microsecond:  50 * time.Microsecond,
		time.Microsecond:       time.Microsecond,
	} {
		if got := (IOConfig{}).otAPIFloor(rpi); got != want {
			t.Errorf("the default floor for %v = %v, want %v", rpi, got, want)
		}
	}
}

// The two floors on the O->T API follow OTAPIDivisor and MinOTAPI: zero
// keeps the released default, a positive value replaces it, a negative
// value disables that floor.
func TestOTAPIFloor(t *testing.T) {
	const (
		ms = time.Millisecond
		us = time.Microsecond
	)
	for _, tc := range []struct {
		name    string
		divisor int
		min     time.Duration
		rpi     time.Duration
		want    time.Duration
	}{
		{"defaults, 100 ms", 0, 0, 100 * ms, 25 * ms},
		{"defaults, 200 µs", 0, 0, 200 * us, 100 * us},
		{"defaults, 50 µs", 0, 0, 50 * us, 50 * us},
		{"divisor 1", 1, 0, 100 * ms, 100 * ms},
		{"divisor 2", 2, 0, 100 * ms, 50 * ms},
		{"divisor 3", 3, 0, 100 * ms, 100 * ms / 3},
		{"divisor 4 as the default", 4, 0, 100 * ms, 25 * ms},
		{"divisor 5", 5, 0, 100 * ms, 20 * ms},
		{"divisor 8", 8, 0, 100 * ms, 12500 * us},
		{"divisor max int", math.MaxInt, 0, 100 * ms, 100 * us},
		{"divisor max int32", math.MaxInt32, 0, 100 * ms, 100 * us},
		{"divisor -1 disables", -1, 0, 100 * ms, 100 * us},
		{"divisor min int disables", math.MinInt, 0, 100 * ms, 100 * us},
		{"min 1 ns", 0, 1, 200 * us, 50 * us},
		{"min 1 µs", -1, us, 100 * ms, us},
		{"min 99 µs", 0, 99 * us, 200 * us, 99 * us},
		{"min 100 µs as the default", 0, 100 * us, 200 * us, 100 * us},
		{"min 101 µs", 0, 101 * us, 200 * us, 101 * us},
		{"min 50 ms", 0, 50 * ms, 100 * ms, 50 * ms},
		{"min above the RPI", 0, time.Second, 100 * ms, 100 * ms},
		{"min max duration", 0, math.MaxInt64, 100 * ms, 100 * ms},
		{"min -1 disables", 0, -1, 200 * us, 50 * us},
		{"min min duration disables", 0, math.MinInt64, 200 * us, 50 * us},
		{"both disabled", -1, -1, 100 * ms, 0},
	} {
		cfg := IOConfig{OTAPIDivisor: tc.divisor, MinOTAPI: tc.min}
		if got := cfg.otAPIFloor(tc.rpi); got != tc.want {
			t.Errorf("%s: floor for %v = %v, want %v", tc.name, tc.rpi, got, tc.want)
		}
	}
}

// Open applies OTAPIDivisor and MinOTAPI to the O->T API of the
// Forward_Open reply: the floor itself is accepted, one microsecond below
// it refused, and an O->T API of 0 is refused with both floors disabled.
func TestReplyAPIFloors(t *testing.T) {
	const rpi = 100 * time.Millisecond // 100000 µs
	for _, tc := range []struct {
		name    string
		divisor int
		min     time.Duration
		otAPI   uint32
		ok      bool
	}{
		{"defaults, a quarter", 0, 0, 25000, true},
		{"defaults, below a quarter", 0, 0, 24999, false},
		{"divisor 8, an eighth", 8, 0, 12500, true},
		{"divisor 8, below an eighth", 8, 0, 12499, false},
		{"divisor 1, the RPI", 1, 0, 100000, true},
		{"divisor 1, below the RPI", 1, 0, 99999, false},
		{"divisor disabled, 100 µs", -1, 0, 100, true},
		{"divisor disabled, 99 µs", -1, 0, 99, false},
		{"min 50 ms", 0, 50 * time.Millisecond, 50000, true},
		{"min 50 ms, below", 0, 50 * time.Millisecond, 49999, false},
		{"divisor disabled, min 50 µs", -1, 50 * time.Microsecond, 50, true},
		{"divisor disabled, min 50 µs, below", -1, 50 * time.Microsecond, 49, false},
		{"both disabled, 0", -1, -1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
				r := okReply(fo)
				r.OTAPI = tc.otAPI
				// Unused port: nothing reads the data of the accepted cases.
				return r, []encap.Item{{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.MustParseAddrPort("127.0.0.1:9")).Encode()}}
			})
			s := newScanner(t, dial(t, f.ln.Addr().String()))
			ctx := ctxT(t)
			cfg := owner(rpi)
			cfg.OTAPIDivisor, cfg.MinOTAPI = tc.divisor, tc.min
			io, err := s.Open(ctx, cfg)
			if !tc.ok {
				if !errors.Is(err, ethernetip.ErrProtocol) {
					t.Fatalf("Open = %v, want ErrProtocol", err)
				}
				if n := f.closes.Load(); n != 1 {
					t.Errorf("%d Forward_Close, want 1", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := io.Info().OTRPI; got != time.Duration(tc.otAPI)*time.Microsecond {
				t.Errorf("Info().OTRPI = %v", got)
			}
			_ = io.Close(ctx)
		})
	}
}

// Open accepts actual packet intervals that differ from the RPI within
// the documented bounds, and refuses (closing the connection again) a
// reply that would make the scanner produce far faster than asked or
// consume without a timeout.
func TestReplyAPIs(t *testing.T) {
	const rpi = 100 * time.Millisecond // 100000 µs
	for _, tc := range []struct {
		name         string
		otAPI, toAPI uint32
		ok           bool
	}{
		{"equal", 100000, 100000, true},
		{"rounded up", 128000, 128000, true},
		{"quarter", 25000, 100000, true},
		{"short T->O", 100000, 1000, true},
		{"O->T 1 µs", 1, 100000, false},
		{"O->T 0", 0, 100000, false},
		{"O->T below a quarter", 24999, 100000, false},
		{"T->O 0", 100000, 0, false},
		{"both", 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
				r := okReply(fo)
				r.OTAPI, r.TOAPI = tc.otAPI, tc.toAPI
				// Unused port: nothing reads the data of the accepted cases.
				return r, []encap.Item{{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.MustParseAddrPort("127.0.0.1:9")).Encode()}}
			})
			s := newScanner(t, dial(t, f.ln.Addr().String()))
			ctx := ctxT(t)
			io, err := s.Open(ctx, owner(rpi))
			if !tc.ok {
				if !errors.Is(err, ethernetip.ErrProtocol) {
					t.Fatalf("Open = %v, want ErrProtocol", err)
				}
				if n := f.closes.Load(); n != 1 {
					t.Errorf("%d Forward_Close, want 1", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := io.Info().OTRPI; got != time.Duration(tc.otAPI)*time.Microsecond {
				t.Errorf("Info().OTRPI = %v", got)
			}
			_ = io.Close(ctx)
		})
	}
}

// The O->T data of a point-to-point connection goes to the target's
// address at the port its Sockaddr Info O->T item names, also when the
// item names another address.
func TestSockaddrOTAddress(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		return okReply(fo), []encap.Item{{Type: encap.ItemSockaddrOT, Data: encap.SockaddrOf(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)).Encode()}}
	})
	s := newScanner(t, dial(t, f.ln.Addr().String()))
	ctx := ctxT(t)
	io, err := s.Open(ctx, owner(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = io.Close(ctx) }()
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	if _, err := pc.Read(b); err != nil {
		t.Fatalf("no O->T datagram at the target's address: %v", err)
	}
}
