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
		if got := minOTAPI(rpi); got != want {
			t.Errorf("minOTAPI(%v) = %v, want %v", rpi, got, want)
		}
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
