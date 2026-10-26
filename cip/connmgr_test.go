// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
)

// openerPath is OpENer's exclusive owner connection path: configuration
// instance 0x97, consumed point 0x96, produced point 0x64.
func openerPath() cip.Path {
	return cip.Path{
		cip.LogicalSegment{Type: cip.LogicalClass, Value: 4, Format: cip.Format8},
		cip.LogicalSegment{Type: cip.LogicalInstance, Value: 0x97, Format: cip.Format8},
		cip.LogicalSegment{Type: cip.LogicalConnectionPoint, Value: 0x96, Format: cip.Format8},
		cip.LogicalSegment{Type: cip.LogicalConnectionPoint, Value: 0x64, Format: cip.Format8},
	}
}

func TestForwardOpenVector(t *testing.T) {
	fo := cip.ForwardOpen{
		PriorityTick:      0x0A,
		TimeoutTicks:      0x0E,
		TOConnID:          0x12345678,
		Triad:             cip.Triad{Serial: 1, VendorID: 0x1337, OriginatorSerial: 0x87654321},
		TimeoutMultiplier: 1,
		OTRPI:             10000,
		OTParams:          cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 38},
		TORPI:             10000,
		TOParams:          cip.NetworkParams{Type: cip.ConnectionMulticast, Priority: cip.PriorityScheduled, Size: 32},
		Transport:         cip.TransportClass1Cyclic,
		Path:              openerPath(),
	}
	want := unhex(t, "0A 0E 00000000 78563412 0100 3713 21436587 01 000000 10270000 2648 10270000 2028 01 04 2004249 72C962C64")
	b, err := fo.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode =\n% X\nwant\n% X", b, want)
	}
	got, err := cip.DecodeForwardOpen(want, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, fo) {
		t.Errorf("DecodeForwardOpen =\n%+v\nwant\n%+v", got, fo)
	}
	if fo.Service() != cip.ServiceForwardOpen {
		t.Errorf("Service = %v", fo.Service())
	}
	if d := cip.TickTimeout(fo.PriorityTick, fo.TimeoutTicks); d != 14*1024*time.Millisecond {
		t.Errorf("TickTimeout = %v", d)
	}
}

func TestLargeForwardOpenVector(t *testing.T) {
	fo := cip.ForwardOpen{
		Large:             true,
		PriorityTick:      0x07,
		TimeoutTicks:      0xE8,
		OTConnID:          0x11111111,
		TOConnID:          0x22222222,
		Triad:             cip.Triad{Serial: 0xBEEF, VendorID: 1, OriginatorSerial: 2},
		TimeoutMultiplier: 3,
		OTRPI:             20000,
		OTParams:          cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 1000},
		TORPI:             30000,
		TOParams:          cip.NetworkParams{RedundantOwner: true, Type: cip.ConnectionMulticast, Priority: cip.PriorityScheduled, Variable: true, Size: 0x1000},
		Transport:         cip.TransportClass3Server,
		Path:              cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}, cip.ClassSegment(2), cip.InstanceSegment(1)},
	}
	want := unhex(t, "07 E8 11111111 22222222 EFBE 0100 02000000 03 000000 204E0000 E8030048 30750000 001000AA A3 03 0100 2002 2401")
	b, err := fo.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode =\n% X\nwant\n% X", b, want)
	}
	got, err := cip.DecodeForwardOpen(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Service() != cip.ServiceLargeForwardOpen || got.OTParams != fo.OTParams || got.TOParams != fo.TOParams || got.Path.String() != fo.Path.String() {
		t.Errorf("DecodeForwardOpen = %+v", got)
	}
	// The same octets read as a small Forward_Open misplace the fields.
	if small, err := cip.DecodeForwardOpen(b, false); err == nil && small.TOParams == fo.TOParams {
		t.Error("large request decoded as small gives the same parameters")
	}
}

func TestForwardOpenErrors(t *testing.T) {
	base := cip.ForwardOpen{OTParams: cip.NetworkParams{Size: 10}, TOParams: cip.NetworkParams{Size: 10}, Path: openerPath()}

	f := base
	f.TimeoutMultiplier = 8
	if _, err := f.Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("multiplier 8: %v", err)
	}
	f = base
	f.Path = cip.Path{cip.PortSegment{}}
	if _, err := f.Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad path: %v", err)
	}
	f = base
	f.Path = cip.Path{cip.DataSegment{Data: make([]byte, 510)}}
	if _, err := f.Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long path: %v", err)
	}
	f = base
	f.OTParams.Size = 512
	if _, err := f.Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("O->T size 512: %v", err)
	}
	f.Large = true
	if _, err := f.Encode(); err != nil {
		t.Errorf("large O->T size 512: %v", err)
	}
	f.TOParams.Type = 4
	if _, err := f.Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("large T->O type 4: %v", err)
	}

	good, err := base.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(good); n++ {
		if _, err := cip.DecodeForwardOpen(good[:n], false); !errors.Is(err, cip.ErrTruncated) {
			t.Fatalf("truncated to %d: %v", n, err)
		}
	}
	bad := append([]byte(nil), good...)
	bad[35] = 1
	bad = append(bad[:36], 0xA0, 0x00)
	if _, err := cip.DecodeForwardOpen(bad, false); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad path: %v", err)
	}
}

func TestNetworkParams(t *testing.T) {
	cases := []struct {
		p   cip.NetworkParams
		v16 uint16
		v32 uint32
		s   string
	}{
		{cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 38}, 0x4826, 0x48000026, "point-to-point scheduled fixed 38"},
		{cip.NetworkParams{Type: cip.ConnectionMulticast, Priority: cip.PriorityLow, Variable: true, Size: 511}, 0x23FF, 0x220001FF, "multicast low variable 511"},
		{cip.NetworkParams{RedundantOwner: true, Type: cip.ConnectionNull, Priority: cip.PriorityUrgent}, 0x8C00, 0x8C000000, "null urgent fixed 0 redundant-owner"},
		{cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityHigh, Size: 500}, 0x45F4, 0x440001F4, "point-to-point high fixed 500"},
	}
	for _, c := range cases {
		v16, err := c.p.Encode16()
		if err != nil || v16 != c.v16 {
			t.Errorf("%v Encode16 = %#04x, %v; want %#04x", c.p, v16, err, c.v16)
		}
		v32, err := c.p.Encode32()
		if err != nil || v32 != c.v32 {
			t.Errorf("%v Encode32 = %#08x, %v; want %#08x", c.p, v32, err, c.v32)
		}
		if d := cip.DecodeNetworkParams16(c.v16); d != c.p {
			t.Errorf("DecodeNetworkParams16(%#04x) = %+v", c.v16, d)
		}
		if d := cip.DecodeNetworkParams32(c.v32); d != c.p {
			t.Errorf("DecodeNetworkParams32(%#08x) = %+v", c.v32, d)
		}
		if s := c.p.String(); s != c.s {
			t.Errorf("String = %q, want %q", s, c.s)
		}
	}
	// Large sizes only fit 32 bits.
	big := cip.NetworkParams{Type: cip.ConnectionPointToPoint, Size: 4000}
	if _, err := big.Encode16(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("Encode16 size 4000: %v", err)
	}
	if v, err := big.Encode32(); err != nil || cip.DecodeNetworkParams32(v) != big {
		t.Errorf("Encode32 size 4000: %#x, %v", v, err)
	}
	for _, p := range []cip.NetworkParams{{Type: 4}, {Priority: 4}} {
		if _, err := p.Encode16(); !errors.Is(err, cip.ErrMalformed) {
			t.Errorf("%+v Encode16: %v", p, err)
		}
		if _, err := p.Encode32(); !errors.Is(err, cip.ErrMalformed) {
			t.Errorf("%+v Encode32: %v", p, err)
		}
	}
	if s := (cip.NetworkParams{Type: 5, Priority: 7}).String(); s != "connection-type-5 priority-7 fixed 0" {
		t.Errorf("String = %q", s)
	}
}

func TestTransportTrigger(t *testing.T) {
	if v := cip.NewTransportTrigger(3, cip.TriggerApplication, true); v != cip.TransportClass3Server {
		t.Errorf("class 3 application server = %#x", uint8(v))
	}
	if v := cip.NewTransportTrigger(1, cip.TriggerCyclic, false); v != cip.TransportClass1Cyclic {
		t.Errorf("class 1 cyclic = %#x", uint8(v))
	}
	v := cip.NewTransportTrigger(0x11, cip.TriggerChangeOfState, false)
	if v != 0x11 || v.Class() != 1 || v.Trigger() != cip.TriggerChangeOfState || v.Server() {
		t.Errorf("class masked to 4 bits: %#x", uint8(v))
	}
	cases := map[cip.TransportTrigger]string{
		cip.TransportClass3Server: "class 3 application server",
		cip.TransportClass1Cyclic: "class 1 cyclic",
		0x10:                      "class 0 change-of-state",
		0x70:                      "class 0 trigger-7",
	}
	for v, s := range cases {
		if v.String() != s {
			t.Errorf("%#x String = %q, want %q", uint8(v), v.String(), s)
		}
	}
}

func TestEnumStrings(t *testing.T) {
	for v, s := range map[cip.ConnectionType]string{0: "null", 1: "multicast", 2: "point-to-point", 3: "connection-type-3"} {
		if v.String() != s {
			t.Errorf("ConnectionType(%d) = %q", v, v.String())
		}
	}
	for v, s := range map[cip.Priority]string{0: "low", 1: "high", 2: "scheduled", 3: "urgent", 4: "priority-4"} {
		if v.String() != s {
			t.Errorf("Priority(%d) = %q", v, v.String())
		}
	}
	for v, s := range map[cip.Trigger]string{0: "cyclic", 1: "change-of-state", 2: "application", 3: "trigger-3"} {
		if v.String() != s {
			t.Errorf("Trigger(%d) = %q", v, v.String())
		}
	}
	tr := cip.Triad{Serial: 1, VendorID: 1, OriginatorSerial: 0x12345678}
	if s := tr.String(); s != "serial 0x0001 vendor 1 originator 0x12345678" {
		t.Errorf("Triad = %q", s)
	}
}

func TestTicks(t *testing.T) {
	cases := []struct {
		d          time.Duration
		tick, n    uint8
		normalized time.Duration
	}{
		{0, 0, 1, time.Millisecond},
		{time.Millisecond, 0, 1, time.Millisecond},
		{255 * time.Millisecond, 0, 255, 255 * time.Millisecond},
		{256 * time.Millisecond, 1, 128, 256 * time.Millisecond},
		{time.Second, 2, 250, time.Second},
		{1001 * time.Millisecond, 2, 251, 1004 * time.Millisecond},
		{10 * time.Hour, 15, 255, 255 << 15 * time.Millisecond},
	}
	for _, c := range cases {
		tick, n := cip.Ticks(c.d)
		if tick != c.tick || n != c.n {
			t.Errorf("Ticks(%v) = %d, %d; want %d, %d", c.d, tick, n, c.tick, c.n)
		}
		if got := cip.TickTimeout(tick, n); got != c.normalized {
			t.Errorf("TickTimeout(Ticks(%v)) = %v, want %v", c.d, got, c.normalized)
		}
	}
	// Ticks never undershoots for durations it can represent.
	for ms := int64(1); ms < 300000; ms = ms*3 + 7 {
		d := time.Duration(ms) * time.Millisecond
		if got := cip.TickTimeout(cip.Ticks(d)); got < d {
			t.Errorf("TickTimeout(Ticks(%v)) = %v", d, got)
		}
	}
	// The high nibble of the priority/tick octet is ignored.
	if d := cip.TickTimeout(0xF3, 2); d != 16*time.Millisecond {
		t.Errorf("TickTimeout(0xF3, 2) = %v", d)
	}
}

func TestConnectionTimeout(t *testing.T) {
	if d := cip.ConnectionTimeout(10*time.Millisecond, 0); d != 40*time.Millisecond {
		t.Errorf("multiplier 0 = %v", d)
	}
	if d := cip.ConnectionTimeout(10*time.Millisecond, 1); d != 80*time.Millisecond {
		t.Errorf("multiplier 1 = %v", d)
	}
	if d := cip.ConnectionTimeout(10*time.Millisecond, 7); d != 5120*time.Millisecond {
		t.Errorf("multiplier 7 = %v", d)
	}
	if d := cip.ConnectionTimeout(10*time.Millisecond, 200); d != 5120*time.Millisecond {
		t.Errorf("multiplier 200 = %v, want clamped to 7", d)
	}
}

func TestForwardOpenReply(t *testing.T) {
	r := cip.ForwardOpenReply{
		OTConnID: 0x11223344, TOConnID: 0x55667788,
		Triad: cip.Triad{Serial: 1, VendorID: 0x1337, OriginatorSerial: 0x87654321},
		OTAPI: 10000, TOAPI: 20000, AppReply: []byte{0xAA, 0xBB},
	}
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "44332211 88776655 0100 3713 21436587 10270000 204E0000 01 00 AABB")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := cip.DecodeForwardOpenReply(b)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Errorf("Decode = %+v, %v", got, err)
	}
	// The application reply is copied.
	b[len(b)-1] = 0
	if got.AppReply[1] != 0xBB {
		t.Error("AppReply aliases the input")
	}
	if _, err := (cip.ForwardOpenReply{AppReply: []byte{1}}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("odd app reply: %v", err)
	}
	if _, err := (cip.ForwardOpenReply{AppReply: make([]byte, 512)}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("long app reply: %v", err)
	}
	if _, err := cip.DecodeForwardOpenReply(want[:len(want)-1]); !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	if _, err := cip.DecodeForwardOpenReply(want[:25]); !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("truncated header: %v", err)
	}
}

func TestConnectionFailure(t *testing.T) {
	f := cip.ConnectionFailure{Triad: cip.Triad{Serial: 1, VendorID: 0x1337, OriginatorSerial: 0x87654321}, RemainingPathSize: 2}
	b := f.Encode()
	if want := unhex(t, "0100 3713 21436587 02 00"); !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	if got, err := cip.DecodeConnectionFailure(b); err != nil || got != f {
		t.Errorf("Decode = %+v, %v", got, err)
	}
	// Some targets omit the remaining path size.
	got, err := cip.DecodeConnectionFailure(b[:8])
	if err != nil || got.Triad != f.Triad || got.RemainingPathSize != 0 {
		t.Errorf("Decode without size = %+v, %v", got, err)
	}
	if _, err := cip.DecodeConnectionFailure(b[:7]); !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
}

func TestForwardClose(t *testing.T) {
	fc := cip.ForwardClose{
		PriorityTick: 0x0A, TimeoutTicks: 0x0E,
		Triad: cip.Triad{Serial: 1, VendorID: 0x1337, OriginatorSerial: 0x87654321},
		Path:  openerPath(),
	}
	b, err := fc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0A 0E 0100 3713 21436587 04 00 2004249 72C962C64")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := cip.DecodeForwardClose(b)
	if err != nil || !reflect.DeepEqual(got, fc) {
		t.Errorf("Decode = %+v, %v", got, err)
	}

	if _, err := (cip.ForwardClose{Path: cip.Path{cip.PortSegment{}}}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad path: %v", err)
	}
	if _, err := (cip.ForwardClose{Path: cip.Path{cip.DataSegment{Data: make([]byte, 510)}}}).Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long path: %v", err)
	}
	if _, err := cip.DecodeForwardClose(want[:len(want)-1]); !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	if _, err := cip.DecodeForwardClose(unhex(t, "0A 0E 0100 3713 21436587 01 00 A000")); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad path: %v", err)
	}

	rep := cip.ForwardCloseReply{Triad: fc.Triad, AppReply: []byte{1, 2}}
	b, err = rep.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0100 3713 21436587 01 00 0102"); !bytes.Equal(b, want) {
		t.Fatalf("reply Encode = % X", b)
	}
	if got, err := cip.DecodeForwardCloseReply(b); err != nil || !reflect.DeepEqual(got, rep) {
		t.Errorf("reply Decode = %+v, %v", got, err)
	}
	if _, err := (cip.ForwardCloseReply{AppReply: []byte{1}}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("odd app reply: %v", err)
	}
	if _, err := cip.DecodeForwardCloseReply(b[:11]); !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("truncated reply: %v", err)
	}
}

func TestUnconnectedSend(t *testing.T) {
	route, err := cip.ParseRoute("1/0")
	if err != nil {
		t.Fatal(err)
	}
	// An embedded message of odd length is followed by a pad octet.
	u := cip.UnconnectedSend{
		PriorityTick: 0x0A, TimeoutTicks: 0x0E,
		Request: cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7), Data: []byte{5}},
		Route:   route,
	}
	b, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0A 0E 0900 10 03 20 01 24 01 30 07 05 00 01 00 01 00")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X, want % X", b, want)
	}
	got, err := cip.DecodeUnconnectedSend(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Request.String() != u.Request.String() || !bytes.Equal(got.Request.Data, []byte{5}) || !reflect.DeepEqual(got.Route, route) {
		t.Errorf("Decode = %+v", got)
	}

	// Even length: no pad.
	u.Request = cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)}
	b, err = u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0A 0E 0800 0E 03 20 01 24 01 30 07 01 00 01 00"); !bytes.Equal(b, want) {
		t.Fatalf("Encode even = % X", b)
	}
	if got, err := cip.DecodeUnconnectedSend(b); err != nil || got.Request.Service != cip.ServiceGetAttributeSingle {
		t.Errorf("Decode even = %+v, %v", got, err)
	}
}

func TestUnconnectedSendErrors(t *testing.T) {
	ok := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.MessageRouterPath()}
	if _, err := (cip.UnconnectedSend{Request: cip.Request{Service: 0x8E}}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("reply bit: %v", err)
	}
	if _, err := (cip.UnconnectedSend{Request: cip.Request{Service: 0x10, Path: cip.MessageRouterPath(), Data: make([]byte, 70000)}}).Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long message: %v", err)
	}
	if _, err := (cip.UnconnectedSend{Request: ok, Route: cip.Path{cip.PortSegment{}}}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad route: %v", err)
	}
	long := make(cip.Path, 256)
	for i := range long {
		long[i] = cip.PortSegment{Port: 1, Link: []byte{0}}
	}
	if _, err := (cip.UnconnectedSend{Request: ok, Route: long}).Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long route: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", cip.ErrTruncated},
		{"message truncated", "0A 0E 0900 0E 03 20", cip.ErrTruncated},
		{"pad missing", "0A 0E 0100 0E", cip.ErrTruncated},
		{"route truncated", "0A 0E 0400 0E 01 2002 02 00 0100", cip.ErrTruncated},
		{"embedded reply", "0A 0E 0400 8E 01 2002 01 00 0100", cip.ErrMalformed},
		{"embedded bad path", "0A 0E 0400 0E 01 A000 01 00 0100", cip.ErrMalformed},
		{"bad route", "0A 0E 0400 0E 01 2002 01 00 0000", cip.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := cip.DecodeUnconnectedSend(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
