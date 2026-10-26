// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

func TestCPFRoundTrip(t *testing.T) {
	items := []encap.Item{
		{Type: encap.ItemNullAddress, Data: []byte{}},
		{Type: encap.ItemUnconnectedData, Data: unhex(t, "0E 03 20 01 24 01 30 07")},
	}
	b, err := encap.AppendCPF(nil, items)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0200 0000 0000 B200 0800 0E03200124013007")
	if !bytes.Equal(b, want) {
		t.Fatalf("AppendCPF = % X", b)
	}
	got, err := encap.DecodeCPF(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, items) {
		t.Errorf("DecodeCPF = %+v", got)
	}
	if it, ok := encap.Find(got, encap.ItemUnconnectedData); !ok || len(it.Data) != 8 {
		t.Errorf("Find = %+v, %v", it, ok)
	}
	if _, ok := encap.Find(got, encap.ItemConnectedData); ok {
		t.Error("Find of an absent item ok")
	}
	if cap(got[1].Data) != len(got[1].Data) {
		t.Error("item data not capped")
	}
	if items, err := encap.DecodeCPF([]byte{0, 0}); err != nil || len(items) != 0 {
		t.Errorf("no items: %v, %v", items, err)
	}
}

func TestCPFErrors(t *testing.T) {
	if _, err := encap.AppendCPF(nil, make([]encap.Item, encap.MaxItems+1)); !errors.Is(err, encap.ErrTooLarge) {
		t.Errorf("65 items: %v", err)
	}
	if _, err := encap.AppendCPF(nil, make([]encap.Item, encap.MaxItems)); err != nil {
		t.Errorf("64 items: %v", err)
	}
	if _, err := encap.AppendCPF(nil, []encap.Item{{Type: 1, Data: make([]byte, 65536)}}); !errors.Is(err, encap.ErrTooLarge) {
		t.Errorf("item of 65536: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", encap.ErrTruncated},
		{"one octet", "01", encap.ErrTruncated},
		{"too many items", "4100", encap.ErrMalformed},
		{"item header", "0100 B200 01", encap.ErrTruncated},
		{"item data", "0100 B200 0400 010203", encap.ErrTruncated},
		{"second item missing", "0200 0000 0000", encap.ErrTruncated},
		{"trailing octets", "0100 0000 0000 FF", encap.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := encap.DecodeCPF(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestRRData(t *testing.T) {
	d := encap.RRData{
		Timeout: 10,
		Items: []encap.Item{
			{Type: encap.ItemNullAddress},
			{Type: encap.ItemUnconnectedData, Data: unhex(t, "0E 03 20 01 24 01 30 07")},
		},
	}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "00000000 0A00 0200 0000 0000 B200 0800 0E03200124013007")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := encap.DecodeRRData(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Timeout != 10 || got.InterfaceHandle != 0 || len(got.Items) != 2 || !bytes.Equal(got.Items[1].Data, d.Items[1].Data) {
		t.Errorf("DecodeRRData = %+v", got)
	}
	if _, err := encap.DecodeRRData(b[:5]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("short: %v", err)
	}
	if got, err := encap.DecodeRRData(append(b, 0)); !errors.Is(err, encap.ErrMalformed) || got.Timeout != 10 {
		t.Errorf("trailing: %+v, %v", got, err)
	}
	if _, err := (encap.RRData{Items: make([]encap.Item, 65)}).Encode(); !errors.Is(err, encap.ErrTooLarge) {
		t.Errorf("65 items: %v", err)
	}
}

func TestSockaddr(t *testing.T) {
	ap := netip.MustParseAddrPort("192.168.1.10:44818")
	s := encap.SockaddrOf(ap)
	if s.Family != encap.AFInet || s.Port != 44818 || s.Addr != [4]byte{192, 168, 1, 10} {
		t.Errorf("SockaddrOf = %+v", s)
	}
	b := s.Encode()
	// Big-endian, unlike the rest of the encapsulation.
	if want := unhex(t, "0002 AF12 C0A8010A 0000000000000000"); !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := encap.DecodeSockaddr(b)
	if err != nil || got != s || got.AddrPort() != ap {
		t.Errorf("DecodeSockaddr = %+v, %v", got, err)
	}
	if _, err := encap.DecodeSockaddr(b[:15]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("short: %v", err)
	}
	// IPv4-mapped IPv6 addresses are unmapped.
	if s := encap.SockaddrOf(netip.MustParseAddrPort("[::ffff:10.0.0.1]:2222")); s.Addr != [4]byte{10, 0, 0, 1} || s.Port != 2222 {
		t.Errorf("mapped = %+v", s)
	}
}

func TestIdentityItem(t *testing.T) {
	it := encap.IdentityItem{
		ProtocolVersion: 1,
		Socket:          encap.SockaddrOf(netip.MustParseAddrPort("192.168.1.10:44818")),
		Identity: cip.Identity{
			VendorID: 1, DeviceType: cip.DeviceTypeCommunicationsAdapter, ProductCode: 65001,
			Revision: cip.Revision{Major: 2, Minor: 3}, Status: 0x0030, SerialNumber: 0x075BCD15,
			ProductName: "OpENer PC", State: 3,
		},
	}
	b, err := it.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0100 0002AF12C0A8010A0000000000000000 0100 0C00 E9FD 02 03 3000 15CD5B07 09 4F70454E6572205043 03")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := encap.DecodeIdentityItem(b)
	if err != nil || got != it {
		t.Errorf("DecodeIdentityItem = %+v, %v", got, err)
	}

	it.ProductName = strings.Repeat("x", 256)
	if _, err := it.Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long name: %v", err)
	}
	if _, err := encap.DecodeIdentityItem(b[:1]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("1 octet: %v", err)
	}
	if _, err := encap.DecodeIdentityItem(b[:10]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("short sockaddr: %v", err)
	}
	// A truncated identity is malformed for the encapsulation and keeps
	// the cip cause.
	_, err = encap.DecodeIdentityItem(b[:30])
	if !errors.Is(err, encap.ErrMalformed) || !errors.Is(err, cip.ErrTruncated) {
		t.Errorf("short identity: %v", err)
	}
}

func TestServiceItem(t *testing.T) {
	it := encap.ServiceItem{Version: 1, Capabilities: encap.CapabilityTCP | encap.CapabilityUDP, Name: "Communications"}
	b, err := it.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0100 2001 436F6D6D756E69636174696F6E73 0000")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	if got, err := encap.DecodeServiceItem(b); err != nil || got != it {
		t.Errorf("DecodeServiceItem = %+v, %v", got, err)
	}
	// A name of exactly 16 octets has no NUL.
	it.Name = "0123456789ABCDEF"
	b, err = it.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := encap.DecodeServiceItem(b); err != nil || got.Name != it.Name {
		t.Errorf("16-octet name = %q, %v", got.Name, err)
	}
	it.Name += "X"
	if _, err := it.Encode(); !errors.Is(err, encap.ErrTooLarge) {
		t.Errorf("17-octet name: %v", err)
	}
	if _, err := encap.DecodeServiceItem(b[:19]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("short: %v", err)
	}
}

func TestSequencedAddress(t *testing.T) {
	a := encap.SequencedAddress{ConnID: 0x12345678, Sequence: 0x9ABCDEF0}
	b := a.Encode()
	if want := unhex(t, "78563412 F0DEBC9A"); !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	if got, err := encap.DecodeSequencedAddress(b); err != nil || got != a {
		t.Errorf("Decode = %+v, %v", got, err)
	}
	for _, n := range []int{0, 7, 9} {
		if _, err := encap.DecodeSequencedAddress(make([]byte, n)); !errors.Is(err, encap.ErrMalformed) {
			t.Errorf("%d octets: %v", n, err)
		}
	}
}

func TestConnectedAddress(t *testing.T) {
	it := encap.ConnectedAddress(0xDEADBEEF)
	if it.Type != encap.ItemConnectedAddress || !bytes.Equal(it.Data, unhex(t, "EFBEADDE")) {
		t.Fatalf("ConnectedAddress = %+v", it)
	}
	if id, err := encap.DecodeConnectedAddress(it); err != nil || id != 0xDEADBEEF {
		t.Errorf("Decode = %#x, %v", id, err)
	}
	if _, err := encap.DecodeConnectedAddress(encap.Item{Type: encap.ItemConnectedData, Data: it.Data}); !errors.Is(err, encap.ErrMalformed) {
		t.Errorf("wrong type: %v", err)
	}
	if _, err := encap.DecodeConnectedAddress(encap.Item{Type: encap.ItemConnectedAddress, Data: []byte{1, 2, 3}}); !errors.Is(err, encap.ErrMalformed) {
		t.Errorf("3 octets: %v", err)
	}
}
