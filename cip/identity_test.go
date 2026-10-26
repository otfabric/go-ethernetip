// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func openerIdentity() cip.Identity {
	return cip.Identity{
		VendorID:     1,
		DeviceType:   cip.DeviceTypeCommunicationsAdapter,
		ProductCode:  65001,
		Revision:     cip.Revision{Major: 2, Minor: 3},
		Status:       cip.StatusOwned | cip.StatusConfigured,
		SerialNumber: 0x075BCD15,
		ProductName:  "OpENer PC",
		State:        0xFF,
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	id := openerIdentity()
	b, err := id.AppendAttributes(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0100 0C00 E9FD 02 03 0500 15CD5B07 09 4F70454E6572205043")
	if !bytes.Equal(b, want) {
		t.Fatalf("AppendAttributes = % X", b)
	}
	got, err := cip.DecodeIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	// Without a state octet, State is 0xFF (not implemented).
	if got != id {
		t.Errorf("DecodeIdentity = %+v", got)
	}

	// A state octet directly after the name; anything after it is ignored.
	got, err = cip.DecodeIdentity(append(append([]byte(nil), b...), 3, 0xAA, 0xBB))
	if err != nil || got.State != 3 {
		t.Errorf("DecodeIdentity with state = %+v, %v", got, err)
	}

	s := id.String()
	if s != "OpENer PC (vendor 1, Communications Adapter, product 65001, rev 2.3, serial 0x075BCD15)" {
		t.Errorf("String = %q", s)
	}
}

func TestIdentityErrors(t *testing.T) {
	id := openerIdentity()
	id.ProductName = strings.Repeat("x", 256)
	if _, err := id.AppendAttributes(nil); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("long name: %v", err)
	}
	b, _ := openerIdentity().AppendAttributes(nil)
	for n := 0; n < len(b); n++ {
		if _, err := cip.DecodeIdentity(b[:n]); !errors.Is(err, cip.ErrTruncated) {
			t.Fatalf("truncated to %d: %v", n, err)
		}
	}
}

func TestIdentityStatus(t *testing.T) {
	cases := map[cip.IdentityStatus]string{
		0:      "",
		0x0001: "OWNED",
		0x0005: "OWNED|CONFIGURED",
		0x0F00: "MINOR_RECOVERABLE_FAULT|MINOR_UNRECOVERABLE_FAULT|MAJOR_RECOVERABLE_FAULT|MAJOR_UNRECOVERABLE_FAULT",
		0x00F2: "",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("IdentityStatus(%#04x) = %q, want %q", uint16(s), got, want)
		}
	}
	if e := cip.IdentityStatus(0x0035).ExtendedDeviceStatus(); e != 3 {
		t.Errorf("ExtendedDeviceStatus = %d", e)
	}
	if s := (cip.Revision{Major: 20, Minor: 11}).String(); s != "20.11" {
		t.Errorf("Revision = %q", s)
	}
}
