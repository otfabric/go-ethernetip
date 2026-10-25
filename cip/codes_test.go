// SPDX-License-Identifier: MIT

package cip_test

import (
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestClassString(t *testing.T) {
	cases := map[cip.Class]string{
		cip.ClassIdentity:          "Identity",
		cip.ClassConnectionManager: "Connection Manager",
		cip.ClassTemplate:          "Template (Rockwell)",
		cip.ClassLLDPDataTable:     "LLDP Data Table",
		0x1234:                     "class 0x1234",
		0xC9:                       "class 0xC9",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Class(%#x) = %q, want %q", uint16(c), got, want)
		}
	}
	if !cip.ClassSymbol.VendorSpecific() || !cip.ClassTemplate.VendorSpecific() {
		t.Error("Logix classes not vendor specific")
	}
	if cip.ClassIdentity.VendorSpecific() {
		t.Error("Identity vendor specific")
	}
}

func TestServiceString(t *testing.T) {
	cases := map[cip.Service]string{
		cip.ServiceGetAttributeSingle:              "Get_Attribute_Single",
		cip.ServiceGetAttributeSingle | 0x80:       "Get_Attribute_Single",
		cip.ServiceMultipleServicePacket:           "Multiple_Service_Packet",
		cip.ServiceForwardOpen:                     "Forward_Open",
		cip.ServiceLargeForwardOpen:                "Large_Forward_Open",
		cip.ServiceWriteTagFragmented:              "Write_Tag_Fragmented",
		cip.ServiceGetInstanceAttributeList | 0x80: "Get_Instance_Attribute_List",
		// Codes several classes define are not named without the class.
		0x4C: "service 0x4C",
		0x4E: "service 0x4E",
		0x52: "service 0x52",
		0x40: "service 0x40",
		0x7F: "service 0x7F",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Service(%#x) = %q, want %q", uint8(s), got, want)
		}
	}
}

func TestServiceName(t *testing.T) {
	cases := []struct {
		c    cip.Class
		s    cip.Service
		want string
	}{
		{cip.ClassSymbol, 0x4C, "Read_Tag"},
		{cip.ClassTemplate, 0x4C, "Read_Template"},
		{cip.ClassTemplate, 0xCC, "Read_Template"},
		{cip.ClassConnectionManager, 0x4E, "Forward_Close"},
		{cip.ClassSymbol, 0x4E, "Read_Modify_Write_Tag"},
		{cip.ClassConnectionManager, 0x52, "Unconnected_Send"},
		{cip.ClassSymbol, 0x52, "Read_Tag_Fragmented"},
		{cip.ClassIdentity, 0x0E, "Get_Attribute_Single"},
		{cip.ClassIdentity, 0x4C, "service 0x4C"},
		{cip.ClassIdentity, 0x54, "Forward_Open"},
	}
	for _, c := range cases {
		if got := cip.ServiceName(c.c, c.s); got != c.want {
			t.Errorf("ServiceName(%v, %#x) = %q, want %q", c.c, uint8(c.s), got, c.want)
		}
	}
}

func TestStatusStrings(t *testing.T) {
	gs := map[cip.GeneralStatus]string{
		cip.StatusSuccess:                "success",
		cip.StatusConnectionFailure:      "connection failure",
		cip.StatusPathDestinationUnknown: "path destination unknown",
		cip.StatusGeneralError:           "general error (vendor specific)",
		0xF0:                             "general status 0xF0",
	}
	for s, want := range gs {
		if got := s.String(); got != want {
			t.Errorf("GeneralStatus(%#x) = %q, want %q", uint8(s), got, want)
		}
	}
	if cip.StatusPathDestinationUnknown != 0x05 || cip.StatusConnectionFailure != 0x01 {
		t.Error("general status codes changed")
	}

	cs := map[cip.ConnectionStatus]string{
		cip.ConnStatusInUse:          "connection in use or duplicate forward open",
		cip.ConnStatusInvalidSegment: "invalid segment in connection path",
		0xBEEF:                       "connection status 0xBEEF",
	}
	for s, want := range cs {
		if got := s.String(); got != want {
			t.Errorf("ConnectionStatus(%#x) = %q, want %q", uint16(s), got, want)
		}
	}

	ds := map[cip.DeviceType]string{
		cip.DeviceTypeCommunicationsAdapter: "Communications Adapter",
		0x0E:                                "Programmable Logic Controller",
		0x9999:                              "device type 0x9999",
	}
	for d, want := range ds {
		if got := d.String(); got != want {
			t.Errorf("DeviceType(%#x) = %q, want %q", uint16(d), got, want)
		}
	}
}

func TestVendorName(t *testing.T) {
	cases := map[uint16]string{
		1:     "Rockwell Automation/Allen-Bradley",
		2:     "Namco Controls Corp.",
		9876:  "ODVA",
		6:     "",
		0:     "",
		65535: "",
	}
	for id, want := range cases {
		if got := cip.VendorName(id); got != want {
			t.Errorf("VendorName(%d) = %q, want %q", id, got, want)
		}
	}
}

func TestDataType(t *testing.T) {
	cases := []struct {
		t                                  cip.DataType
		name                               string
		size                               int
		integer, signed, float, str, known bool
	}{
		{cip.TypeBOOL, "BOOL", 1, false, false, false, false, true},
		{cip.TypeSINT, "SINT", 1, true, true, false, false, true},
		{cip.TypeDINT, "DINT", 4, true, true, false, false, true},
		{cip.TypeLINT, "LINT", 8, true, true, false, false, true},
		{cip.TypeUDINT, "UDINT", 4, true, false, false, false, true},
		{cip.TypeDWORD, "DWORD", 4, true, false, false, false, true},
		{cip.TypeREAL, "REAL", 4, false, false, true, false, true},
		{cip.TypeLREAL, "LREAL", 8, false, false, true, false, true},
		{cip.TypeSTRING, "STRING", 0, false, false, false, true, true},
		{cip.TypeShortString, "SHORT_STRING", 0, false, false, false, true, true},
		{cip.TypeDateAndTime, "DATE_AND_TIME", 6, false, false, false, false, true},
		{cip.TypeEPATH, "EPATH", 0, false, false, false, false, true},
		{0x00, "type 0x00", 0, false, false, false, false, false},
		{0xA0, "type 0xA0", 0, false, false, false, false, false},
	}
	for _, c := range cases {
		if c.t.String() != c.name || c.t.Size() != c.size || c.t.IsInteger() != c.integer ||
			c.t.IsSigned() != c.signed || c.t.IsFloat() != c.float || c.t.IsString() != c.str || c.t.Known() != c.known {
			t.Errorf("%s: size %d int %v signed %v float %v string %v known %v", c.t, c.t.Size(),
				c.t.IsInteger(), c.t.IsSigned(), c.t.IsFloat(), c.t.IsString(), c.t.Known())
		}
	}

	// Every known type parses back from its name.
	n := 0
	for i := 0; i < 256; i++ {
		dt := cip.DataType(i)
		if !dt.Known() {
			continue
		}
		n++
		if got, ok := cip.ParseDataType(dt.String()); !ok || got != dt {
			t.Errorf("ParseDataType(%q) = %v, %v", dt.String(), got, ok)
		}
	}
	if n < 20 {
		t.Errorf("only %d known types", n)
	}
	for _, s := range []string{"dint", "", "type 0x00", "UNKNOWN"} {
		if _, ok := cip.ParseDataType(s); ok {
			t.Errorf("ParseDataType(%q) ok", s)
		}
	}
}
