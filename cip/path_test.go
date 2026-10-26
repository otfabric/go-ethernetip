// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

// segmentVectors are segments with their padded and packed encodings.
var segmentVectors = []struct {
	name   string
	seg    cip.Segment
	padded string
	packed string
}{
	{"class 8", cip.LogicalSegment{Type: cip.LogicalClass, Value: 0x02, Format: cip.Format8}, "20 02", "20 02"},
	{"class 16", cip.LogicalSegment{Type: cip.LogicalClass, Value: 0x0302, Format: cip.Format16}, "21 00 02 03", "21 02 03"},
	{"instance 16", cip.LogicalSegment{Type: cip.LogicalInstance, Value: 0x1234, Format: cip.Format16}, "25 00 34 12", "25 34 12"},
	{"instance 32", cip.LogicalSegment{Type: cip.LogicalInstance, Value: 0x12345678, Format: cip.Format32}, "26 00 78 56 34 12", "26 78 56 34 12"},
	{"member 8", cip.LogicalSegment{Type: cip.LogicalMember, Value: 5, Format: cip.Format8}, "28 05", "28 05"},
	{"member 32", cip.LogicalSegment{Type: cip.LogicalMember, Value: 0x10000, Format: cip.Format32}, "2A 00 00 00 01 00", "2A 00 00 01 00"},
	{"point 8", cip.LogicalSegment{Type: cip.LogicalConnectionPoint, Value: 100, Format: cip.Format8}, "2C 64", "2C 64"},
	{"point 32", cip.LogicalSegment{Type: cip.LogicalConnectionPoint, Value: 0xDEADBEEF, Format: cip.Format32}, "2E 00 EF BE AD DE", "2E EF BE AD DE"},
	{"attribute 8", cip.LogicalSegment{Type: cip.LogicalAttribute, Value: 7, Format: cip.Format8}, "30 07", "30 07"},
	{"attribute 16", cip.LogicalSegment{Type: cip.LogicalAttribute, Value: 0x100, Format: cip.Format16}, "31 00 00 01", "31 00 01"},
	{"service 8", cip.LogicalSegment{Type: cip.LogicalServiceID, Value: 0x0E, Format: cip.Format8}, "38 0E", "38 0E"},
	{"backplane slot 0", cip.PortSegment{Port: 1, Link: []byte{0}}, "01 00", "01 00"},
	{"port 2 IP", cip.PortSegment{Port: 2, Link: []byte("192.168.1.10")}, "12 0C 3139322E3136382E312E3130", "12 0C 3139322E3136382E312E3130"},
	{"port 2 odd link", cip.PortSegment{Port: 2, Link: []byte("abc")}, "12 03 616263 00", "12 03 616263"},
	{"port 18", cip.PortSegment{Port: 18, Link: []byte{5}}, "0F 12 00 05", "0F 12 00 05"},
	{"port 20 extended", cip.PortSegment{Port: 20, Link: []byte{0xAA, 0xBB}}, "1F 02 14 00 AA BB", "1F 02 14 00 AA BB"},
	{"port 20 extended odd", cip.PortSegment{Port: 20, Link: []byte{1, 2, 3}}, "1F 03 14 00 01 02 03 00", "1F 03 14 00 01 02 03"},
	{"port 15", cip.PortSegment{Port: 15, Link: []byte{9}}, "0F 0F 00 09", "0F 0F 00 09"},
	{"key", cip.KeySegment{VendorID: 1, DeviceType: 12, ProductCode: 65001, Major: 2, Minor: 3, Compatible: true}, "34 04 0100 0C00 E9FD 82 03", "34 04 0100 0C00 E9FD 82 03"},
	{"key exact", cip.KeySegment{VendorID: 0x1337, Major: 1}, "34 04 3713 0000 0000 01 00", "34 04 3713 0000 0000 01 00"},
	{"symbol odd", cip.SymbolSegment{Name: "Tag"}, "91 03 546167 00", "91 03 546167"},
	{"symbol even", cip.SymbolSegment{Name: "Ab"}, "91 02 4162", "91 02 4162"},
	{"data", cip.DataSegment{Data: []byte{1, 2, 3, 4}}, "80 02 01020304", "80 02 01020304"},
	{"network inhibit", cip.NetworkSegment{Subtype: cip.NetworkProductionInhibit, Data: []byte{10}}, "43 0A", "43 0A"},
	{"network extended", cip.NetworkSegment{Subtype: 0x10, Data: []byte{0xAA, 0xBB}}, "50 01 AABB", "50 01 AABB"},
}

func TestSegmentVectors(t *testing.T) {
	for _, v := range segmentVectors {
		t.Run(v.name, func(t *testing.T) {
			p := cip.Path{v.seg}
			for _, packed := range []bool{false, true} {
				want := unhex(t, v.padded)
				dec := cip.DecodePath
				if packed {
					want = unhex(t, v.packed)
					dec = cip.DecodePacked
				}
				got, err := p.AppendTo(nil, packed)
				if err != nil {
					t.Fatalf("packed=%v encode: %v", packed, err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("packed=%v encode = % X, want % X", packed, got, want)
				}
				back, err := dec(want)
				if err != nil {
					t.Fatalf("packed=%v decode: %v", packed, err)
				}
				if !reflect.DeepEqual(back, p) {
					t.Errorf("packed=%v decode = %#v, want %#v", packed, back, p)
				}
			}
		})
	}
}

func TestEncodeHelpers(t *testing.T) {
	p := cip.Path{cip.ClassSegment(cip.ClassAssembly), cip.InstanceSegment(0x97), cip.ConnectionPointSegment(0x96), cip.ConnectionPointSegment(0x64)}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// OpENer's exclusive owner connection path.
	if want := unhex(t, "20 04 24 97 2C 96 2C 64"); !bytes.Equal(b, want) {
		t.Errorf("Encode = % X, want % X", b, want)
	}
	if n, err := p.Words(); n != 4 || err != nil {
		t.Errorf("Words = %d, %v", n, err)
	}
	pk, err := p.EncodePacked()
	if err != nil || !bytes.Equal(pk, b) {
		t.Errorf("EncodePacked = % X, %v", pk, err)
	}

	cases := []struct {
		p    cip.Path
		want string
	}{
		{cip.AttributePath(cip.ClassIdentity, 1, 7), "20 01 24 01 30 07"},
		{cip.MessageRouterPath(), "20 02 24 01"},
		{cip.ConnectionManagerPath(), "20 06 24 01"},
		{cip.ObjectPath(cip.ClassAssembly, 0x1234), "20 04 25 00 34 12"},
		{cip.ObjectPath(0x300, 0x12345), "21 00 00 03 26 00 45 23 01 00"},
		{cip.Path{cip.SymbolSegment{Name: "Arr"}, cip.MemberSegment(300)}, "91 03 417272 00 29 00 2C 01"},
	}
	for _, c := range cases {
		b, err := c.p.Encode()
		if err != nil {
			t.Fatalf("%v: %v", c.p, err)
		}
		if want := unhex(t, c.want); !bytes.Equal(b, want) {
			t.Errorf("%v = % X, want % X", c.p, b, want)
		}
	}
}

func TestDecodeReservedFormat3(t *testing.T) {
	// pycomm3 sends logical format 3 for 32-bit instances.
	p, err := cip.DecodePath(unhex(t, "20 6B 27 00 78 56 34 12"))
	if err != nil {
		t.Fatal(err)
	}
	want := cip.Path{
		cip.LogicalSegment{Type: cip.LogicalClass, Value: 0x6B, Format: cip.Format8},
		cip.LogicalSegment{Type: cip.LogicalInstance, Value: 0x12345678, Format: cip.Format32},
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("DecodePath = %#v", p)
	}
	p, err = cip.DecodePacked(unhex(t, "27 78 56 34 12"))
	if err != nil || !reflect.DeepEqual(p, want[1:]) {
		t.Errorf("DecodePacked = %#v, %v", p, err)
	}
}

func TestDecodeExtendedSymbolic(t *testing.T) {
	p, err := cip.DecodePath(unhex(t, "63 414243"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, cip.Path{cip.SymbolSegment{Name: "ABC"}}) {
		t.Errorf("DecodePath = %#v", p)
	}
}

func TestDecodePortPaddingAtEnd(t *testing.T) {
	// A padded port segment at the end of a path may omit its pad octet.
	p, err := cip.DecodePath(unhex(t, "12 03 616263"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, cip.Path{cip.PortSegment{Port: 2, Link: []byte("abc")}}) {
		t.Errorf("DecodePath = %#v", p)
	}
}

func TestDecodePathErrors(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		packed bool
		want   error
	}{
		{"segment type 5", "A0 00", false, cip.ErrMalformed},
		{"segment type 7", "E0 00", false, cip.ErrMalformed},
		{"logical type 5", "35 00 01 00", false, cip.ErrMalformed},
		{"logical type 7", "3C 01", false, cip.ErrMalformed},
		// 32-bit class, attribute and service IDs are not defined; read as
		// such they would be truncated to 16 bits by Path.Class and
		// Path.Attribute (class 0x00010001 taken for Identity).
		{"32-bit class", "22 00 01 00 01 00", false, cip.ErrMalformed},
		{"32-bit class format 3", "23 01 00 01 00", true, cip.ErrMalformed},
		{"32-bit attribute", "32 00 07 00 01 00", false, cip.ErrMalformed},
		{"32-bit service", "3A 00 0E 00 00 00", false, cip.ErrMalformed},
		{"key format", "34 05 0100 0C00 E9FD 82 03", false, cip.ErrMalformed},
		{"key truncated", "34 04 01", false, cip.ErrTruncated},
		{"key format truncated", "34", false, cip.ErrTruncated},
		{"empty extended symbol", "60", false, cip.ErrMalformed},
		{"unknown data segment", "81 00", false, cip.ErrMalformed},
		{"empty symbol", "91 00", false, cip.ErrMalformed},
		{"symbol truncated", "91 05 4142", false, cip.ErrTruncated},
		{"port 0 extended", "0F 00 00 05", false, cip.ErrMalformed},
		{"port 0", "00 05", false, cip.ErrMalformed},
		{"port empty link", "11 00", false, cip.ErrMalformed},
		{"port truncated", "12 05 41", false, cip.ErrTruncated},
		{"logical truncated", "20", false, cip.ErrTruncated},
		{"logical 16 truncated", "25 00 34", false, cip.ErrTruncated},
		{"logical 32 truncated", "26 78 56 34", true, cip.ErrTruncated},
		{"data truncated", "80 02 01", false, cip.ErrTruncated},
		{"network truncated", "43", false, cip.ErrTruncated},
		{"network extended truncated", "50 02 AABB", false, cip.ErrTruncated},
	}
	for _, c := range cases {
		dec := cip.DecodePath
		if c.packed {
			dec = cip.DecodePacked
		}
		if p, err := dec(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: DecodePath(%s) = %v, %v; want %v", c.name, c.in, p, err, c.want)
		}
	}
}

func TestDecodePathTooManySegments(t *testing.T) {
	b := bytes.Repeat([]byte{0x20, 0x01}, 257)
	if _, err := cip.DecodePath(b); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("257 segments: %v", err)
	}
	if p, err := cip.DecodePath(b[:512]); err != nil || len(p) != 256 {
		t.Errorf("256 segments: %d, %v", len(p), err)
	}
	if p, err := cip.DecodePath(nil); err != nil || p != nil {
		t.Errorf("empty path: %v, %v", p, err)
	}
}

func TestEncodeSegmentErrors(t *testing.T) {
	cases := []struct {
		name string
		seg  cip.Segment
		want error
	}{
		{"logical type 5", cip.LogicalSegment{Type: 5, Value: 1}, cip.ErrMalformed},
		{"logical type 8", cip.LogicalSegment{Type: 8, Value: 1}, cip.ErrMalformed},
		{"8 bits too small", cip.LogicalSegment{Type: cip.LogicalInstance, Value: 300, Format: cip.Format8}, cip.ErrTooLarge},
		{"16 bits too small", cip.LogicalSegment{Type: cip.LogicalInstance, Value: 70000, Format: cip.Format16}, cip.ErrTooLarge},
		{"32-bit class", cip.LogicalSegment{Type: cip.LogicalClass, Value: 70000}, cip.ErrMalformed},
		{"32-bit attribute", cip.LogicalSegment{Type: cip.LogicalAttribute, Value: 1, Format: cip.Format32}, cip.ErrMalformed},
		{"bad format", cip.LogicalSegment{Type: cip.LogicalInstance, Value: 1, Format: 9}, cip.ErrMalformed},
		{"key major", cip.KeySegment{Major: 0x80}, cip.ErrTooLarge},
		{"port 0", cip.PortSegment{Port: 0, Link: []byte{0}}, cip.ErrMalformed},
		{"port empty link", cip.PortSegment{Port: 1}, cip.ErrMalformed},
		{"port long link", cip.PortSegment{Port: 1, Link: make([]byte, 256)}, cip.ErrMalformed},
		{"empty symbol", cip.SymbolSegment{}, cip.ErrMalformed},
		{"long symbol", cip.SymbolSegment{Name: strings.Repeat("a", 256)}, cip.ErrMalformed},
		{"odd data", cip.DataSegment{Data: []byte{1}}, cip.ErrMalformed},
		{"long data", cip.DataSegment{Data: make([]byte, 512)}, cip.ErrMalformed},
		{"network subtype", cip.NetworkSegment{Subtype: 0x20, Data: []byte{1}}, cip.ErrMalformed},
		{"network short 2 octets", cip.NetworkSegment{Subtype: 3, Data: []byte{1, 2}}, cip.ErrMalformed},
		{"network extended odd", cip.NetworkSegment{Subtype: 0x10, Data: []byte{1}}, cip.ErrMalformed},
	}
	for _, c := range cases {
		for _, packed := range []bool{false, true} {
			b, err := cip.Path{cip.ClassSegment(1), c.seg}.AppendTo([]byte{0xEE}, packed)
			if !errors.Is(err, c.want) {
				t.Errorf("%s packed=%v: %v, want %v", c.name, packed, err, c.want)
			}
			// What was appended before the failing segment is kept.
			if !bytes.HasPrefix(b, []byte{0xEE, 0x20, 0x01}) {
				t.Errorf("%s: prefix lost: % X", c.name, b)
			}
		}
	}
	if _, err := (cip.Path{cip.ClassSegment(1), nil}).Encode(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("nil segment: %v", err)
	}
}

func TestAutoFormat(t *testing.T) {
	cases := []struct {
		seg  cip.LogicalSegment
		want string
	}{
		{cip.InstanceSegment(0xFF), "24 FF"},
		{cip.InstanceSegment(0x100), "25 00 00 01"},
		{cip.InstanceSegment(0xFFFF), "25 00 FF FF"},
		{cip.InstanceSegment(0x10000), "26 00 00 00 01 00"},
		{cip.AttributeSegment(0xFFFF), "31 00 FF FF"},
		{cip.ClassSegment(0x10A), "21 00 0A 01"},
		{cip.LogicalSegment{Type: cip.LogicalInstance, Value: 1, Format: cip.Format32}, "26 00 01 00 00 00"},
	}
	for _, c := range cases {
		b, err := cip.Path{c.seg}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := unhex(t, c.want); !bytes.Equal(b, want) {
			t.Errorf("%v = % X, want % X", c.seg, b, want)
		}
	}
}

func TestPathWordsErrors(t *testing.T) {
	if _, err := (cip.Path{cip.PortSegment{}}).Words(); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad segment: %v", err)
	}
	// 255 words of data plus the segment header: 256 words.
	big := cip.Path{cip.DataSegment{Data: make([]byte, 510)}}
	if _, err := big.Words(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("256 words: %v", err)
	}
	ok := cip.Path{cip.DataSegment{Data: make([]byte, 508)}}
	if n, err := ok.Words(); n != 255 || err != nil {
		t.Errorf("255 words: %d, %v", n, err)
	}
}

func TestPathAccessors(t *testing.T) {
	p := cip.Path{
		cip.PortSegment{Port: 1, Link: []byte{0}},
		cip.ClassSegment(cip.ClassAssembly),
		cip.InstanceSegment(100),
		cip.MemberSegment(3),
		cip.AttributeSegment(3),
		cip.InstanceSegment(200),
	}
	if c, ok := p.Class(); c != cip.ClassAssembly || !ok {
		t.Errorf("Class = %v, %v", c, ok)
	}
	if i, ok := p.Instance(); i != 100 || !ok {
		t.Errorf("Instance = %v, %v (want the first)", i, ok)
	}
	if a, ok := p.Attribute(); a != 3 || !ok {
		t.Errorf("Attribute = %v, %v", a, ok)
	}
	if m, ok := p.Member(); m != 3 || !ok {
		t.Errorf("Member = %v, %v", m, ok)
	}
	if p.Symbolic() {
		t.Error("Symbolic = true")
	}

	var empty cip.Path
	if _, ok := empty.Class(); ok {
		t.Error("empty Class ok")
	}
	if _, ok := empty.Attribute(); ok {
		t.Error("empty Attribute ok")
	}
	if empty.Symbolic() {
		t.Error("empty Symbolic")
	}

	sym := cip.Path{cip.SymbolSegment{Name: "Tag"}, cip.MemberSegment(1)}
	if c, ok := sym.Class(); c != cip.ClassSymbol || !ok {
		t.Errorf("symbolic Class = %v, %v", c, ok)
	}
	if !sym.Symbolic() {
		t.Error("Symbolic = false")
	}
}

func TestPathString(t *testing.T) {
	cases := []struct {
		p    cip.Path
		want string
	}{
		{cip.AttributePath(cip.ClassIdentity, 1, 7), "@1/1/7"},
		{cip.ObjectPath(cip.ClassAssembly, 100), "@4/100"},
		{cip.Path{cip.ClassSegment(cip.ClassTemplate)}, "@108"},
		{cip.Path{cip.InstanceSegment(1)}, "[instance 1]"},
		{cip.Path{cip.ClassSegment(4), cip.ConnectionPointSegment(100)}, "[class 0x04] [point 100]"},
		{cip.Path{cip.ClassSegment(4), cip.InstanceSegment(1), cip.AttributeSegment(3), cip.MemberSegment(2)}, "[class 0x04] [instance 1] [attribute 3] [member 2]"},
		{cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}, cip.PortSegment{Port: 2, Link: []byte("10.0.0.1")}}, "[port 1:0] [port 2:10.0.0.1]"},
		{cip.Path{cip.PortSegment{Port: 3, Link: []byte{0, 1, 0xFF}}}, "[port 3:0x0001ff]"},
		{cip.Path{cip.SymbolSegment{Name: "MyTag"}, nil}, "[symbol MyTag] [nil]"},
		{cip.Path{cip.KeySegment{VendorID: 1, DeviceType: 12, ProductCode: 65001, Major: 2, Minor: 3}}, "[key 1/12/65001 2.3]"},
		{cip.Path{cip.KeySegment{VendorID: 1, Compatible: true}}, "[key 1/0/0 0.0 compatible]"},
		{cip.Path{cip.DataSegment{Data: []byte{1, 2}}}, "[data 0102]"},
		{cip.Path{cip.NetworkSegment{Subtype: 3, Data: []byte{10}}}, "[network 0x43 0a]"},
		{cip.Path{cip.LogicalSegment{Type: cip.LogicalServiceID, Value: 14}}, "[service 14]"},
		{cip.Path{cip.LogicalSegment{Type: 5, Value: 1}}, "[logical-5 1]"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("String = %q, want %q", got, c.want)
		}
	}
}

func TestParsePath(t *testing.T) {
	cases := []struct {
		in   string
		want cip.Path
	}{
		{"@4/100/3", cip.AttributePath(cip.ClassAssembly, 100, 3)},
		{" @0x04/0x64/3 ", cip.AttributePath(cip.ClassAssembly, 100, 3)},
		{"@1/1", cip.ObjectPath(cip.ClassIdentity, 1)},
		{"@6", cip.Path{cip.ClassSegment(cip.ClassConnectionManager)}},
		{"@1/4294967295", cip.ObjectPath(cip.ClassIdentity, 0xFFFFFFFF)},
		{"20 04 24 64 30 03", cip.Path{
			cip.LogicalSegment{Type: cip.LogicalClass, Value: 4, Format: cip.Format8},
			cip.LogicalSegment{Type: cip.LogicalInstance, Value: 100, Format: cip.Format8},
			cip.LogicalSegment{Type: cip.LogicalAttribute, Value: 3, Format: cip.Format8},
		}},
		{"20012401", cip.Path{
			cip.LogicalSegment{Type: cip.LogicalClass, Value: 1, Format: cip.Format8},
			cip.LogicalSegment{Type: cip.LogicalInstance, Value: 1, Format: cip.Format8},
		}},
	}
	for _, c := range cases {
		p, err := cip.ParsePath(c.in)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(p, c.want) {
			t.Errorf("ParsePath(%q) = %#v, want %#v", c.in, p, c.want)
		}
	}

	errs := []struct {
		in   string
		want error
	}{
		{"@", cip.ErrMalformed},
		{"@1/2/3/4", cip.ErrMalformed},
		{"@x/1", cip.ErrMalformed},
		{"@65536/1", cip.ErrMalformed},
		{"@1/4294967296", cip.ErrMalformed},
		{"@1/1/65536", cip.ErrMalformed},
		{"@-1", cip.ErrMalformed},
		{"zz", cip.ErrMalformed},
		{"201", cip.ErrMalformed},
		{"20", cip.ErrTruncated},
		{"A0 00", cip.ErrMalformed},
	}
	for _, c := range errs {
		if p, err := cip.ParsePath(c.in); !errors.Is(err, c.want) {
			t.Errorf("ParsePath(%q) = %v, %v; want %v", c.in, p, err, c.want)
		}
	}
}

func TestParsePathRoundTripString(t *testing.T) {
	for _, s := range []string{"@1/1/7", "@4/100", "@108", "@6/1"} {
		p, err := cip.ParsePath(s)
		if err != nil {
			t.Fatal(err)
		}
		if p.String() != s {
			t.Errorf("ParsePath(%q).String() = %q", s, p.String())
		}
	}
}

func TestParseRoute(t *testing.T) {
	cases := []struct {
		in   string
		want cip.Path
	}{
		{"", nil},
		{"  ", nil},
		{"1/0", cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}}},
		{"1/0, 2/192.168.1.10", cip.Path{
			cip.PortSegment{Port: 1, Link: []byte{0}},
			cip.PortSegment{Port: 2, Link: []byte("192.168.1.10")},
		}},
		{"18/0x05", cip.Path{cip.PortSegment{Port: 18, Link: []byte{5}}}},
		{"2/300", cip.Path{cip.PortSegment{Port: 2, Link: []byte("300")}}},
	}
	for _, c := range cases {
		p, err := cip.ParseRoute(c.in)
		if err != nil {
			t.Fatalf("ParseRoute(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(p, c.want) {
			t.Errorf("ParseRoute(%q) = %#v, want %#v", c.in, p, c.want)
		}
	}
	// The backplane route encodes as pycomm3 and RSLinx send it.
	p, _ := cip.ParseRoute("1/0")
	if b, err := p.Encode(); err != nil || !bytes.Equal(b, []byte{1, 0}) {
		t.Errorf("route 1/0 = % X, %v", b, err)
	}

	for _, s := range []string{"1", "0/1", "x/1", "1/", "65536/1", "1/0,,2/1"} {
		if p, err := cip.ParseRoute(s); !errors.Is(err, cip.ErrMalformed) {
			t.Errorf("ParseRoute(%q) = %v, %v; want ErrMalformed", s, p, err)
		}
	}
}

func TestLogicalTypeString(t *testing.T) {
	want := map[cip.LogicalType]string{
		cip.LogicalClass: "class", cip.LogicalInstance: "instance", cip.LogicalMember: "member",
		cip.LogicalConnectionPoint: "point", cip.LogicalAttribute: "attribute", cip.LogicalServiceID: "service",
		7: "logical-7",
	}
	for lt, s := range want {
		if lt.String() != s {
			t.Errorf("LogicalType(%d) = %q, want %q", lt, lt.String(), s)
		}
	}
}
