// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestRequestGetAttributeSingle(t *testing.T) {
	req := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)}
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0E 03 20 01 24 01 30 07")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X, want % X", b, want)
	}
	if s := req.String(); s != "Get_Attribute_Single @1/1/7" {
		t.Errorf("String = %q", s)
	}

	got, err := cip.DecodeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	if got.Service != cip.ServiceGetAttributeSingle || got.Path.String() != "@1/1/7" || len(got.Data) != 0 {
		t.Errorf("DecodeRequest = %+v", got)
	}

	// AppendTo appends after existing content.
	b, err = req.AppendTo([]byte{0xAA})
	if err != nil || !bytes.Equal(b, append([]byte{0xAA}, want...)) {
		t.Errorf("AppendTo = % X, %v", b, err)
	}
}

func TestRequestWithData(t *testing.T) {
	// Set_Attribute_Single of an assembly's data attribute.
	req := cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, 150, 3), Data: []byte{1, 2, 3}}
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "10 03 20 04 24 96 30 03 010203"); !bytes.Equal(b, want) {
		t.Errorf("Encode = % X", b)
	}
	got, err := cip.DecodeRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, []byte{1, 2, 3}) || got.Service != req.Service {
		t.Errorf("DecodeRequest = %+v", got)
	}

	sym := cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{cip.SymbolSegment{Name: "Tag"}}, Data: []byte{1, 0}}
	if s := sym.String(); s != "Read_Tag [symbol Tag]" {
		t.Errorf("String = %q", s)
	}
	b, err = sym.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "4C 03 91 03 546167 00 0100"); !bytes.Equal(b, want) {
		t.Errorf("Read_Tag = % X", b)
	}
}

func TestRequestErrors(t *testing.T) {
	prefix := []byte{0xAA}
	b, err := cip.Request{Service: 0x8E, Path: cip.MessageRouterPath()}.AppendTo(prefix)
	if !errors.Is(err, cip.ErrMalformed) || !bytes.Equal(b, prefix) {
		t.Errorf("reply bit: %v, % X", err, b)
	}
	b, err = cip.Request{Service: 0x0E, Path: cip.Path{cip.PortSegment{}}}.AppendTo(prefix)
	if !errors.Is(err, cip.ErrMalformed) || !bytes.Equal(b, prefix) {
		t.Errorf("bad path: %v, % X", err, b)
	}
	big := cip.Path{cip.DataSegment{Data: make([]byte, 510)}}
	b, err = cip.Request{Service: 0x0E, Path: big}.AppendTo(prefix)
	if !errors.Is(err, cip.ErrTooLarge) || !bytes.Equal(b, prefix) {
		t.Errorf("256-word path: %v, len %d", err, len(b))
	}

	cases := []struct {
		in   string
		want error
	}{
		{"", cip.ErrTruncated},
		{"0E", cip.ErrTruncated},
		{"0E 03 20 01", cip.ErrTruncated},
		{"8E 01 20 01", cip.ErrMalformed},
		{"0E 01 A0 00", cip.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := cip.DecodeRequest(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("DecodeRequest(%s) = %v, want %v", c.in, err, c.want)
		}
	}
}

func TestResponse(t *testing.T) {
	// Get_Attribute_Single reply with a UINT.
	in := unhex(t, "8E 00 00 00 0100")
	r, err := cip.DecodeResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Service != cip.ServiceGetAttributeSingle || !r.OK() || r.Extended != nil || !bytes.Equal(r.Data, []byte{1, 0}) {
		t.Errorf("DecodeResponse = %+v", r)
	}
	if b, err := r.Encode(); err != nil || !bytes.Equal(b, in) {
		t.Errorf("Encode = % X, %v", b, err)
	}

	// Forward_Open failure: connection failure, extended status
	// "connection in use", then the triad.
	in = unhex(t, "D4 00 01 01 0001 0100 3713 21436587 00 00")
	r, err = cip.DecodeResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Service != cip.ServiceForwardOpen || r.OK() || r.Status != cip.StatusConnectionFailure {
		t.Errorf("DecodeResponse = %+v", r)
	}
	if !reflect.DeepEqual(r.Extended, []uint16{uint16(cip.ConnStatusInUse)}) {
		t.Errorf("Extended = %v", r.Extended)
	}
	f, err := cip.DecodeConnectionFailure(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	if f.Serial != 1 || f.VendorID != 0x1337 || f.OriginatorSerial != 0x87654321 {
		t.Errorf("ConnectionFailure = %+v", f)
	}
	if b, err := r.Encode(); err != nil || !bytes.Equal(b, in) {
		t.Errorf("Encode = % X, %v", b, err)
	}

	er := cip.ErrorResponse(cip.Request{Service: cip.ServiceGetAttributeSingle}, cip.StatusPathDestinationUnknown, 0x0001)
	b, err := er.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "8E 00 05 01 0100"); !bytes.Equal(b, want) {
		t.Errorf("ErrorResponse = % X", b)
	}
}

func TestResponseErrors(t *testing.T) {
	if _, err := (cip.Response{Extended: make([]uint16, 256)}).Encode(); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("256 extended words: %v", err)
	}
	cases := []struct {
		in   string
		want error
	}{
		{"", cip.ErrTruncated},
		{"8E 00 00", cip.ErrTruncated},
		{"8E 00 01 02 0100", cip.ErrTruncated},
		{"8E 00 01 01 01", cip.ErrTruncated},
		{"0E 00 00 00", cip.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := cip.DecodeResponse(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("DecodeResponse(%s) = %v, want %v", c.in, err, c.want)
		}
	}
}

func TestMultipleService(t *testing.T) {
	reqs := []cip.Request{
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)},
	}
	b, err := cip.EncodeMultipleService(reqs)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0200 0600 0E00 0E03200124013001 0E03200124013007")
	if !bytes.Equal(b, want) {
		t.Fatalf("EncodeMultipleService = % X, want % X", b, want)
	}
	parts, err := cip.SplitMultiple(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("SplitMultiple = %d parts", len(parts))
	}
	for i, p := range parts {
		r, err := cip.DecodeRequest(p)
		if err != nil {
			t.Fatal(err)
		}
		if r.Path.String() != reqs[i].Path.String() {
			t.Errorf("part %d = %v", i, r)
		}
		// The parts are capped: appending to one cannot overwrite the next.
		if cap(p) != len(p) {
			t.Errorf("part %d cap %d len %d", i, cap(p), len(p))
		}
	}

	resps := []cip.Response{
		{Service: cip.ServiceGetAttributeSingle, Data: []byte{1, 0}},
		{Service: cip.ServiceGetAttributeSingle, Status: cip.StatusAttributeNotSupported},
	}
	b, err = cip.EncodeMultipleServiceResponse(resps)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0200 0600 0C00 8E000000 0100 8E001400"); !bytes.Equal(b, want) {
		t.Fatalf("EncodeMultipleServiceResponse = % X, want % X", b, want)
	}
	parts, err = cip.SplitMultiple(b)
	if err != nil || len(parts) != 2 {
		t.Fatalf("SplitMultiple = %v, %v", parts, err)
	}
	r, err := cip.DecodeResponse(parts[1])
	if err != nil || r.Status != cip.StatusAttributeNotSupported {
		t.Errorf("response 1 = %+v, %v", r, err)
	}

	b, err = cip.EncodeMultipleServiceResponse(nil)
	if err != nil || !bytes.Equal(b, []byte{0, 0}) {
		t.Errorf("empty response = % X, %v", b, err)
	}
	if parts, err := cip.SplitMultiple(b); parts != nil || err != nil {
		t.Errorf("SplitMultiple(empty) = %v, %v", parts, err)
	}
}

func TestMultipleServiceErrors(t *testing.T) {
	if _, err := cip.EncodeMultipleService(nil); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("no requests: %v", err)
	}
	if _, err := cip.EncodeMultipleService([]cip.Request{{Service: 0x8E}}); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("bad request: %v", err)
	}
	if _, err := cip.EncodeMultipleServiceResponse([]cip.Response{{Extended: make([]uint16, 300)}}); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("bad response: %v", err)
	}
	// The offset of the third request does not fit 16 bits.
	big := make([]byte, 33000)
	reqs := []cip.Request{
		{Service: 0x10, Path: cip.MessageRouterPath(), Data: big},
		{Service: 0x10, Path: cip.MessageRouterPath(), Data: big},
		{Service: 0x10, Path: cip.MessageRouterPath(), Data: big},
	}
	if _, err := cip.EncodeMultipleService(reqs[:2]); err != nil {
		t.Errorf("offsets within 16 bits: %v", err)
	}
	if _, err := cip.EncodeMultipleService(reqs); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("offset overflow: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", cip.ErrTruncated},
		{"one octet", "02", cip.ErrTruncated},
		{"count beyond data", "0300 0800 0A00", cip.ErrTruncated},
		{"offset in offset table", "0200 0200 0600 0E00", cip.ErrMalformed},
		{"offsets decreasing", "0200 0800 0600 0E00 0E00", cip.ErrMalformed},
		{"offset beyond data", "0100 0900 0E00", cip.ErrMalformed},
		// Two equal offsets beyond the data: this used to panic slicing
		// b[off:off] past its capacity.
		{"equal offsets beyond data", "0200 3030 3030", cip.ErrMalformed},
		{"next offset beyond data", "0200 0600 3030 0E00", cip.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := cip.SplitMultiple(unhex(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: SplitMultiple(%s) = %v, want %v", c.name, c.in, err, c.want)
		}
	}
	// Equal offsets give an empty message, which is accepted.
	parts, err := cip.SplitMultiple(unhex(t, "0200 0600 0600 0E00"))
	if err != nil || len(parts[0]) != 0 || !bytes.Equal(parts[1], []byte{0x0E, 0}) {
		t.Errorf("equal offsets: %v, %v", parts, err)
	}
}
