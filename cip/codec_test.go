// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

// unhex decodes a hex string with optional spaces.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestReaderValues(t *testing.T) {
	var b []byte
	b = cip.AppendUint8(b, 0xFE)
	b = cip.AppendUint16(b, 0xFFFE)
	b = cip.AppendUint32(b, 0xFFFFFFFD)
	b = cip.AppendUint64(b, 0xFFFFFFFFFFFFFFFC)
	b = cip.AppendFloat32(b, 1.5)
	b = cip.AppendFloat64(b, -2.25)
	b = cip.AppendUint8(b, 0x7F)
	b = cip.AppendUint16(b, 0x1234)
	b = cip.AppendUint32(b, 0x12345678)
	b = cip.AppendUint64(b, 0x0102030405060708)

	// Little-endian layout check of the first values.
	if want := unhex(t, "FE FEFF FDFFFFFF FCFFFFFFFFFFFFFF 0000C03F"); !bytes.Equal(b[:19], want) {
		t.Fatalf("encoding = % X, want % X", b[:19], want)
	}

	r := cip.NewReader(b)
	if v := r.Int8(); v != -2 {
		t.Errorf("Int8 = %d", v)
	}
	if v := r.Int16(); v != -2 {
		t.Errorf("Int16 = %d", v)
	}
	if v := r.Int32(); v != -3 {
		t.Errorf("Int32 = %d", v)
	}
	if v := r.Int64(); v != -4 {
		t.Errorf("Int64 = %d", v)
	}
	if v := r.Float32(); v != 1.5 {
		t.Errorf("Float32 = %v", v)
	}
	if v := r.Float64(); v != -2.25 {
		t.Errorf("Float64 = %v", v)
	}
	if v := r.Uint8(); v != 0x7F {
		t.Errorf("Uint8 = %#x", v)
	}
	if v := r.Uint16(); v != 0x1234 {
		t.Errorf("Uint16 = %#x", v)
	}
	if v := r.Uint32(); v != 0x12345678 {
		t.Errorf("Uint32 = %#x", v)
	}
	if r.Offset() != len(b)-8 || r.Len() != 8 {
		t.Errorf("Offset/Len = %d/%d", r.Offset(), r.Len())
	}
	if v := r.Uint64(); v != 0x0102030405060708 {
		t.Errorf("Uint64 = %#x", v)
	}
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d", r.Len())
	}
}

func TestReaderSticky(t *testing.T) {
	r := cip.NewReader([]byte{1, 2, 3})
	if v := r.Uint16(); v != 0x0201 {
		t.Fatalf("Uint16 = %#x", v)
	}
	if v := r.Uint32(); v != 0 {
		t.Errorf("truncated Uint32 = %#x, want 0", v)
	}
	if !errors.Is(r.Err(), cip.ErrTruncated) {
		t.Fatalf("Err = %v, want ErrTruncated", r.Err())
	}
	first := r.Err()
	// The remaining octet is no longer readable: the error is sticky.
	if v := r.Uint8(); v != 0 {
		t.Errorf("Uint8 after error = %d, want 0", v)
	}
	if r.Uint16() != 0 || r.Uint64() != 0 || r.Bytes(1) != nil || r.Rest() != nil {
		t.Error("reads after error returned data")
	}
	if r.ShortString() != "" || r.String() != "" || r.String2() != "" {
		t.Error("string reads after error returned data")
	}
	r.Fail(errors.New("other"))
	if r.Err() != first {
		t.Errorf("Fail replaced the first error: %v", r.Err())
	}
	if r.Offset() != 2 {
		t.Errorf("Offset = %d, want 2", r.Offset())
	}
}

func TestReaderBytesSkipRest(t *testing.T) {
	r := cip.NewReader([]byte{1, 2, 3, 4, 5})
	if got := r.Bytes(2); !bytes.Equal(got, []byte{1, 2}) {
		t.Errorf("Bytes = %v", got)
	}
	r.Skip(1)
	if got := r.Rest(); !bytes.Equal(got, []byte{4, 5}) {
		t.Errorf("Rest = %v", got)
	}
	if r.Err() != nil || r.Len() != 0 {
		t.Fatalf("Err = %v, Len = %d", r.Err(), r.Len())
	}
	// Rest of nothing is empty, not an error.
	if got := r.Rest(); len(got) != 0 || r.Err() != nil {
		t.Errorf("Rest at end = %v, %v", got, r.Err())
	}

	r = cip.NewReader([]byte{1})
	if r.Bytes(-1) != nil || !errors.Is(r.Err(), cip.ErrTruncated) {
		t.Errorf("Bytes(-1): %v", r.Err())
	}

	r = cip.NewReader(nil)
	r.Fail(cip.ErrMalformed)
	if !errors.Is(r.Err(), cip.ErrMalformed) {
		t.Errorf("Fail: %v", r.Err())
	}
}

func TestStrings(t *testing.T) {
	b, err := cip.AppendShortString(nil, "OpENer PC")
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{9}, "OpENer PC"...); !bytes.Equal(b, want) {
		t.Errorf("SHORT_STRING = % X", b)
	}
	b, err = cip.AppendString(b, "Tag")
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{3, 0}, "Tag"...); !bytes.Equal(b[10:], want) {
		t.Errorf("STRING = % X", b[10:])
	}
	b, err = cip.AppendString2(b, "Aé€")
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0300 4100 E900 AC20"); !bytes.Equal(b[15:], want) {
		t.Errorf("STRING2 = % X, want % X", b[15:], want)
	}

	r := cip.NewReader(b)
	if s := r.ShortString(); s != "OpENer PC" {
		t.Errorf("ShortString = %q", s)
	}
	if s := r.String(); s != "Tag" {
		t.Errorf("String = %q", s)
	}
	if s := r.String2(); s != "Aé€" {
		t.Errorf("String2 = %q", s)
	}
	if r.Err() != nil || r.Len() != 0 {
		t.Fatalf("Err = %v, Len = %d", r.Err(), r.Len())
	}
}

func TestString2Surrogates(t *testing.T) {
	// A lone high surrogate, a low surrogate and an ordinary character.
	r := cip.NewReader(unhex(t, "0300 00D8 FFDF 4100"))
	if s := r.String2(); s != "��A" {
		t.Errorf("String2 = %q, want replacement characters", s)
	}
	if r.Err() != nil {
		t.Fatal(r.Err())
	}

	// Two characters announced, one present.
	r = cip.NewReader(unhex(t, "0200 4100"))
	if s := r.String2(); s != "" || !errors.Is(r.Err(), cip.ErrTruncated) {
		t.Errorf("truncated String2 = %q, %v", s, r.Err())
	}
}

func TestAppendStringErrors(t *testing.T) {
	prefix := []byte{0xAA}
	if b, err := cip.AppendShortString(prefix, strings.Repeat("x", 256)); !errors.Is(err, cip.ErrTooLarge) || !bytes.Equal(b, prefix) {
		t.Errorf("SHORT_STRING of 256: %v, % X", err, b)
	}
	if _, err := cip.AppendShortString(nil, strings.Repeat("x", 255)); err != nil {
		t.Errorf("SHORT_STRING of 255: %v", err)
	}
	if b, err := cip.AppendString(prefix, strings.Repeat("x", math.MaxUint16+1)); !errors.Is(err, cip.ErrTooLarge) || !bytes.Equal(b, prefix) {
		t.Errorf("STRING of 65536: %v", err)
	}
	if _, err := cip.AppendString2(nil, strings.Repeat("x", math.MaxUint16+1)); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("STRING2 of 65536: %v", err)
	}
	// U+1F600 is outside the BMP: UCS-2 cannot carry it.
	if _, err := cip.AppendString2(nil, "a\U0001F600"); !errors.Is(err, cip.ErrMalformed) {
		t.Errorf("STRING2 non-BMP: %v", err)
	}
}

func TestShortStringTruncated(t *testing.T) {
	r := cip.NewReader([]byte{5, 'a', 'b'})
	if s := r.ShortString(); s != "" || !errors.Is(r.Err(), cip.ErrTruncated) {
		t.Errorf("ShortString = %q, %v", s, r.Err())
	}
	r = cip.NewReader([]byte{5, 0, 'a'})
	if s := r.String(); s != "" || !errors.Is(r.Err(), cip.ErrTruncated) {
		t.Errorf("String = %q, %v", s, r.Err())
	}
}
