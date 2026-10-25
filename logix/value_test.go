// SPDX-License-Identifier: MIT

package logix

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestValueIntsRoundTrip(t *testing.T) {
	cases := []struct {
		t        cip.DataType
		min, max int64
	}{
		{cip.TypeSINT, math.MinInt8, math.MaxInt8},
		{cip.TypeINT, math.MinInt16, math.MaxInt16},
		{cip.TypeITIME, math.MinInt16, math.MaxInt16},
		{cip.TypeDINT, math.MinInt32, math.MaxInt32},
		{cip.TypeSTIME, math.MinInt32, math.MaxInt32},
		{cip.TypeFTIME, math.MinInt32, math.MaxInt32},
		{cip.TypeTIME, math.MinInt32, math.MaxInt32},
		{cip.TypeLINT, math.MinInt64, math.MaxInt64},
		{cip.TypeLTIME, math.MinInt64, math.MaxInt64},
		{cip.TypeUSINT, 0, math.MaxUint8},
		{cip.TypeBYTE, 0, math.MaxUint8},
		{cip.TypeUINT, 0, math.MaxUint16},
		{cip.TypeWORD, 0, math.MaxUint16},
		{cip.TypeUDINT, 0, math.MaxUint32},
		{cip.TypeDWORD, 0, math.MaxUint32},
		{cip.TypeULINT, 0, math.MaxInt64},
		{cip.TypeLWORD, 0, math.MaxInt64},
	}
	for _, c := range cases {
		v, err := Ints(c.t, c.min, c.max, 1)
		if err != nil {
			t.Fatalf("%s: %v", c.t, err)
		}
		if v.Count != 3 || len(v.Data) != 3*c.t.Size() || v.ElemSize() != c.t.Size() || v.IsStruct() {
			t.Fatalf("%s: %+v", c.t, v)
		}
		for i, want := range []int64{c.min, c.max, 1} {
			got, err := v.Int(i)
			if err != nil || got != want {
				t.Fatalf("%s[%d] = %d, %v; want %d", c.t, i, got, err, want)
			}
		}
		if c.t.IsSigned() {
			if _, err := v.Uint(0); !errors.Is(err, ErrType) {
				t.Fatalf("%s: Uint of signed: %v", c.t, err)
			}
			if c.t.Size() < 8 {
				if _, err := Ints(c.t, c.max+1); !errors.Is(err, ErrType) {
					t.Fatalf("%s: max+1 accepted", c.t)
				}
				if _, err := Ints(c.t, c.min-1); !errors.Is(err, ErrType) {
					t.Fatalf("%s: min-1 accepted", c.t)
				}
			}
		} else {
			u, err := v.Uint(1)
			if err != nil || u != uint64(c.max) {
				t.Fatalf("%s: Uint %d %v", c.t, u, err)
			}
			if _, err := Ints(c.t, -1); !errors.Is(err, ErrType) {
				t.Fatalf("%s: -1 accepted", c.t)
			}
			if c.t.Size() < 8 {
				if _, err := Ints(c.t, c.max+1); !errors.Is(err, ErrType) {
					t.Fatalf("%s: max+1 accepted", c.t)
				}
			}
		}
		if _, err := v.Int(3); !errors.Is(err, ErrType) {
			t.Fatalf("%s: element 3 of 3: %v", c.t, err)
		}
		if _, err := v.Int(-1); !errors.Is(err, ErrType) {
			t.Fatalf("%s: element -1: %v", c.t, err)
		}
		if _, err := v.Uint(3); !errors.Is(err, ErrType) {
			t.Fatalf("%s: Uint element 3: %v", c.t, err)
		}
	}
}

func TestValueUlintAboveInt64(t *testing.T) {
	v := Value{Type: cip.TypeULINT, Count: 1, Data: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}
	if u, err := v.Uint(0); err != nil || u != math.MaxUint64 {
		t.Fatalf("Uint %d %v", u, err)
	}
	if _, err := v.Int(0); !errors.Is(err, ErrType) {
		t.Fatalf("Int of MaxUint64: %v", err)
	}
}

func TestValueBool(t *testing.T) {
	v, err := Ints(cip.TypeBOOL, 0, 5, -1)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Data) != "\x00\xff\xff" {
		t.Fatalf("BOOL encoding %x", v.Data)
	}
	for i, want := range []bool{false, true, true} {
		if b, err := v.Bool(i); err != nil || b != want {
			t.Fatalf("Bool(%d) = %v %v", i, b, err)
		}
		n, err := v.Int(i)
		if err != nil || (n == 1) != want {
			t.Fatalf("Int(%d) = %d %v", i, n, err)
		}
	}
	if _, err := v.Bool(3); !errors.Is(err, ErrType) {
		t.Fatalf("Bool(3): %v", err)
	}
	if _, err := v.Uint(0); !errors.Is(err, ErrType) {
		t.Fatalf("Uint of BOOL: %v", err)
	}
	d := Value{Type: cip.TypeDINT, Count: 1, Data: []byte{1, 0, 0, 0}}
	if _, err := d.Bool(0); !errors.Is(err, ErrType) {
		t.Fatalf("Bool of DINT: %v", err)
	}
}

func TestValueDwordBits(t *testing.T) {
	v, _ := Ints(cip.TypeDWORD, 1<<31|1<<3, 1<<0)
	for i, want := range map[int]bool{0: false, 3: true, 31: true, 32: true, 33: false, 63: false} {
		if b, err := v.Bool(i); err != nil || b != want {
			t.Fatalf("bit %d = %v %v", i, b, err)
		}
	}
	if _, err := v.Bool(64); !errors.Is(err, ErrType) {
		t.Fatalf("bit 64: %v", err)
	}
	// A negative bit used to panic with a negative shift.
	if _, err := v.Bool(-1); !errors.Is(err, ErrType) {
		t.Fatalf("bit -1: %v", err)
	}
}

func TestValueFloats(t *testing.T) {
	r, err := Floats(cip.TypeREAL, 1.5, -2)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Floats(cip.TypeLREAL, math.Pi)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := r.Float(1); err != nil || f != -2 {
		t.Fatalf("REAL %v %v", f, err)
	}
	if f, err := l.Float(0); err != nil || f != math.Pi {
		t.Fatalf("LREAL %v %v", f, err)
	}
	if _, err := r.Float(2); !errors.Is(err, ErrType) {
		t.Fatalf("REAL[2]: %v", err)
	}
	if _, err := r.Int(0); !errors.Is(err, ErrType) {
		t.Fatalf("Int of REAL: %v", err)
	}
	d, _ := Ints(cip.TypeDINT, 1)
	if _, err := d.Float(0); !errors.Is(err, ErrType) {
		t.Fatalf("Float of DINT: %v", err)
	}
	if _, err := Floats(cip.TypeDINT, 1); !errors.Is(err, ErrType) {
		t.Fatalf("Floats DINT: %v", err)
	}
	// The type is checked even without values.
	if _, err := Floats(cip.TypeDINT); !errors.Is(err, ErrType) {
		t.Fatalf("Floats DINT without values: %v", err)
	}
	if _, err := Ints(cip.TypeREAL, 1); !errors.Is(err, ErrType) {
		t.Fatalf("Ints REAL: %v", err)
	}
}

func TestValueStrings(t *testing.T) {
	v, err := Strings("", "hello", strings.Repeat("x", StringCapacity))
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsStruct() || v.Handle != StringHandle || v.ElemSize() != StringSize || len(v.Data) != 3*StringSize {
		t.Fatalf("%+v", v)
	}
	for i, want := range []string{"", "hello", strings.Repeat("x", StringCapacity)} {
		if s, err := v.Text(i); err != nil || s != want {
			t.Fatalf("Text(%d) = %q %v", i, s, err)
		}
	}
	if _, err := v.Text(3); !errors.Is(err, ErrType) {
		t.Fatalf("Text(3): %v", err)
	}
	if _, err := Strings(strings.Repeat("x", StringCapacity+1)); !errors.Is(err, ErrType) {
		t.Fatalf("83 characters: %v", err)
	}
	bad := Value{Handle: StringHandle, Count: 1, Data: make([]byte, StringSize)}
	bad.Data[0] = StringCapacity + 1
	if _, err := bad.Text(0); !errors.Is(err, ErrType) {
		t.Fatalf("length 83: %v", err)
	}
	bad.Data[3] = 0x80 // negative length
	if _, err := bad.Text(0); !errors.Is(err, ErrType) {
		t.Fatalf("negative length: %v", err)
	}
	d, _ := Ints(cip.TypeDINT, 1)
	if _, err := d.Text(0); !errors.Is(err, ErrType) {
		t.Fatalf("Text of DINT: %v", err)
	}
}

func TestValueStringAndElemSize(t *testing.T) {
	v, _ := Ints(cip.TypeDINT, 1, 2)
	if s := v.String(); s != "DINT[2] 0100000002000000" {
		t.Fatalf("String %q", s)
	}
	st := Value{Handle: 0xBEEF, Count: 1, Data: []byte{0xAB}}
	if s := st.String(); s != "struct 0xBEEF[1] ab" {
		t.Fatalf("String %q", s)
	}
	empty := Value{Handle: 1}
	if empty.ElemSize() != 0 {
		t.Fatal("ElemSize of struct with Count 0")
	}
	if _, err := empty.Int(0); !errors.Is(err, ErrType) {
		t.Fatalf("element of empty struct: %v", err)
	}
	short := Value{Type: cip.TypeDINT, Count: 2, Data: []byte{1, 0, 0, 0}}
	if _, err := short.Int(1); !errors.Is(err, ErrType) {
		t.Fatalf("element beyond data: %v", err)
	}
	b := st.appendType(nil)
	if string(b) != "\xa0\x02\xef\xbe" {
		t.Fatalf("struct type code %x", b)
	}
	typ, h := decodeType(cip.NewReader(b))
	if typ != 0 || h != 0xBEEF {
		t.Fatalf("decodeType %v %x", typ, h)
	}
	typ, h = decodeType(cip.NewReader(v.appendType(nil)))
	if typ != cip.TypeDINT || h != 0 {
		t.Fatalf("decodeType %v %x", typ, h)
	}
}
