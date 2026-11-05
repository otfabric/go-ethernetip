// SPDX-License-Identifier: MIT

package logix

import (
	"errors"
	"math"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestUints(t *testing.T) {
	v, err := Uints(cip.TypeULINT, math.MaxUint64, 1<<63, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint64{math.MaxUint64, 1 << 63, 0} {
		if got, err := v.Uint(i); err != nil || got != want {
			t.Errorf("element %d: %d, %v", i, got, err)
		}
	}
	if v, err := Uints(cip.TypeUSINT, 0xFF); err != nil || len(v.Data) != 1 || v.Data[0] != 0xFF {
		t.Errorf("USINT: %v %v", v, err)
	}
	if v, err := Uints(cip.TypeLWORD, math.MaxUint64); err != nil || len(v.Data) != 8 {
		t.Errorf("LWORD: %v %v", v, err)
	}
	for _, c := range []struct {
		t cip.DataType
		x uint64
	}{{cip.TypeUSINT, 0x100}, {cip.TypeUINT, 0x10000}, {cip.TypeUDINT, 1 << 32}, {cip.TypeDINT, 1}, {cip.TypeREAL, 1}, {cip.TypeBOOL, 1}} {
		if _, err := Uints(c.t, c.x); !errors.Is(err, ErrType) {
			t.Errorf("Uints(%s, %d): %v", c.t, c.x, err)
		}
	}
}

func TestFloatsREALRange(t *testing.T) {
	for _, x := range []float64{3.5e38, -3.5e38, math.MaxFloat64} {
		if _, err := Floats(cip.TypeREAL, x); !errors.Is(err, ErrType) {
			t.Errorf("REAL %g: %v", x, err)
		}
	}
	for _, x := range []float64{math.MaxFloat32, -math.MaxFloat32, math.Inf(1), math.Inf(-1), 1e-50, 0.1} {
		v, err := Floats(cip.TypeREAL, x)
		if err != nil {
			t.Errorf("REAL %g: %v", x, err)
			continue
		}
		if got, _ := v.Float(0); got != float64(float32(x)) {
			t.Errorf("REAL %g: %g", x, got)
		}
	}
	if v, err := Floats(cip.TypeREAL, math.NaN()); err != nil {
		t.Error(err)
	} else if got, _ := v.Float(0); !math.IsNaN(got) {
		t.Errorf("NaN: %g", got)
	}
	if _, err := Floats(cip.TypeLREAL, math.MaxFloat64); err != nil {
		t.Errorf("LREAL: %v", err)
	}
}
