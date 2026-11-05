// SPDX-License-Identifier: MIT

package scanner

import (
	"math"
	"testing"
	"time"
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
