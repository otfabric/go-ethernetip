// SPDX-License-Identifier: MIT

package encap

import (
	"math"
	"testing"
)

func TestLen16(t *testing.T) {
	for _, c := range []struct {
		n  int
		v  uint16
		ok bool
	}{
		{-1, 0, false},
		{0, 0, true},
		{math.MaxUint16, math.MaxUint16, true},
		{math.MaxUint16 + 1, 0, false},
	} {
		if v, ok := len16(c.n); v != c.v || ok != c.ok {
			t.Errorf("len16(%d) = %d, %v", c.n, v, ok)
		}
	}
}
