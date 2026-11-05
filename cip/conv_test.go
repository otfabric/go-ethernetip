// SPDX-License-Identifier: MIT

package cip

import (
	"errors"
	"math"
	"testing"
)

func TestLengthConversions(t *testing.T) {
	for _, c := range []struct {
		n      int
		v8     uint8
		ok8    bool
		v16    uint16
		ok16   bool
		words  uint8
		okWord bool
	}{
		{-1, 0, false, 0, false, 0, false},
		{0, 0, true, 0, true, 0, true},
		{1, 1, true, 1, true, 0, false},
		{math.MaxUint8, math.MaxUint8, true, math.MaxUint8, true, 0, false},
		{math.MaxUint8 + 1, 0, false, math.MaxUint8 + 1, true, 128, true},
		{2 * math.MaxUint8, 0, false, 2 * math.MaxUint8, true, math.MaxUint8, true},
		{2*math.MaxUint8 + 2, 0, false, 2*math.MaxUint8 + 2, true, 0, false},
		{math.MaxUint16, 0, false, math.MaxUint16, true, 0, false},
		{math.MaxUint16 + 1, 0, false, 0, false, 0, false},
	} {
		if v, ok := len8(c.n); v != c.v8 || ok != c.ok8 {
			t.Errorf("len8(%d) = %d, %v", c.n, v, ok)
		}
		if v, ok := len16(c.n); v != c.v16 || ok != c.ok16 {
			t.Errorf("len16(%d) = %d, %v", c.n, v, ok)
		}
		if v, ok := words8(c.n); v != c.words || ok != c.okWord {
			t.Errorf("words8(%d) = %d, %v", c.n, v, ok)
		}
	}
}

func TestPackMultipleCount(t *testing.T) {
	if _, err := packMultiple(make([][]byte, math.MaxUint16+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("65536 messages: %v", err)
	}
}
