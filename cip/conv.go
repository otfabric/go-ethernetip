// SPDX-License-Identifier: MIT

package cip

import "math"

// len8 converts a length to the USINT that encodes it, reporting false when
// it does not fit.
func len8(n int) (uint8, bool) {
	if n < 0 {
		return 0, false
	}
	if n > math.MaxUint8 {
		return 0, false
	}
	return uint8(n), true
}

// len16 converts a length to the UINT that encodes it, reporting false when
// it does not fit.
func len16(n int) (uint16, bool) {
	if n < 0 {
		return 0, false
	}
	if n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}

// words8 converts a length in octets to the USINT word count that encodes
// it, reporting false when the length is odd or the count does not fit.
func words8(n int) (uint8, bool) {
	if n%2 != 0 {
		return 0, false
	}
	return len8(n / 2)
}
