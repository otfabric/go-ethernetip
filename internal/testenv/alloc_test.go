// SPDX-License-Identifier: MIT

package testenv

import "testing"

var sink []byte

func TestAllocated(t *testing.T) {
	if n := Allocated(func() { sink = make([]byte, 1<<20) }); n < 1<<20 || n > 2<<20 {
		t.Errorf("1 MiB allocation measured as %d octets", n)
	}
	sink = nil
}
