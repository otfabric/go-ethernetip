// SPDX-License-Identifier: MIT

package implicit

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// TestDecodeAllocationBudget: an I/O datagram allocates for its items only
// (at most encap.MaxItems; the payload aliases the input), however large
// it is, and splitting the payload allocates nothing. The budget is what
// Decode must hold, the slice of encap.MaxItems items (twice that, for the
// allocator's size classes), and an error.
func TestDecodeAllocationBudget(t *testing.T) {
	budget := 2*uint64(encap.MaxItems)*uint64(unsafe.Sizeof(encap.Item{})) + testenv.ErrorOctets
	b := binary.LittleEndian.AppendUint16(nil, encap.MaxItems)
	b = binary.LittleEndian.AppendUint16(b, uint16(encap.ItemSequencedAddress))
	b = binary.LittleEndian.AppendUint16(b, 8)
	b = append(b, 9, 0, 0, 0, 1, 0, 0, 0)
	size := (encap.MaxData - len(b)) / (encap.MaxItems - 1)
	for range encap.MaxItems - 1 {
		b = binary.LittleEndian.AppendUint16(b, uint16(encap.ItemConnectedData))
		b = binary.LittleEndian.AppendUint16(b, uint16(size-4))
		b = append(b, make([]byte, size-4)...)
	}
	var m Message
	var err error
	a := testenv.PerCall(t, 100, func() { m, err = Decode(b) })
	t.Logf("%d octets: %v, budget %d", len(b), a, budget)
	if err != nil || a.Octets > budget {
		t.Fatalf("%d octets: %v, budget %d (%v)", len(b), a, budget, err)
	}
	if n := testing.AllocsPerRun(100, func() { _, err = SplitPayload(m.Payload, 1, FormatHeader32) }); err != nil || n != 0 {
		t.Fatalf("SplitPayload: %v allocations (%v)", n, err)
	}
}
