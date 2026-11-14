// SPDX-License-Identifier: MIT

package implicit

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// TestDecodeAllocationBudget: an I/O datagram allocates for its items only
// (at most encap.MaxItems; the payload aliases the input), however large
// it is, and splitting the payload allocates nothing.
func TestDecodeAllocationBudget(t *testing.T) {
	const budget = 4 << 10
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
	if alloc := testenv.Allocated(func() { m, err = Decode(b) }); err != nil || alloc > budget {
		t.Fatalf("%d octets: %d allocated, budget %d (%v)", len(b), alloc, budget, err)
	}
	if n := testing.AllocsPerRun(100, func() { _, err = SplitPayload(m.Payload, 1, FormatHeader32) }); err != nil || n != 0 {
		t.Fatalf("SplitPayload: %v allocations (%v)", n, err)
	}
}
