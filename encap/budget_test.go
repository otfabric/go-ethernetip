// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// cpf returns a common packet format of n items of size octets each.
func cpf(n, size int) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(n))
	for range n {
		b = binary.LittleEndian.AppendUint16(b, uint16(encap.ItemConnectedData))
		b = binary.LittleEndian.AppendUint16(b, uint16(size))
		b = append(b, make([]byte, size)...)
	}
	return b
}

// TestCPFAllocationBudget: a common packet format allocates for its items
// only (at most MaxItems of them; the data alias the input), whatever the
// count field says.
func TestCPFAllocationBudget(t *testing.T) {
	const budget = 4 << 10
	for _, tc := range []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"MaxItems empty items", cpf(encap.MaxItems, 0), true},
		{"MaxItems items in the largest packet", cpf(encap.MaxItems, (encap.MaxData-2)/encap.MaxItems-4), true},
		{"a count above MaxItems", append(binary.LittleEndian.AppendUint16(nil, 0xFFFF), make([]byte, 4*encap.MaxItems)...), false},
		{"MaxItems announced, none present", binary.LittleEndian.AppendUint16(nil, encap.MaxItems), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			alloc := testenv.Allocated(func() { _, err = encap.DecodeCPF(tc.in) })
			if (err == nil) != tc.ok {
				t.Fatalf("DecodeCPF = %v", err)
			}
			if alloc > budget {
				t.Fatalf("%d octets allocated for %d octets of input, budget %d", alloc, len(tc.in), budget)
			}
		})
	}
}

// TestReadPacketAllocationBudget: ReadPacket allocates for at most the
// header and the limit it is given (twice that, for the allocator's size
// classes), whatever length the header states; a buffer large enough is
// reused.
func TestReadPacketAllocationBudget(t *testing.T) {
	header := func(length uint16) []byte {
		h := encap.Header{Command: encap.CommandSendRRData, Length: length}
		return h.AppendTo(nil)
	}
	for _, tc := range []struct {
		name   string
		stream []byte
		max    int
	}{
		{"largest length, no data", header(encap.MaxData), 0},
		{"largest packet", append(header(encap.MaxData), make([]byte, encap.MaxData)...), 0},
		{"length above the limit", header(encap.MaxData), 4096},
		{"packet at the limit", append(header(4096), make([]byte, 4096)...), 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := tc.max
			if limit == 0 {
				limit = encap.MaxData
			}
			budget := uint64(2*(encap.HeaderSize+limit)) + 4096
			alloc := testenv.Allocated(func() { _, _, _ = encap.ReadPacket(bytes.NewReader(tc.stream), nil, tc.max) })
			if alloc > budget {
				t.Fatalf("%d octets allocated, budget %d", alloc, budget)
			}
			buf := make([]byte, 0, encap.HeaderSize+limit)
			if alloc := testenv.Allocated(func() { _, _, _ = encap.ReadPacket(bytes.NewReader(tc.stream), buf, tc.max) }); alloc > 4096 {
				t.Fatalf("%d octets allocated with a large enough buffer", alloc)
			}
		})
	}
}
