// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

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

// budgetRuns is the number of calls an allocation measurement averages.
const budgetRuns = 100

// TestCPFAllocationBudget: a common packet format allocates for its items
// only (at most MaxItems of them; the data alias the input), whatever the
// count field says. The budget is what DecodeCPF must hold, the slice of
// MaxItems items (twice that, for the allocator's size classes), and an
// error.
func TestCPFAllocationBudget(t *testing.T) {
	budget := 2*uint64(encap.MaxItems)*uint64(unsafe.Sizeof(encap.Item{})) + testenv.ErrorOctets
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
			a := testenv.PerCall(t, budgetRuns, func() { _, err = encap.DecodeCPF(tc.in) })
			t.Logf("%v, budget %d", a, budget)
			if (err == nil) != tc.ok {
				t.Fatalf("DecodeCPF = %v", err)
			}
			if a.Octets > budget {
				t.Fatalf("%v for %d octets of input, budget %d", a, len(tc.in), budget)
			}
		})
	}
}

// TestReadPacketAllocationBudget: ReadPacket allocates for at most the
// header and the limit it is given (twice that, for the allocator's size
// classes), whatever length the header states; a buffer large enough is
// reused, and then only the reader and an error are allocated.
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
			budget := uint64(2*(encap.HeaderSize+limit)) + testenv.ErrorOctets
			a := testenv.PerCall(t, budgetRuns, func() { _, _, _ = encap.ReadPacket(bytes.NewReader(tc.stream), nil, tc.max) })
			t.Logf("%v, budget %d", a, budget)
			if a.Octets > budget {
				t.Fatalf("%v, budget %d", a, budget)
			}
			buf := make([]byte, 0, encap.HeaderSize+limit)
			a = testenv.PerCall(t, budgetRuns, func() { _, _, _ = encap.ReadPacket(bytes.NewReader(tc.stream), buf, tc.max) })
			t.Logf("with a large enough buffer: %v, budget %d", a, testenv.ErrorOctets)
			if a.Octets > testenv.ErrorOctets {
				t.Fatalf("%v with a large enough buffer, budget %d", a, testenv.ErrorOctets)
			}
		})
	}
}
