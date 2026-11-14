// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// The allocation budget of a decoder: what one call allocates is bounded
// by its input, at most budgetFactor octets per input octet plus
// budgetBase, whatever the counts and sizes inside say.
const (
	budgetFactor = 16
	budgetBase   = 64 << 10
)

// repeat returns n copies of b.
func repeat(b []byte, n int) []byte { return bytes.Repeat(b, n) }

// symbolic is an ANSI extended symbolic segment of n octets, padded.
func symbolic(n int) []byte {
	b := append([]byte{0x91, byte(n)}, bytes.Repeat([]byte{'A'}, n)...)
	if n%2 != 0 {
		b = append(b, 0)
	}
	return b
}

// dataSegment is a simple data segment of n words.
func dataSegment(n int) []byte { return append([]byte{0x80, byte(n)}, make([]byte, 2*n)...) }

// withPath is a request of service 0x0E with path p (at most 510 octets)
// and data.
func withPath(p, data []byte) []byte {
	return append(append([]byte{0x0E, byte(len(p) / 2)}, p...), data...)
}

// TestDecodeAllocationBudget: the decoders of paths, requests, responses,
// Multiple Service Packets, Forward_Open, Unconnected_Send and identity,
// with the largest counts and sizes their fields can state, allocate
// within the budget.
func TestDecodeAllocationBudget(t *testing.T) {
	maxSvc := (0xFFFF - 2) / 2
	msp := binary.LittleEndian.AppendUint16(nil, uint16(maxSvc))
	for range maxSvc {
		msp = binary.LittleEndian.AppendUint16(msp, uint16(2+2*maxSvc))
	}
	msp = append(msp, 0x0E)
	ext := append([]byte{0x8E, 0, 0x01, 0xFF}, make([]byte, 2*0xFF)...)
	fo := func(path []byte) []byte {
		b, err := cip.ForwardOpen{Path: cip.Path{cip.ClassSegment(cip.ClassAssembly)}}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		b = b[:len(b)-2] // the encoded path
		b[len(b)-1] = byte(len(path) / 2)
		return append(b, path...)
	}
	us := func(msg, route []byte) []byte {
		b := append([]byte{0x0A, 0x0E}, binary.LittleEndian.AppendUint16(nil, uint16(len(msg)))...)
		b = append(b, msg...)
		if len(msg)%2 != 0 {
			b = append(b, 0)
		}
		return append(append(b, byte(len(route)/2), 0), route...)
	}
	identity := append(make([]byte, 14), 0xFF)
	identity = append(identity, bytes.Repeat([]byte{'N'}, 0xFF)...)
	for _, tc := range []struct {
		name   string
		in     []byte
		decode func([]byte) error
		ok     bool // the input decodes
	}{
		{"path of 256 logical segments", repeat([]byte{0x20, 0x01}, 256), budgetDecodePath, true},
		{"path of 256 symbolic segments of 255 octets", repeat(symbolic(255), 256), budgetDecodePath, true},
		{"path of 256 data segments of 255 words", repeat(dataSegment(255), 256), budgetDecodePath, true},
		{"path of 255 one-octet symbolic segments", repeat(symbolic(1), 255), budgetDecodePath, true},
		{"path of more segments than allowed", repeat([]byte{0x20, 0x01}, 0x7FFF), budgetDecodePath, false},
		{"request with the largest path and data", withPath(repeat([]byte{0x20, 0x01}, 255), make([]byte, 0xFFFF-512)), budgetDecodeRequest, true},
		{"response with 255 additional status words", ext, budgetDecodeResponse, true},
		{"response with more status words than octets", []byte{0x8E, 0, 0x01, 0xFF, 0, 0}, budgetDecodeResponse, false},
		{"Multiple Service Packet of the most services", msp, budgetSplitMultiple, true},
		{"Forward_Open with the largest path", fo(repeat([]byte{0x20, 0x01}, 255)), budgetDecodeForwardOpen, true},
		{"Unconnected_Send with the largest request and route", us(withPath(repeat(symbolic(3), 85), make([]byte, 0xFFFF-1024)), repeat([]byte{0x01, 0x00}, 255)), budgetDecodeUnconnectedSend, true},
		{"identity with the longest product name", identity, budgetDecodeIdentity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			alloc := testenv.Allocated(func() { err = tc.decode(tc.in) })
			budget := uint64(budgetFactor*len(tc.in) + budgetBase)
			t.Logf("%d octets in, %d allocated (%v)", len(tc.in), alloc, err)
			if (err == nil) != tc.ok {
				t.Fatalf("decode = %v", err)
			}
			if alloc > budget {
				t.Fatalf("%d octets allocated for %d octets of input, budget %d", alloc, len(tc.in), budget)
			}
		})
	}
}

var (
	pathSink  cip.Path
	partsSink [][]byte
	anySink   any
)

func budgetDecodePath(b []byte) (err error)    { pathSink, err = cip.DecodePath(b); return err }
func budgetSplitMultiple(b []byte) (err error) { partsSink, err = cip.SplitMultiple(b); return err }
func budgetDecodeRequest(b []byte) error       { r, err := cip.DecodeRequest(b); anySink = r; return err }
func budgetDecodeResponse(b []byte) error      { r, err := cip.DecodeResponse(b); anySink = r; return err }
func budgetDecodeForwardOpen(b []byte) error {
	r, err := cip.DecodeForwardOpen(b, false)
	anySink = r
	return err
}
func budgetDecodeIdentity(b []byte) error { r, err := cip.DecodeIdentity(b); anySink = r; return err }
func budgetDecodeUnconnectedSend(b []byte) error {
	r, err := cip.DecodeUnconnectedSend(b)
	anySink = r
	return err
}
