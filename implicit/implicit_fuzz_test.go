// SPDX-License-Identifier: MIT

package implicit

import (
	"bytes"
	"testing"
)

func FuzzDecodeImplicit(f *testing.F) {
	f.Add(unhex(f, "0200 0280 0800 78563412 03000000 B100 0A00 0200 01000000 AABBCCDD"))
	f.Add(unhex(f, "0200 0280 0800 01000000 01000000 B100 0000"))
	f.Add(unhex(f, "0300 0180 1000 0002AF12C0A8010A0000000000000000 0280 0800 01000000 01000000 B100 0200 0100"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		enc, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m2, err := Decode(enc)
		if err != nil || m2.ConnID != m.ConnID || m2.EncapSeq != m.EncapSeq || !bytes.Equal(m2.Payload, m.Payload) {
			t.Fatalf("round trip: %+v, %v", m2, err)
		}
		for class := uint8(0); class <= 1; class++ {
			for f := FormatModeless; f <= FormatHeader32; f++ {
				p, err := SplitPayload(m.Payload, class, f)
				if err != nil {
					if len(m.Payload) >= f.Overhead(class) {
						t.Fatalf("class %d %s: %v", class, f, err)
					}
					continue
				}
				if len(p.Data)+f.Overhead(class) != len(m.Payload) {
					t.Fatalf("class %d %s: %d data octets of %d", class, f, len(p.Data), len(m.Payload))
				}
				// Formats with data rebuild the payload exactly.
				if f == FormatModeless || f == FormatHeader32 {
					if got := AppendPayload(nil, class, f, p); !bytes.Equal(got, m.Payload) {
						t.Fatalf("class %d %s: AppendPayload = % X, want % X", class, f, got, m.Payload)
					}
				}
			}
		}
	})
}
