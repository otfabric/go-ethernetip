// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/otfabric/go-ethernetip/encap"
)

func FuzzDecodeHeader(f *testing.F) {
	f.Add(unhex(f, registerRequest))
	f.Add(unhex(f, "6F00 1000 44332211 00000000 0000000000000000 00000000 00000000 0A00 0000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := encap.DecodeHeader(b)
		if err != nil {
			if len(b) >= encap.HeaderSize {
				t.Fatalf("%d octets: %v", len(b), err)
			}
			return
		}
		if enc := h.AppendTo(nil); !bytes.Equal(enc, b[:encap.HeaderSize]) {
			t.Fatalf("round trip: % X != % X", enc, b[:encap.HeaderSize])
		}
		p, err := encap.Decode(b)
		if err != nil {
			return
		}
		enc, err := p.Encode()
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("packet round trip: % X, %v", enc, err)
		}
	})
}

func FuzzReadPacket(f *testing.F) {
	f.Add(unhex(f, registerRequest), uint16(0))
	f.Add(append(unhex(f, registerRequest), unhex(f, registerRequest)...), uint16(4))
	f.Add(unhex(f, registerRequest)[:26], uint16(100))
	f.Fuzz(func(t *testing.T, b []byte, max uint16) {
		r := bytes.NewReader(b)
		var buf []byte
		read := 0
		for {
			p, nb, err := encap.ReadPacket(r, buf, int(max))
			buf = nb
			if err != nil {
				if errors.Is(err, encap.ErrTooLarge) {
					if max != 0 && int(p.Length) <= int(max) {
						t.Fatalf("ErrTooLarge for %d <= %d", p.Length, max)
					}
				} else if err != io.EOF && err != io.ErrUnexpectedEOF {
					t.Fatalf("error %v", err)
				}
				if err == io.EOF && read != len(b) {
					t.Fatalf("io.EOF after %d of %d octets", read, len(b))
				}
				return
			}
			n := encap.HeaderSize + len(p.Data)
			if int(p.Length) != len(p.Data) {
				t.Fatalf("length %d with %d octets", p.Length, len(p.Data))
			}
			// The packet is exactly what the stream carried.
			q, err := encap.Decode(b[read : read+n])
			if err != nil || q.Header != p.Header || !bytes.Equal(q.Data, p.Data) {
				t.Fatalf("ReadPacket and Decode disagree: %v", err)
			}
			read += n
		}
	})
}

func FuzzDecodeCPF(f *testing.F) {
	f.Add(unhex(f, "0200 0000 0000 B200 0800 0E03200124013007"))
	f.Add(unhex(f, "0200 0280 0800 01000000 02000000 B100 0400 01000000"))
	f.Add(unhex(f, "0000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		items, err := encap.DecodeCPF(b)
		if err != nil {
			return
		}
		if len(items) > encap.MaxItems {
			t.Fatalf("%d items", len(items))
		}
		enc, err := encap.AppendCPF(nil, items)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("round trip: % X, %v", enc, err)
		}
		if d, err := encap.DecodeRRData(append(make([]byte, 6), b...)); err != nil || !reflect.DeepEqual(d.Items, items) {
			t.Fatalf("DecodeRRData disagrees: %v", err)
		}
	})
}

func FuzzDecodeIdentityItem(f *testing.F) {
	f.Add(unhex(f, "0100 0002AF12C0A8010A0000000000000000 0100 0C00 E9FD 02 03 3000 15CD5B07 09 4F70454E6572205043 03"))
	f.Add(unhex(f, "0100 0002AF12C0A8010A0000000000000000 0100 0C00 E9FD 02 03 3000 15CD5B07 00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		it, err := encap.DecodeIdentityItem(b)
		if err != nil {
			return
		}
		enc, err := it.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := encap.DecodeIdentityItem(enc)
		if err != nil || got.Identity != it.Identity || got.ProtocolVersion != it.ProtocolVersion || got.Socket != it.Socket {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
	})
}
