// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func FuzzDecodePath(f *testing.F) {
	for _, v := range segmentVectors {
		f.Add(unhex(f, v.padded), false)
		f.Add(unhex(f, v.packed), true)
	}
	f.Add(unhex(f, "20 04 24 97 2C 96 2C 64"), false)
	f.Add(unhex(f, "20 6B 27 00 78 56 34 12"), false)
	f.Add(unhex(f, "01 00 12 0C 3139322E3136382E312E3130 91 03 546167 00"), false)
	f.Fuzz(func(t *testing.T, b []byte, packed bool) {
		dec := cip.DecodePath
		if packed {
			dec = cip.DecodePacked
		}
		p, err := dec(b)
		if err != nil {
			return
		}
		if len(p) > 256 {
			t.Fatalf("%d segments", len(p))
		}
		_ = p.String()
		enc, err := p.AppendTo(nil, packed)
		if err != nil {
			t.Fatalf("decoded path %v does not encode: %v", p, err)
		}
		q, err := dec(enc)
		if err != nil {
			t.Fatalf("re-encoded path % X does not decode: %v", enc, err)
		}
		if !reflect.DeepEqual(p, q) {
			t.Fatalf("round trip: %#v != %#v", p, q)
		}
	})
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add(unhex(f, "0E 03 20 01 24 01 30 07"))
	f.Add(unhex(f, "4C 03 91 03 546167 00 0100"))
	f.Add(unhex(f, "10 03 20 04 24 96 30 03 010203"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := cip.DecodeRequest(b)
		if err != nil {
			return
		}
		_ = r.String()
		enc, err := r.Encode()
		if err != nil {
			// A decoded path can use encodings the encoder refuses
			// (32-bit class); it must still not panic.
			return
		}
		r2, err := cip.DecodeRequest(enc)
		if err != nil {
			t.Fatalf("re-encoded request does not decode: %v", err)
		}
		if r2.Service != r.Service || !bytes.Equal(r2.Data, r.Data) || !reflect.DeepEqual(r2.Path, r.Path) {
			t.Fatalf("round trip: %+v != %+v", r2, r)
		}
	})
}

func FuzzDecodeResponse(f *testing.F) {
	f.Add(unhex(f, "8E 00 00 00 0100"))
	f.Add(unhex(f, "D4 00 01 01 0001 0100 3713 21436587 00 00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := cip.DecodeResponse(b)
		if err != nil {
			return
		}
		if len(r.Extended) > len(b)/2 {
			t.Fatalf("%d extended words from %d octets", len(r.Extended), len(b))
		}
		_ = r.Status.String()
		enc, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		// The reserved octet is written as 0.
		want := append([]byte(nil), b...)
		want[1] = 0
		if !bytes.Equal(enc, want) {
			t.Fatalf("round trip: % X != % X", enc, want)
		}
	})
}

func FuzzSplitMultiple(f *testing.F) {
	f.Add(unhex(f, "0200 0600 0E00 0E03200124013001 0E03200124013007"))
	f.Add(unhex(f, "0200 0600 0C00 8E000000 0100 8E001400"))
	f.Add(unhex(f, "0000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parts, err := cip.SplitMultiple(b)
		if err != nil {
			return
		}
		total := 0
		for _, p := range parts {
			total += len(p)
		}
		if len(parts) > 0 && total > len(b)-2-2*len(parts) {
			t.Fatalf("%d octets of parts from %d", total, len(b))
		}
	})
}

func FuzzDecodeForwardOpen(f *testing.F) {
	f.Add(unhex(f, "0A 0E 00000000 78563412 0100 3713 21436587 01 000000 10270000 2648 10270000 2028 01 04 2004249 72C962C64"), false)
	f.Add(unhex(f, "07 E8 11111111 22222222 EFBE 0100 02000000 03 000000 204E0000 E8030048 30750000 001000AA A3 03 0100 2002 2401"), true)
	f.Fuzz(func(t *testing.T, b []byte, large bool) {
		fo, err := cip.DecodeForwardOpen(b, large)
		if err != nil {
			return
		}
		if fo.TimeoutMultiplier > 7 || (!large && fo.OTParams.Size > 0x1FF) {
			// Not encodable; a decoder must still accept what it reads.
			return
		}
		enc, err := fo.Encode()
		if err != nil {
			return // e.g. a 32-bit class segment in the path
		}
		fo2, err := cip.DecodeForwardOpen(enc, large)
		if err != nil {
			t.Fatalf("re-encoded Forward_Open does not decode: %v", err)
		}
		if !reflect.DeepEqual(fo, fo2) {
			t.Fatalf("round trip:\n%+v\n%+v", fo, fo2)
		}
	})
}

func FuzzDecodeUnconnectedSend(f *testing.F) {
	f.Add(unhex(f, "0A 0E 0900 10 03 20 01 24 01 30 07 05 00 01 00 01 00"))
	f.Add(unhex(f, "0A 0E 0800 0E 03 20 01 24 01 30 07 01 00 01 00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := cip.DecodeUnconnectedSend(b)
		if err != nil {
			return
		}
		enc, err := u.Encode()
		if err != nil {
			return
		}
		u2, err := cip.DecodeUnconnectedSend(enc)
		if err != nil {
			t.Fatalf("re-encoded Unconnected_Send does not decode: %v", err)
		}
		if !reflect.DeepEqual(u.Route, u2.Route) || u.Request.Service != u2.Request.Service || !bytes.Equal(u.Request.Data, u2.Request.Data) {
			t.Fatalf("round trip:\n%+v\n%+v", u, u2)
		}
	})
}

func FuzzDecodeIdentity(f *testing.F) {
	f.Add(unhex(f, "0100 0C00 E9FD 02 03 0500 15CD5B07 09 4F70454E6572205043"))
	f.Add(unhex(f, "0100 0C00 E9FD 02 03 0500 15CD5B07 09 4F70454E6572205043 03"))
	f.Fuzz(func(t *testing.T, b []byte) {
		id, err := cip.DecodeIdentity(b)
		if err != nil {
			return
		}
		_ = id.String()
		enc, err := id.AppendAttributes(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(b, enc) {
			t.Fatalf("round trip: % X is not a prefix of % X", enc, b)
		}
	})
}
