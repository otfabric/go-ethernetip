// SPDX-License-Identifier: MIT

package cip

import "testing"

var benchPath = Path{
	PortSegment{Port: 1, Link: []byte{0}},
	KeySegment{VendorID: 1, DeviceType: 12, ProductCode: 65001, Major: 2, Minor: 3},
	ClassSegment(ClassAssembly), InstanceSegment(151),
	ConnectionPointSegment(150), ConnectionPointSegment(100),
}

func BenchmarkPathEncode(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		if buf, err = benchPath.AppendTo(buf[:0], false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPathDecode(b *testing.B) {
	enc, _ := benchPath.Encode()
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodePath(enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequestEncode(b *testing.B) {
	req := Request{Service: ServiceGetAttributeSingle, Path: AttributePath(ClassIdentity, 1, 7)}
	buf := make([]byte, 0, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		if buf, err = req.AppendTo(buf[:0]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequestDecode(b *testing.B) {
	enc, _ := Request{Service: ServiceSetAttributeSingle, Path: AttributePath(ClassAssembly, 150, 3), Data: make([]byte, 32)}.Encode()
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeRequest(enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResponseDecode(b *testing.B) {
	enc, _ := Response{Service: ServiceGetAttributeSingle, Data: make([]byte, 32)}.Encode()
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeResponse(enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkForwardOpenRoundTrip(b *testing.B) {
	fo := ForwardOpen{TOConnID: 1, Triad: Triad{Serial: 1, VendorID: 2, OriginatorSerial: 3}, OTRPI: 10000, TORPI: 10000,
		OTParams: NetworkParams{Type: ConnectionPointToPoint, Size: 38}, TOParams: NetworkParams{Type: ConnectionPointToPoint, Size: 34},
		Transport: TransportClass1Cyclic, Path: benchPath[2:]}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc, err := fo.Encode()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeForwardOpen(enc, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMultipleService(b *testing.B) {
	reqs := make([]Request, 16)
	for i := range reqs {
		reqs[i] = Request{Service: ServiceGetAttributeSingle, Path: AttributePath(ClassIdentity, 1, uint16(i+1))}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc, err := EncodeMultipleService(reqs)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := SplitMultiple(enc); err != nil {
			b.Fatal(err)
		}
	}
}
