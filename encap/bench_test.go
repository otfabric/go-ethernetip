// SPDX-License-Identifier: MIT

package encap

import (
	"bytes"
	"testing"
)

func benchRR(b *testing.B, size int) []byte {
	b.Helper()
	data, err := RRData{Items: []Item{{Type: ItemNullAddress}, {Type: ItemUnconnectedData, Data: make([]byte, size)}}}.Encode()
	if err != nil {
		b.Fatal(err)
	}
	pkt, err := Packet{Header: Header{Command: CommandSendRRData, Session: 1}, Data: data}.Encode()
	if err != nil {
		b.Fatal(err)
	}
	return pkt
}

func BenchmarkPacketEncode(b *testing.B) {
	for _, size := range []int{32, 500, 4000} {
		b.Run(sizeName(size), func(b *testing.B) {
			data, _ := RRData{Items: []Item{{Type: ItemNullAddress}, {Type: ItemUnconnectedData, Data: make([]byte, size)}}}.Encode()
			buf := make([]byte, 0, HeaderSize+len(data))
			b.SetBytes(int64(HeaderSize + len(data)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				if buf, err = (Packet{Header: Header{Command: CommandSendRRData, Session: 1}, Data: data}).AppendTo(buf[:0]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReadPacket(b *testing.B) {
	for _, size := range []int{32, 500, 4000} {
		b.Run(sizeName(size), func(b *testing.B) {
			pkt := benchRR(b, size)
			r := bytes.NewReader(pkt)
			var buf []byte
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r.Reset(pkt)
				var err error
				if _, buf, err = ReadPacket(r, buf, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecodeRRData(b *testing.B) {
	pkt := benchRR(b, 500)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeRRData(pkt[HeaderSize:]); err != nil {
			b.Fatal(err)
		}
	}
}

func sizeName(n int) string {
	switch n {
	case 32:
		return "32B"
	case 500:
		return "500B"
	default:
		return "4000B"
	}
}
