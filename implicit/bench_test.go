// SPDX-License-Identifier: MIT

package implicit

import "testing"

func BenchmarkMessageEncode(b *testing.B) {
	data := make([]byte, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := Message{ConnID: 1, EncapSeq: uint32(i), Payload: AppendPayload(nil, 1, FormatHeader32, Payload{SeqCount: uint16(i), Header: RunBit, Data: data})}
		if _, err := m.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageDecode(b *testing.B) {
	m := Message{ConnID: 1, EncapSeq: 7, Payload: AppendPayload(nil, 1, FormatHeader32, Payload{SeqCount: 3, Header: RunBit, Data: make([]byte, 32)})}
	enc, _ := m.Encode()
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d, err := Decode(enc)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := SplitPayload(d.Payload, 1, FormatHeader32); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConsume measures the receive path of a connection: decoding,
// sequence checks and the data callback, without the socket.
func BenchmarkConsume(b *testing.B) {
	e, err := Listen("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	c, err := e.Open(Config{Class: 1, ConsumedID: 9, ConsumeSize: 32, ConsumeFormat: FormatModeless, OnData: func([]byte, bool) {}})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	src := e.LocalAddr()
	msgs := make([][]byte, 1024)
	for i := range msgs {
		enc, _ := Message{ConnID: 9, EncapSeq: uint32(i + 1), Payload: AppendPayload(nil, 1, FormatModeless, Payload{SeqCount: uint16(i + 1), Data: make([]byte, 32)})}.Encode()
		msgs[i] = enc
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.handle(src, msgs[i%len(msgs)])
	}
}
