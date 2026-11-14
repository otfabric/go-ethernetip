// SPDX-License-Identifier: MIT

package implicit

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

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

// consumeDatagram returns a Class 1 datagram of connection id with size
// octets of modeless data, and a function that sets its encapsulation
// sequence number and its sequence count to i in place: each call makes
// the datagram newer than the last.
func consumeDatagram(tb testing.TB, id uint32, size int) ([]byte, func(i uint32)) {
	tb.Helper()
	b, err := Message{ConnID: id, Payload: AppendPayload(nil, 1, FormatModeless, Payload{Data: make([]byte, size)})}.Encode()
	if err != nil {
		tb.Fatal(err)
	}
	// Item count; sequenced address item (type, length, connection ID,
	// sequence number); connected data item (type, length, sequence
	// count, data).
	const encapSeqAt, seqCountAt = 2 + 4 + 4, 2 + 4 + 8 + 4
	return b, func(i uint32) {
		binary.LittleEndian.PutUint32(b[encapSeqAt:], i)
		binary.LittleEndian.PutUint16(b[seqCountAt:], uint16(i))
	}
}

// consumer opens the connection BenchmarkConsume feeds, counting OnData.
func consumer(tb testing.TB) (*Endpoint, *Connection, *int) {
	tb.Helper()
	e, err := Listen("127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = e.Close() })
	calls := new(int)
	c, err := e.Open(Config{Class: 1, ConsumedID: 9, ConsumeSize: 32, ConsumeFormat: FormatModeless, OnData: func([]byte, bool) { *calls++ }})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(c.Close)
	return e, c, calls
}

// checkConsumed fails tb unless every one of n datagrams was received as
// new data.
func checkConsumed(tb testing.TB, c *Connection, calls, n int) {
	tb.Helper()
	if st := c.Stats(); st.Received != uint64(n) || st.Dropped != 0 || st.Duplicates != 0 || calls != n {
		tb.Fatalf("%d datagrams: %+v, %d OnData calls", n, st, calls)
	}
}

// BenchmarkConsume measures the receive path of a connection: decoding,
// sequence checks and the data callback, without the socket. Every
// datagram is newer than the last, so each one reaches the callback.
func BenchmarkConsume(b *testing.B) {
	e, c, calls := consumer(b)
	src := e.LocalAddr()
	msg, seq := consumeDatagram(b, 9, 32)
	n := 0
	b.ReportAllocs()
	for b.Loop() {
		n++
		seq(uint32(n))
		e.handle(src, msg)
	}
	b.StopTimer()
	checkConsumed(b, c, *calls, n)
}

// TestConsumeDatagram: the datagrams BenchmarkConsume replays decode with
// the sequence numbers set, and every one is consumed as new data, across
// the wrap of the 16-bit sequence count.
func TestConsumeDatagram(t *testing.T) {
	e, c, calls := consumer(t)
	msg, seq := consumeDatagram(t, 9, 32)
	const n = 70000
	for i := uint32(1); i <= n; i++ {
		seq(i)
		if i%9973 == 0 {
			m, err := Decode(msg)
			if err != nil {
				t.Fatal(err)
			}
			p, err := SplitPayload(m.Payload, 1, FormatModeless)
			if err != nil || m.ConnID != 9 || m.EncapSeq != i || p.SeqCount != uint16(i) || len(p.Data) != 32 {
				t.Fatalf("datagram %d: %+v %+v %v", i, m, p, err)
			}
		}
		e.handle(netip.AddrPort{}, msg)
	}
	checkConsumed(t, c, *calls, n)
}
