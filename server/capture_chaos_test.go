// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/capture"
	"github.com/otfabric/go-ethernetip/server"
)

// Mutated streams of the recorded RSLinx requests: each stream registers a
// session, then sends recorded requests cut short, with a wrong length
// field, with flipped octets, duplicated or out of order (a connected
// request before its Forward_Open or after its Forward_Close), and ends
// with the recorded Identity request. The server must neither stop nor
// hang: the closing request is answered on the stream, or, when the server
// dropped the stream, on a new connection, as the 1756-L63 answered it.
// Seeded (ETHERNETIP_CHAOS_SEED repeats a run; the default seed is fixed,
// so that CI runs the same streams).
func TestCaptureMutatedStreams(t *testing.T) {
	seed := uint64(1)
	if s := os.Getenv("ETHERNETIP_CHAOS_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("ETHERNETIP_CHAOS_SEED=%q", s)
		}
		seed = v
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("repeat with ETHERNETIP_CHAOS_SEED=%d", seed)
		}
	})
	rng := rand.New(rand.NewPCG(seed, 2))
	rec, _ := capture.Get(recordings(t), "controllogix-download")
	var pool [][]byte
	var probe, probeReply []byte
	for _, c := range rec.Conversations {
		ex, _ := capture.Exchanges(c)
		for _, e := range ex {
			h, _ := capture.ParseHeader(e.Request.Data)
			if h.Command == 0x0065 {
				continue
			}
			pool = append(pool, e.Request.Data)
			if e.Request.Frame == 221 { // Unconnected_Send of Identity Get_Attributes_All
				probe, probeReply = e.Request.Data, e.Reply.Data
			}
		}
	}
	if probe == nil || len(pool) < 20 {
		t.Fatalf("%d requests, probe %v", len(pool), probe != nil)
	}
	s := startServer(t, server.WithIdentity(identity1756L63), server.WithMaxPacket(4096), server.WithInactivityTimeout(2*time.Second))
	n := 300
	if testing.Short() {
		n = 50
	}
	dropped := 0
	for i := range n {
		var stream [][]byte
		for range 1 + rng.IntN(4) {
			stream = append(stream, mutate(rng, pool[rng.IntN(len(pool))]))
		}
		if rng.IntN(4) == 0 && len(stream) > 1 {
			rng.Shuffle(len(stream), func(a, b int) { stream[a], stream[b] = stream[b], stream[a] })
		}
		if !answered(t, s, stream, probe, probeReply) {
			dropped++
			if !answered(t, s, nil, probe, probeReply) {
				t.Fatalf("stream %d: the server does not answer a new connection", i)
			}
		}
	}
	t.Logf("%d streams, %d dropped by the server", n, dropped)
}

// mutate returns a variant of the recorded message m.
func mutate(rng *rand.Rand, m []byte) []byte {
	b := append([]byte(nil), m...)
	switch rng.IntN(6) {
	case 0: // cut short
		return b[:rng.IntN(len(b))]
	case 1: // a length field off by up to ±8, within 0..65535
		l := int(binary.LittleEndian.Uint16(b[2:])) + rng.IntN(17) - 8
		binary.LittleEndian.PutUint16(b[2:], uint16(max(0, min(l, 0xFFFF))))
	case 2: // a flipped octet after the header's command
		i := 2 + rng.IntN(len(b)-2)
		b[i] ^= byte(1 + rng.IntN(255))
	case 3: // duplicated
		return append(b, b...)
	case 4: // an oversized length field
		binary.LittleEndian.PutUint16(b[2:], 0xFFFF)
	}
	return b // 5: unchanged
}

// answered sends a RegisterSession, the stream (with the session handle)
// and the probe on one connection, and reports whether the probe got the
// recorded reply.
func answered(t *testing.T, s *server.Server, stream [][]byte, probe, want []byte) bool {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	reg := []byte{0x65, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}
	if _, err := c.Write(reg); err != nil {
		return false
	}
	h := make([]byte, encap.HeaderSize+4)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatal(err)
	}
	sess := binary.LittleEndian.Uint32(h[4:])
	var out []byte
	for _, m := range stream {
		m = append([]byte(nil), m...)
		if len(m) >= 8 {
			binary.LittleEndian.PutUint32(m[4:], sess)
		}
		out = append(out, m...)
	}
	p := append([]byte(nil), probe...)
	binary.LittleEndian.PutUint32(p[4:], sess)
	copy(p[12:20], "probe!!!")
	if _, err := c.Write(append(out, p...)); err != nil {
		return false
	}
	// End the stream: a message whose length field claims more than was
	// sent is not waited for.
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		hd := make([]byte, encap.HeaderSize)
		if _, err := io.ReadFull(c, hd); err != nil {
			return false
		}
		body := make([]byte, binary.LittleEndian.Uint16(hd[2:]))
		if _, err := io.ReadFull(c, body); err != nil {
			return false
		}
		if string(hd[12:20]) != "probe!!!" {
			continue
		}
		got := append(hd, body...)
		w := append([]byte(nil), want...)
		copy(w[4:8], got[4:8])
		copy(w[12:20], got[12:20])
		if !bytes.Equal(got, w) {
			t.Fatalf("probe answered\n  % x\nwant\n  % x", got, w)
		}
		return true
	}
}
