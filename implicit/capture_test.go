// SPDX-License-Identifier: MIT

package implicit_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/internal/capture"
)

// The 398 recorded Class 1 I/O datagrams of enip_cip_example (UDP 2222, 24
// connections, producers 192.168.1.22 and .24; the devices are not
// identified, class C): every one decodes and encodes back to the recorded
// octets; per connection the encapsulation sequence number advances by
// one with every datagram and the Class 1 sequence count never goes back.
func TestCaptureClass1IO(t *testing.T) {
	recs, err := capture.Load("../testdata/captures", capture.Extended)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := capture.Get(recs, "icsnpp-enip-cip-example")
	type state struct {
		encap uint32
		count uint16
		n     int
		size  int
	}
	conns := map[uint32]*state{}
	n := 0
	for _, c := range r.Conversations {
		if c.Transport != capture.UDP || !strings.HasSuffix(c.Server, ":2222") {
			continue
		}
		for _, m := range c.Messages {
			n++
			msg, err := implicit.Decode(m.Data)
			if err != nil {
				t.Fatalf("frame %d: %v", m.Frame, err)
			}
			if b, err := msg.Encode(); err != nil || !bytes.Equal(b, m.Data) {
				t.Errorf("frame %d: encodes to % x, %v", m.Frame, b, err)
			}
			p, err := implicit.SplitPayload(msg.Payload, 1, implicit.FormatModeless)
			if err != nil {
				t.Fatalf("frame %d: %v", m.Frame, err)
			}
			s := conns[msg.ConnID]
			if s == nil {
				conns[msg.ConnID] = &state{encap: msg.EncapSeq, count: p.SeqCount, n: 1, size: len(msg.Payload)}
				continue
			}
			if msg.EncapSeq != s.encap+1 || !implicit.SeqNewer(msg.EncapSeq, s.encap) {
				t.Errorf("frame %d: connection %#x sequence %d after %d", m.Frame, msg.ConnID, msg.EncapSeq, s.encap)
			}
			if implicit.SeqNewer16(s.count, p.SeqCount) {
				t.Errorf("frame %d: connection %#x count %d after %d", m.Frame, msg.ConnID, p.SeqCount, s.count)
			}
			if len(msg.Payload) != s.size {
				t.Errorf("frame %d: connection %#x payload of %d octets, was %d", m.Frame, msg.ConnID, len(msg.Payload), s.size)
			}
			s.encap, s.count, s.n = msg.EncapSeq, p.SeqCount, s.n+1
		}
	}
	if n != 398 || len(conns) != 24 {
		t.Errorf("%d datagrams on %d connections", n, len(conns))
	}
	// Twelve connections of .22 carry the sequence count alone (a
	// heartbeat); of .24 eleven carry 6 octets and one 88.
	sizes := map[int]int{}
	for _, s := range conns {
		sizes[s.size]++
	}
	if sizes[2] != 12 || sizes[6] != 11 || sizes[88] != 1 {
		t.Errorf("payload sizes %v", sizes)
	}
}
