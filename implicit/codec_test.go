// SPDX-License-Identifier: MIT

package implicit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/encap"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestFormat(t *testing.T) {
	cases := []struct {
		f          Format
		s          string
		oh0, oh1   int
		runPresent bool
	}{
		{FormatModeless, "modeless", 0, 2, true},
		{FormatZeroLength, "zero-length", 0, 2, true},
		{FormatHeartbeat, "heartbeat", 0, 2, true},
		{FormatHeader32, "header32", 4, 6, false},
		{7, "format-7", 0, 2, true},
	}
	for _, c := range cases {
		if c.f.String() != c.s {
			t.Errorf("Format(%d) = %q, want %q", c.f, c.f.String(), c.s)
		}
		if c.f.Overhead(0) != c.oh0 || c.f.Overhead(1) != c.oh1 {
			t.Errorf("%s Overhead = %d/%d", c.f, c.f.Overhead(0), c.f.Overhead(1))
		}
		// Without a header, the presence of a packet means run.
		if (Payload{}).Run(c.f) != c.runPresent {
			t.Errorf("%s Run of zero payload = %v", c.f, !c.runPresent)
		}
	}
	if !(Payload{Header: RunBit}).Run(FormatHeader32) || (Payload{Header: 0xFFFFFFFE}).Run(FormatHeader32) {
		t.Error("Run ignores the run bit")
	}
}

func TestMessageVector(t *testing.T) {
	// An O->T datagram of OpENer's exclusive owner connection: sequenced
	// address, connected data with sequence count, run header and data.
	m := Message{ConnID: 0x12345678, EncapSeq: 3, Payload: unhex(t, "0200 01000000 AABBCCDD")}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "0200 0280 0800 78563412 03000000 B100 0A00 0200 01000000 AABBCCDD")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X", b)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnID != m.ConnID || got.EncapSeq != 3 || !bytes.Equal(got.Payload, m.Payload) {
		t.Errorf("Decode = %+v", got)
	}
	p, err := SplitPayload(got.Payload, 1, FormatHeader32)
	if err != nil {
		t.Fatal(err)
	}
	if p.SeqCount != 2 || p.Header != RunBit || !bytes.Equal(p.Data, unhex(t, "AABBCCDD")) || !p.Run(FormatHeader32) {
		t.Errorf("SplitPayload = %+v", p)
	}
}

func TestDecodeIgnoresSockaddr(t *testing.T) {
	sa := encap.SockaddrOf(mustAddrPort("192.168.1.10:2222")).Encode()
	b, err := encap.AppendCPF(nil, []encap.Item{
		{Type: encap.ItemSockaddrTO, Data: sa},
		{Type: encap.ItemConnectedData, Data: []byte{1, 0}},
		{Type: encap.ItemSequencedAddress, Data: encap.SequencedAddress{ConnID: 9, Sequence: 1}.Encode()},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(b)
	if err != nil || m.ConnID != 9 || m.EncapSeq != 1 || !bytes.Equal(m.Payload, []byte{1, 0}) {
		t.Errorf("Decode = %+v, %v", m, err)
	}
}

func TestDecodeErrors(t *testing.T) {
	seq := encap.Item{Type: encap.ItemSequencedAddress, Data: encap.SequencedAddress{ConnID: 1}.Encode()}
	data := encap.Item{Type: encap.ItemConnectedData}
	cases := []struct {
		name  string
		items []encap.Item
	}{
		{"no items", nil},
		{"no data", []encap.Item{seq}},
		{"no address", []encap.Item{data}},
		{"connected address instead", []encap.Item{encap.ConnectedAddress(1), data}},
		{"short address", []encap.Item{{Type: encap.ItemSequencedAddress, Data: []byte{1, 2, 3, 4}}, data}},
	}
	for _, c := range cases {
		b, err := encap.AppendCPF(nil, c.items)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	_, err := Decode([]byte{1})
	if !errors.Is(err, ErrMalformed) || !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("truncated CPF: %v", err)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	data := []byte{1, 2, 3}
	cases := []struct {
		class uint8
		f     Format
		want  string
		data  bool
	}{
		{0, FormatModeless, "010203", true},
		{0, FormatHeader32, "01000000 010203", true},
		{0, FormatZeroLength, "", false},
		{0, FormatHeartbeat, "", false},
		{1, FormatModeless, "3412 010203", true},
		{1, FormatHeader32, "3412 01000000 010203", true},
		{1, FormatZeroLength, "3412", false},
		{1, FormatHeartbeat, "3412", false},
	}
	for _, c := range cases {
		in := Payload{SeqCount: 0x1234, Header: RunBit, Data: data}
		b := AppendPayload([]byte{0xEE}, c.class, c.f, in)
		if want := append([]byte{0xEE}, unhex(t, c.want)...); !bytes.Equal(b, want) {
			t.Errorf("class %d %s: AppendPayload = % X, want % X", c.class, c.f, b, want)
			continue
		}
		p, err := SplitPayload(b[1:], c.class, c.f)
		if err != nil {
			t.Fatalf("class %d %s: %v", c.class, c.f, err)
		}
		wantSeq := uint16(0)
		if c.class == 1 {
			wantSeq = 0x1234
		}
		wantHeader := uint32(0)
		if c.f == FormatHeader32 {
			wantHeader = RunBit
		}
		if p.SeqCount != wantSeq || p.Header != wantHeader {
			t.Errorf("class %d %s: SplitPayload = %+v", c.class, c.f, p)
		}
		if c.data != bytes.Equal(p.Data, data) || (!c.data && len(p.Data) != 0) {
			t.Errorf("class %d %s: data = % X", c.class, c.f, p.Data)
		}
		// One octet short of the overhead fails.
		if oh := c.f.Overhead(c.class); oh > 0 {
			if _, err := SplitPayload(b[1:oh], c.class, c.f); !errors.Is(err, ErrMalformed) {
				t.Errorf("class %d %s: short payload: %v", c.class, c.f, err)
			}
		}
	}
}

func TestSeqNewer(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{5, 5, false},
		{0, 0xFFFFFFFF, true},          // wrap-around
		{0xFFFFFFFF, 0, false},         // wrap-around
		{0x80000000, 0, false},         // exactly half way: not newer
		{0x7FFFFFFF, 0, true},          // just under half way
		{0x00000010, 0xFFFFFFF0, true}, // across the wrap
	}
	for _, c := range cases {
		if got := SeqNewer(c.a, c.b); got != c.want {
			t.Errorf("SeqNewer(%#x, %#x) = %v", c.a, c.b, got)
		}
	}
	cases16 := []struct {
		a, b uint16
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{7, 7, false},
		{0, 0xFFFF, true},
		{0xFFFF, 0, false},
		{0x8000, 0, false},
		{0x7FFF, 0, true},
		{3, 0xFFFD, true},
	}
	for _, c := range cases16 {
		if got := SeqNewer16(c.a, c.b); got != c.want {
			t.Errorf("SeqNewer16(%#x, %#x) = %v", c.a, c.b, got)
		}
	}
}
