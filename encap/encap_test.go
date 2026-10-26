// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
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

// registerRequest is a RegisterSession request as every client sends it.
const registerRequest = "6500 0400 00000000 00000000 0102030405060708 00000000 0100 0000"

func TestHeaderVector(t *testing.T) {
	h := encap.Header{
		Command: encap.CommandRegisterSession,
		Length:  4,
		Context: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	want := unhex(t, registerRequest)
	b := h.AppendTo(nil)
	if !bytes.Equal(b, want[:encap.HeaderSize]) {
		t.Fatalf("AppendTo = % X", b)
	}
	got, err := encap.DecodeHeader(want)
	if err != nil || got != h {
		t.Errorf("DecodeHeader = %+v, %v", got, err)
	}

	h = encap.Header{Command: encap.CommandSendRRData, Length: 0x1234, Session: 0x11223344, Status: encap.StatusInvalidLength, Options: 0xAABBCCDD}
	b = h.AppendTo([]byte{0xEE})
	if want := unhex(t, "EE 6F00 3412 44332211 65000000 0000000000000000 DDCCBBAA"); !bytes.Equal(b, want) {
		t.Errorf("AppendTo = % X", b)
	}
	if got, err := encap.DecodeHeader(b[1:]); err != nil || got != h {
		t.Errorf("DecodeHeader = %+v, %v", got, err)
	}
	if _, err := encap.DecodeHeader(b[1:24]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("23 octets: %v", err)
	}
}

func TestPacket(t *testing.T) {
	want := unhex(t, registerRequest)
	p := encap.Packet{
		Header: encap.Header{Command: encap.CommandRegisterSession, Length: 99, Context: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		Data:   encap.Register{ProtocolVersion: encap.ProtocolVersion}.Encode(),
	}
	// Encode sets the length from the data.
	b, err := p.Encode()
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("Encode = % X, %v", b, err)
	}
	got, err := encap.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Length != 4 || got.Command != encap.CommandRegisterSession || !bytes.Equal(got.Data, p.Data) {
		t.Errorf("Decode = %+v", got)
	}
	r, err := encap.DecodeRegister(got.Data)
	if err != nil || r != (encap.Register{ProtocolVersion: 1}) {
		t.Errorf("DecodeRegister = %+v, %v", r, err)
	}

	if _, err := encap.Decode(b[:30]); !errors.Is(err, encap.ErrMalformed) {
		t.Errorf("short data: %v", err)
	}
	if got, err := encap.Decode(append(b, 0)); !errors.Is(err, encap.ErrMalformed) || got.Command != encap.CommandRegisterSession {
		t.Errorf("long data: %+v, %v", got, err)
	}
	if _, err := encap.Decode(b[:10]); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("short header: %v", err)
	}
	if _, err := (encap.Packet{Data: make([]byte, encap.MaxData+1)}).Encode(); !errors.Is(err, encap.ErrTooLarge) {
		t.Errorf("65536 octets: %v", err)
	}
	if b, err := (encap.Packet{Data: make([]byte, encap.MaxData)}).Encode(); err != nil || len(b) != encap.HeaderSize+encap.MaxData {
		t.Errorf("65535 octets: %d, %v", len(b), err)
	}
	if _, err := encap.DecodeRegister([]byte{1, 0, 0}); !errors.Is(err, encap.ErrTruncated) {
		t.Errorf("DecodeRegister short: %v", err)
	}
}

// oneByteReader returns at most one octet per Read.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestReadPacketStream(t *testing.T) {
	p1, _ := encap.Packet{Header: encap.Header{Command: encap.CommandNOP}, Data: []byte("abc")}.Encode()
	p2, _ := encap.Packet{Header: encap.Header{Command: encap.CommandSendRRData, Session: 7}, Data: bytes.Repeat([]byte{0x55}, 1000)}.Encode()
	p3, _ := encap.Packet{Header: encap.Header{Command: encap.CommandListIdentity}}.Encode()
	stream := append(append(append([]byte(nil), p1...), p2...), p3...)

	r := oneByteReader{bytes.NewReader(stream)}
	var buf []byte
	pkt, buf, err := encap.ReadPacket(r, buf, 0)
	if err != nil || pkt.Command != encap.CommandNOP || string(pkt.Data) != "abc" {
		t.Fatalf("packet 1 = %+v, %v", pkt, err)
	}
	if cap(buf) != 512 {
		t.Errorf("initial buffer cap = %d", cap(buf))
	}
	// The data is capped so that appending to it cannot overwrite the
	// buffer behind it.
	if cap(pkt.Data) != len(pkt.Data) {
		t.Errorf("data cap %d len %d", cap(pkt.Data), len(pkt.Data))
	}

	pkt, buf, err = encap.ReadPacket(r, buf, 0)
	if err != nil || pkt.Session != 7 || len(pkt.Data) != 1000 || pkt.Data[999] != 0x55 {
		t.Fatalf("packet 2 = %v, %v", pkt.Header, err)
	}
	if cap(buf) < 1024 {
		t.Errorf("buffer not grown: %d", cap(buf))
	}
	grown := &buf[:1][0]

	pkt, buf, err = encap.ReadPacket(r, buf, 0)
	if err != nil || pkt.Command != encap.CommandListIdentity || len(pkt.Data) != 0 {
		t.Fatalf("packet 3 = %+v, %v", pkt, err)
	}
	if &buf[:1][0] != grown {
		t.Error("buffer not reused")
	}

	// End of stream between packets: io.EOF as is.
	if _, _, err := encap.ReadPacket(r, buf, 0); err != io.EOF {
		t.Errorf("at end: %v, want io.EOF", err)
	}
}

func TestReadPacketUnexpectedEOF(t *testing.T) {
	p, _ := encap.Packet{Header: encap.Header{Command: encap.CommandNOP}, Data: []byte("abcdef")}.Encode()
	// Inside the header.
	if _, _, err := encap.ReadPacket(bytes.NewReader(p[:10]), nil, 0); err != io.ErrUnexpectedEOF {
		t.Errorf("in header: %v", err)
	}
	// Exactly after the header: the data is missing entirely.
	if pkt, _, err := encap.ReadPacket(bytes.NewReader(p[:encap.HeaderSize]), nil, 0); err != io.ErrUnexpectedEOF || pkt.Command != encap.CommandNOP {
		t.Errorf("after header: %+v, %v", pkt, err)
	}
	// Inside the data.
	if _, _, err := encap.ReadPacket(oneByteReader{bytes.NewReader(p[:27])}, nil, 0); err != io.ErrUnexpectedEOF {
		t.Errorf("in data: %v", err)
	}
	// Other errors are returned as is.
	boom := errors.New("boom")
	if _, _, err := encap.ReadPacket(io.MultiReader(bytes.NewReader(p[:26]), errReader{boom}), nil, 0); err != boom {
		t.Errorf("read error: %v", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// countingReader counts the octets read.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestReadPacketTooLarge(t *testing.T) {
	p, _ := encap.Packet{Header: encap.Header{Command: encap.CommandSendRRData}, Data: make([]byte, 600)}.Encode()
	cr := &countingReader{r: bytes.NewReader(p)}
	pkt, _, err := encap.ReadPacket(cr, nil, 512)
	if !errors.Is(err, encap.ErrTooLarge) {
		t.Fatalf("600 > 512: %v", err)
	}
	if pkt.Length != 600 || pkt.Command != encap.CommandSendRRData {
		t.Errorf("header = %+v", pkt.Header)
	}
	// The data is not read.
	if cr.n != encap.HeaderSize {
		t.Errorf("read %d octets, want only the header", cr.n)
	}
	// At the limit it is accepted; a limit above MaxData means MaxData.
	if _, _, err := encap.ReadPacket(bytes.NewReader(p), nil, 600); err != nil {
		t.Errorf("600 = 600: %v", err)
	}
	if _, _, err := encap.ReadPacket(bytes.NewReader(p), make([]byte, 0, 10), 1<<20); err != nil {
		t.Errorf("limit above MaxData: %v", err)
	}
	if _, _, err := encap.ReadPacket(bytes.NewReader(p), nil, -1); err != nil {
		t.Errorf("negative limit: %v", err)
	}
}

func TestStrings(t *testing.T) {
	cmds := map[encap.Command]string{
		encap.CommandNOP: "NOP", encap.CommandListServices: "ListServices", encap.CommandListIdentity: "ListIdentity",
		encap.CommandListInterfaces: "ListInterfaces", encap.CommandRegisterSession: "RegisterSession",
		encap.CommandUnRegisterSession: "UnRegisterSession", encap.CommandSendRRData: "SendRRData",
		encap.CommandSendUnitData: "SendUnitData", encap.CommandIndicateStatus: "IndicateStatus",
		encap.CommandCancel: "Cancel", 0x1234: "command 0x1234",
	}
	for c, want := range cmds {
		if c.String() != want {
			t.Errorf("Command(%#x) = %q, want %q", uint16(c), c.String(), want)
		}
	}
	sts := map[encap.Status]string{
		encap.StatusSuccess: "success", encap.StatusInvalidCommand: "invalid or unsupported command",
		encap.StatusInsufficientMemory: "insufficient memory", encap.StatusIncorrectData: "incorrect data",
		encap.StatusInvalidSessionHandle: "invalid session handle", encap.StatusInvalidLength: "invalid length",
		encap.StatusUnsupportedProtocol: "unsupported encapsulation protocol revision", 0x99: "status 0x0099",
	}
	for s, want := range sts {
		if s.String() != want {
			t.Errorf("Status(%#x) = %q, want %q", uint32(s), s.String(), want)
		}
	}
	items := map[encap.ItemType]string{
		encap.ItemNullAddress: "Null Address", encap.ItemListIdentity: "CIP Identity",
		encap.ItemConnectedAddress: "Connected Address", encap.ItemConnectedData: "Connected Data",
		encap.ItemUnconnectedData: "Unconnected Data", encap.ItemListServices: "ListServices Response",
		encap.ItemSockaddrOT: "Sockaddr Info O->T", encap.ItemSockaddrTO: "Sockaddr Info T->O",
		encap.ItemSequencedAddress: "Sequenced Address", 0x00B3: "item 0x00B3",
	}
	for it, want := range items {
		if it.String() != want {
			t.Errorf("ItemType(%#x) = %q, want %q", uint16(it), it.String(), want)
		}
	}
}
