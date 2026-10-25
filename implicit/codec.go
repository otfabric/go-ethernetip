// SPDX-License-Identifier: MIT

// Package implicit is EtherNet/IP implicit (I/O) messaging: the codec of
// Class 0 and Class 1 datagrams, a UDP [Endpoint] that receives them on
// port 2222 and dispatches them by connection ID, and the [Connection]
// that produces and consumes the data of one connection at its requested
// packet intervals, with sequence handling, run/idle and the inactivity
// watchdog.
//
// The scanner package (originator) and the server package (target) build
// their I/O connections on it; Forward_Open itself is theirs.
package implicit

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/otfabric/go-ethernetip/encap"
)

// Errors of the codec.
var (
	// ErrMalformed reports a datagram that is not an I/O message: not two
	// items, not a sequenced address and connected data, a payload shorter
	// than its format needs.
	ErrMalformed = errors.New("implicit: malformed I/O message")
)

// Format is the real-time format of one direction of a connection: what
// precedes the application data.
type Format uint8

// Real-time formats.
const (
	// FormatModeless carries the data alone; the usual T->O format.
	FormatModeless Format = 0
	// FormatZeroLength carries no data: a packet means run, its absence
	// idle.
	FormatZeroLength Format = 1
	// FormatHeartbeat carries no data: the packets only keep the
	// connection alive (input-only and listen-only connections).
	FormatHeartbeat Format = 2
	// FormatHeader32 prefixes the data with the 32-bit run/idle header; the
	// usual O->T format.
	FormatHeader32 Format = 3
)

// String returns "modeless", "zero-length", "heartbeat" or "header32".
func (f Format) String() string {
	switch f {
	case FormatModeless:
		return "modeless"
	case FormatZeroLength:
		return "zero-length"
	case FormatHeartbeat:
		return "heartbeat"
	case FormatHeader32:
		return "header32"
	default:
		return fmt.Sprintf("format-%d", uint8(f))
	}
}

// Overhead returns the octets a Class 1 (class 1) or Class 0 (class 0)
// connection adds to the application data in this format: the 16-bit
// sequence count (Class 1) and the 32-bit header (FormatHeader32). The
// connection size of a Forward_Open is the data size plus Overhead.
func (f Format) Overhead(class uint8) int {
	n := 0
	if class != 0 {
		n += 2
	}
	if f == FormatHeader32 {
		n += 4
	}
	return n
}

// RunBit is the run bit of the 32-bit run/idle header.
const RunBit uint32 = 1

// Message is one I/O datagram.
type Message struct {
	// ConnID is the connection ID of the sequenced address item.
	ConnID uint32
	// EncapSeq is the 32-bit encapsulation sequence number, incremented by
	// the producer with every datagram.
	EncapSeq uint32
	// Payload is the data of the connected data item: for Class 1 the
	// sequence count, the header in FormatHeader32, then the data.
	Payload []byte
}

// Encode returns the datagram: a common packet format of a sequenced
// address item and a connected data item.
func (m Message) Encode() ([]byte, error) {
	b := make([]byte, 0, 2+12+4+len(m.Payload))
	return encap.AppendCPF(b, []encap.Item{
		{Type: encap.ItemSequencedAddress, Data: encap.SequencedAddress{ConnID: m.ConnID, Sequence: m.EncapSeq}.Encode()},
		{Type: encap.ItemConnectedData, Data: m.Payload},
	})
}

// Decode decodes a datagram. Items other than the sequenced address and
// the connected data (Sockaddr Info items) are ignored. The payload aliases
// b.
func Decode(b []byte) (Message, error) {
	items, err := encap.DecodeCPF(b)
	if err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	addr, ok1 := encap.Find(items, encap.ItemSequencedAddress)
	data, ok2 := encap.Find(items, encap.ItemConnectedData)
	if !ok1 || !ok2 {
		return Message{}, fmt.Errorf("%w: sequenced address or connected data item missing", ErrMalformed)
	}
	sa, err := encap.DecodeSequencedAddress(addr.Data)
	if err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return Message{ConnID: sa.ConnID, EncapSeq: sa.Sequence, Payload: data.Data}, nil
}

// Payload is the content of a connected data item, split by format.
type Payload struct {
	// SeqCount is the Class 1 sequence count (0 for Class 0).
	SeqCount uint16
	// Header is the 32-bit run/idle header (FormatHeader32 only).
	Header uint32
	// Data is the application data.
	Data []byte
}

// Run reports whether the payload says run: the run bit of the header in
// FormatHeader32, the presence of the packet in the other formats.
func (p Payload) Run(f Format) bool {
	if f == FormatHeader32 {
		return p.Header&RunBit != 0
	}
	return true
}

// AppendPayload appends the payload of a connection of class 0 or 1 in
// format f.
func AppendPayload(b []byte, class uint8, f Format, p Payload) []byte {
	if class != 0 {
		b = binary.LittleEndian.AppendUint16(b, p.SeqCount)
	}
	if f == FormatHeader32 {
		b = binary.LittleEndian.AppendUint32(b, p.Header)
	}
	if f == FormatHeartbeat || f == FormatZeroLength {
		return b
	}
	return append(b, p.Data...)
}

// SplitPayload splits the payload of a connection of class 0 or 1 in
// format f. The data aliases b.
func SplitPayload(b []byte, class uint8, f Format) (Payload, error) {
	var p Payload
	if need := f.Overhead(class); len(b) < need {
		return p, fmt.Errorf("%w: payload of %d octets, %s class %d needs %d", ErrMalformed, len(b), f, class, need)
	}
	if class != 0 {
		p.SeqCount = binary.LittleEndian.Uint16(b)
		b = b[2:]
	}
	if f == FormatHeader32 {
		p.Header = binary.LittleEndian.Uint32(b)
		b = b[4:]
	}
	p.Data = b
	return p, nil
}

// SeqNewer reports whether 32-bit sequence number a follows b in serial
// number arithmetic: a is newer when a-b, as a signed number, is positive.
func SeqNewer(a, b uint32) bool { return int32(a-b) > 0 }

// SeqNewer16 is [SeqNewer] for the 16-bit Class 1 sequence count.
func SeqNewer16(a, b uint16) bool { return int16(a-b) > 0 }
