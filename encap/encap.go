// SPDX-License-Identifier: MIT

// Package encap is the EtherNet/IP encapsulation codec: the 24-octet
// header, the commands and their status codes, the common packet format
// (CPF) and the items of ListIdentity, ListServices and the connected and
// I/O messages.
//
// The package is a pure codec: it does no I/O beyond [ReadPacket] over an
// io.Reader, and keeps no state. Every decoder checks lengths against the
// data it is given before allocating, so it is safe on untrusted input.
package encap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Ports registered for EtherNet/IP.
const (
	// TCPPort is the explicit messaging port, TCP and UDP (44818).
	TCPPort = 44818
	// IOPort is the implicit (I/O) messaging port, UDP (2222).
	IOPort = 2222
	// SecurePort is EtherNet/IP over TLS (TCP) and DTLS (UDP), CIP
	// Security (2221).
	SecurePort = 2221
)

// HeaderSize is the size of the encapsulation header.
const HeaderSize = 24

// MaxData is the largest data length the header's 16-bit length field can
// carry.
const MaxData = math.MaxUint16

// Errors of the codec.
var (
	// ErrTruncated reports data that ends before the structure it encodes.
	ErrTruncated = errors.New("encap: truncated")
	// ErrMalformed reports data that does not encode a valid structure.
	ErrMalformed = errors.New("encap: malformed")
	// ErrTooLarge reports a packet whose length exceeds the limit given to
	// [ReadPacket], or data that does not fit a length field.
	ErrTooLarge = errors.New("encap: too large")
)

// Command is an encapsulation command.
type Command uint16

// Encapsulation commands.
const (
	CommandNOP               Command = 0x0000
	CommandListServices      Command = 0x0004
	CommandListIdentity      Command = 0x0063
	CommandListInterfaces    Command = 0x0064
	CommandRegisterSession   Command = 0x0065
	CommandUnRegisterSession Command = 0x0066
	CommandSendRRData        Command = 0x006F
	CommandSendUnitData      Command = 0x0070
	CommandIndicateStatus    Command = 0x0072
	CommandCancel            Command = 0x0073
)

// String returns the name of the command, for example "SendRRData".
func (c Command) String() string {
	switch c {
	case CommandNOP:
		return "NOP"
	case CommandListServices:
		return "ListServices"
	case CommandListIdentity:
		return "ListIdentity"
	case CommandListInterfaces:
		return "ListInterfaces"
	case CommandRegisterSession:
		return "RegisterSession"
	case CommandUnRegisterSession:
		return "UnRegisterSession"
	case CommandSendRRData:
		return "SendRRData"
	case CommandSendUnitData:
		return "SendUnitData"
	case CommandIndicateStatus:
		return "IndicateStatus"
	case CommandCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("command 0x%04X", uint16(c))
	}
}

// Status is an encapsulation status.
type Status uint32

// Encapsulation status codes.
const (
	StatusSuccess              Status = 0x0000
	StatusInvalidCommand       Status = 0x0001
	StatusInsufficientMemory   Status = 0x0002
	StatusIncorrectData        Status = 0x0003
	StatusInvalidSessionHandle Status = 0x0064
	StatusInvalidLength        Status = 0x0065
	StatusUnsupportedProtocol  Status = 0x0069
)

// String returns the meaning of the status, for example
// "invalid session handle".
func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "success"
	case StatusInvalidCommand:
		return "invalid or unsupported command"
	case StatusInsufficientMemory:
		return "insufficient memory"
	case StatusIncorrectData:
		return "incorrect data"
	case StatusInvalidSessionHandle:
		return "invalid session handle"
	case StatusInvalidLength:
		return "invalid length"
	case StatusUnsupportedProtocol:
		return "unsupported encapsulation protocol revision"
	default:
		return fmt.Sprintf("status 0x%04X", uint32(s))
	}
}

// Header is the encapsulation header.
type Header struct {
	Command Command
	// Length is the length of the data that follows the header.
	Length uint16
	// Session is the session handle; 0 outside a session.
	Session uint32
	Status  Status
	// Context is the sender context: the originator's data, echoed in the
	// reply, which correlates replies with requests.
	Context [8]byte
	// Options must be 0.
	Options uint32
}

// AppendTo appends the encoding of the header.
func (h Header) AppendTo(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(h.Command))
	b = binary.LittleEndian.AppendUint16(b, h.Length)
	b = binary.LittleEndian.AppendUint32(b, h.Session)
	b = binary.LittleEndian.AppendUint32(b, uint32(h.Status))
	b = append(b, h.Context[:]...)
	return binary.LittleEndian.AppendUint32(b, h.Options)
}

// DecodeHeader decodes the header at the start of b.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: header of %d octets", ErrTruncated, len(b))
	}
	var h Header
	h.Command = Command(binary.LittleEndian.Uint16(b[0:]))
	h.Length = binary.LittleEndian.Uint16(b[2:])
	h.Session = binary.LittleEndian.Uint32(b[4:])
	h.Status = Status(binary.LittleEndian.Uint32(b[8:]))
	copy(h.Context[:], b[12:20])
	h.Options = binary.LittleEndian.Uint32(b[20:])
	return h, nil
}

// Packet is an encapsulation packet: a header and its data.
type Packet struct {
	Header
	Data []byte
}

// Encode returns the encoding of the packet; the header's length is set
// from the data.
func (p Packet) Encode() ([]byte, error) { return p.AppendTo(nil) }

// AppendTo appends the encoding of the packet.
func (p Packet) AppendTo(b []byte) ([]byte, error) {
	if len(p.Data) > MaxData {
		return b, fmt.Errorf("%w: %d octets of data", ErrTooLarge, len(p.Data))
	}
	h := p.Header
	h.Length = uint16(len(p.Data))
	return append(h.AppendTo(b), p.Data...), nil
}

// Decode decodes a packet that fills b exactly, as a UDP datagram carries
// it. The data aliases b.
func Decode(b []byte) (Packet, error) {
	h, err := DecodeHeader(b)
	if err != nil {
		return Packet{}, err
	}
	if int(h.Length) != len(b)-HeaderSize {
		return Packet{Header: h}, fmt.Errorf("%w: length %d with %d octets of data", ErrMalformed, h.Length, len(b)-HeaderSize)
	}
	return Packet{Header: h, Data: b[HeaderSize:]}, nil
}

// ReadPacket reads one packet from a stream. buf is reused when it is large
// enough; the packet's data aliases the returned buffer, which the caller
// passes to the next call. A length above max (or [MaxData] when max is 0)
// fails with [ErrTooLarge] before the data is read: the stream cannot be
// resynchronised and should be closed. io.EOF is returned as is when the
// stream ends between packets, io.ErrUnexpectedEOF inside one.
func ReadPacket(r io.Reader, buf []byte, max int) (Packet, []byte, error) {
	if max <= 0 || max > MaxData {
		max = MaxData
	}
	if cap(buf) < HeaderSize {
		buf = make([]byte, HeaderSize, 512)
	}
	buf = buf[:HeaderSize]
	if _, err := io.ReadFull(r, buf); err != nil {
		return Packet{}, buf, err
	}
	h, _ := DecodeHeader(buf)
	if int(h.Length) > max {
		return Packet{Header: h}, buf, fmt.Errorf("%w: %s with %d octets of data, limit %d", ErrTooLarge, h.Command, h.Length, max)
	}
	n := HeaderSize + int(h.Length)
	if cap(buf) < n {
		nb := make([]byte, n)
		copy(nb, buf)
		buf = nb
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf[HeaderSize:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Packet{Header: h}, buf, err
	}
	return Packet{Header: h, Data: buf[HeaderSize:n:n]}, buf, nil
}

// Register is the data of RegisterSession: the protocol version (1) and
// the options flags (0).
type Register struct {
	ProtocolVersion uint16
	Options         uint16
}

// ProtocolVersion is the encapsulation protocol version this package
// implements.
const ProtocolVersion = 1

// Encode returns the data.
func (r Register) Encode() []byte {
	b := binary.LittleEndian.AppendUint16(nil, r.ProtocolVersion)
	return binary.LittleEndian.AppendUint16(b, r.Options)
}

// DecodeRegister decodes the data of RegisterSession.
func DecodeRegister(b []byte) (Register, error) {
	if len(b) < 4 {
		return Register{}, fmt.Errorf("%w: RegisterSession data of %d octets", ErrTruncated, len(b))
	}
	return Register{binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])}, nil
}
