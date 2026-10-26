// SPDX-License-Identifier: MIT

package cip

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Segment is one segment of an EPATH: a [PortSegment], [LogicalSegment],
// [KeySegment], [SymbolSegment], [DataSegment] or [NetworkSegment]. The set
// is closed.
type Segment interface {
	// String describes the segment, for example "class 0x04".
	String() string
	appendTo(b []byte, packed bool) ([]byte, error)
}

// Path is an EPATH: a sequence of segments addressing an object, an
// attribute, a symbol, a route or a connection.
//
// Message Router requests, route paths and connection paths are padded
// EPATHs: 16- and 32-bit logical values, port segments and symbols are
// aligned on 16-bit words with pad octets. EDS files use packed EPATHs.
type Path []Segment

// LogicalType is the type of a [LogicalSegment].
type LogicalType uint8

// Logical segment types.
const (
	LogicalClass           LogicalType = 0 // class ID
	LogicalInstance        LogicalType = 1 // instance ID
	LogicalMember          LogicalType = 2 // member ID, also a Logix array element
	LogicalConnectionPoint LogicalType = 3 // connection point (an assembly instance in I/O paths)
	LogicalAttribute       LogicalType = 4 // attribute ID
	LogicalServiceID       LogicalType = 6 // service ID
)

// String returns "class", "instance", "member", "point", "attribute" or
// "service".
func (t LogicalType) String() string {
	switch t {
	case LogicalClass:
		return "class"
	case LogicalInstance:
		return "instance"
	case LogicalMember:
		return "member"
	case LogicalConnectionPoint:
		return "point"
	case LogicalAttribute:
		return "attribute"
	case LogicalServiceID:
		return "service"
	default:
		return fmt.Sprintf("logical-%d", uint8(t))
	}
}

// LogicalFormat is the width of a logical segment's value.
type LogicalFormat uint8

// Logical formats. FormatAuto picks the smallest that holds the value.
const (
	FormatAuto LogicalFormat = iota
	Format8
	Format16
	Format32
)

// LogicalSegment addresses a class, instance, member, connection point,
// attribute or service ID.
type LogicalSegment struct {
	Type  LogicalType
	Value uint32
	// Format forces the width of the value; the zero value picks the
	// smallest. Decoding records the width received.
	Format LogicalFormat
}

// String returns for example "class 0x04", "instance 100", "attribute 3".
func (s LogicalSegment) String() string {
	if s.Type == LogicalClass {
		return fmt.Sprintf("class 0x%02X", s.Value)
	}
	return fmt.Sprintf("%s %d", s.Type, s.Value)
}

func (s LogicalSegment) format() LogicalFormat {
	if s.Format != FormatAuto {
		return s.Format
	}
	switch {
	case s.Value <= math.MaxUint8:
		return Format8
	case s.Value <= math.MaxUint16:
		return Format16
	default:
		return Format32
	}
}

func (s LogicalSegment) appendTo(b []byte, packed bool) ([]byte, error) {
	if s.Type > 7 || s.Type == 5 {
		return b, fmt.Errorf("%w: logical type %d", ErrMalformed, s.Type)
	}
	head := 0x20 | byte(s.Type)<<2
	switch s.format() {
	case Format8:
		if s.Value > math.MaxUint8 {
			return b, fmt.Errorf("%w: %s does not fit 8 bits", ErrTooLarge, s)
		}
		return append(b, head, byte(s.Value)), nil
	case Format16:
		if s.Value > math.MaxUint16 {
			return b, fmt.Errorf("%w: %s does not fit 16 bits", ErrTooLarge, s)
		}
		b = append(b, head|1)
		if !packed {
			b = append(b, 0)
		}
		return AppendUint16(b, uint16(s.Value)), nil
	case Format32:
		if s.Type != LogicalInstance && s.Type != LogicalMember && s.Type != LogicalConnectionPoint {
			return b, fmt.Errorf("%w: 32-bit %s segments are not defined", ErrMalformed, s.Type)
		}
		b = append(b, head|2)
		if !packed {
			b = append(b, 0)
		}
		return AppendUint32(b, s.Value), nil
	default:
		return b, fmt.Errorf("%w: logical format %d", ErrMalformed, s.Format)
	}
}

// KeySegment is an electronic key (logical segment, special type, key
// format 4): the identity the target must have for a connection.
// Zero fields match anything.
type KeySegment struct {
	VendorID    uint16
	DeviceType  uint16
	ProductCode uint16
	Major       uint8 // 7 bits
	Minor       uint8
	// Compatible accepts a target that emulates the key (compatibility
	// bit); otherwise the key must match exactly.
	Compatible bool
}

// String returns for example "key 1/12/65001 2.3".
func (s KeySegment) String() string {
	c := ""
	if s.Compatible {
		c = " compatible"
	}
	return fmt.Sprintf("key %d/%d/%d %d.%d%s", s.VendorID, s.DeviceType, s.ProductCode, s.Major, s.Minor, c)
}

func (s KeySegment) appendTo(b []byte, _ bool) ([]byte, error) {
	if s.Major > 0x7F {
		return b, fmt.Errorf("%w: key major revision %d", ErrTooLarge, s.Major)
	}
	b = append(b, 0x34, 4)
	b = AppendUint16(b, s.VendorID)
	b = AppendUint16(b, s.DeviceType)
	b = AppendUint16(b, s.ProductCode)
	major := s.Major
	if s.Compatible {
		major |= 0x80
	}
	return append(b, major, s.Minor), nil
}

// PortSegment routes through a port of a device to a link address: port 1
// (the backplane) and link [0] address slot 0; an EtherNet/IP port with an
// IP address as text ("192.168.1.10") addresses a node on that network.
type PortSegment struct {
	Port uint16
	Link []byte
}

// String returns for example "port 1:0" or "port 2:192.168.1.10".
func (s PortSegment) String() string {
	if len(s.Link) == 1 {
		return fmt.Sprintf("port %d:%d", s.Port, s.Link[0])
	}
	printable := len(s.Link) > 0
	for _, c := range s.Link {
		if c < 0x20 || c > 0x7E {
			printable = false
		}
	}
	if printable {
		return fmt.Sprintf("port %d:%s", s.Port, s.Link)
	}
	return fmt.Sprintf("port %d:0x%x", s.Port, s.Link)
}

func (s PortSegment) appendTo(b []byte, packed bool) ([]byte, error) {
	if s.Port == 0 {
		return b, fmt.Errorf("%w: port 0", ErrMalformed)
	}
	if len(s.Link) == 0 || len(s.Link) > math.MaxUint8 {
		return b, fmt.Errorf("%w: port segment link of %d octets", ErrMalformed, len(s.Link))
	}
	start := len(b)
	head := byte(0)
	if s.Port < 15 {
		head = byte(s.Port)
	} else {
		head = 0x0F
	}
	ext := len(s.Link) > 1
	if ext {
		head |= 0x10
	}
	b = append(b, head)
	if ext {
		b = append(b, byte(len(s.Link)))
	}
	if s.Port >= 15 {
		b = AppendUint16(b, s.Port)
	}
	b = append(b, s.Link...)
	if !packed && (len(b)-start)%2 != 0 {
		b = append(b, 0)
	}
	return b, nil
}

// SymbolSegment is an ANSI extended symbol segment (0x91): a tag name, or
// one member of a dotted tag name.
type SymbolSegment struct {
	Name string
}

// String returns for example "symbol MyTag".
func (s SymbolSegment) String() string { return "symbol " + s.Name }

func (s SymbolSegment) appendTo(b []byte, packed bool) ([]byte, error) {
	if len(s.Name) == 0 || len(s.Name) > math.MaxUint8 {
		return b, fmt.Errorf("%w: symbol of %d octets", ErrMalformed, len(s.Name))
	}
	b = append(b, 0x91, byte(len(s.Name)))
	b = append(b, s.Name...)
	if !packed && len(s.Name)%2 != 0 {
		b = append(b, 0)
	}
	return b, nil
}

// DataSegment is a simple data segment (0x80): configuration data at the
// end of a connection path. Its length must be even (a number of words).
type DataSegment struct {
	Data []byte
}

// String returns for example "data 0102".
func (s DataSegment) String() string { return "data " + hex.EncodeToString(s.Data) }

func (s DataSegment) appendTo(b []byte, _ bool) ([]byte, error) {
	if len(s.Data)%2 != 0 || len(s.Data)/2 > math.MaxUint8 {
		return b, fmt.Errorf("%w: data segment of %d octets", ErrMalformed, len(s.Data))
	}
	b = append(b, 0x80, byte(len(s.Data)/2))
	return append(b, s.Data...), nil
}

// NetworkSegment is a network segment (0x40..0x5F): schedule, fixed tag,
// production inhibit time and the extended network segments. Subtypes
// 0x00..0x0F carry one octet; subtypes 0x10..0x1F carry a length in words.
type NetworkSegment struct {
	Subtype uint8
	Data    []byte
}

// NetworkProductionInhibit is the production inhibit time network segment
// subtype (milliseconds, one octet).
const NetworkProductionInhibit uint8 = 0x03

// String returns for example "network 0x43 0a".
func (s NetworkSegment) String() string {
	return fmt.Sprintf("network 0x%02X %x", 0x40|s.Subtype, s.Data)
}

func (s NetworkSegment) appendTo(b []byte, _ bool) ([]byte, error) {
	if s.Subtype > 0x1F {
		return b, fmt.Errorf("%w: network subtype 0x%02X", ErrMalformed, s.Subtype)
	}
	if s.Subtype < 0x10 {
		if len(s.Data) != 1 {
			return b, fmt.Errorf("%w: network segment 0x%02X needs 1 octet", ErrMalformed, 0x40|s.Subtype)
		}
		return append(b, 0x40|s.Subtype, s.Data[0]), nil
	}
	if len(s.Data)%2 != 0 || len(s.Data)/2 > math.MaxUint8 {
		return b, fmt.Errorf("%w: network segment of %d octets", ErrMalformed, len(s.Data))
	}
	b = append(b, 0x40|s.Subtype, byte(len(s.Data)/2))
	return append(b, s.Data...), nil
}

// ClassSegment returns a logical class segment.
func ClassSegment(c Class) LogicalSegment {
	return LogicalSegment{Type: LogicalClass, Value: uint32(c)}
}

// InstanceSegment returns a logical instance segment.
func InstanceSegment(i uint32) LogicalSegment {
	return LogicalSegment{Type: LogicalInstance, Value: i}
}

// AttributeSegment returns a logical attribute segment.
func AttributeSegment(a uint16) LogicalSegment {
	return LogicalSegment{Type: LogicalAttribute, Value: uint32(a)}
}

// MemberSegment returns a logical member segment, which Logix uses for an
// array element.
func MemberSegment(m uint32) LogicalSegment {
	return LogicalSegment{Type: LogicalMember, Value: m}
}

// ConnectionPointSegment returns a logical connection point segment.
func ConnectionPointSegment(p uint32) LogicalSegment {
	return LogicalSegment{Type: LogicalConnectionPoint, Value: p}
}

// ObjectPath returns the path of an instance: class, instance.
func ObjectPath(c Class, instance uint32) Path {
	return Path{ClassSegment(c), InstanceSegment(instance)}
}

// AttributePath returns the path of an attribute: class, instance,
// attribute.
func AttributePath(c Class, instance uint32, attribute uint16) Path {
	return Path{ClassSegment(c), InstanceSegment(instance), AttributeSegment(attribute)}
}

// MessageRouterPath is the path of the Message Router, the target of
// Class 3 connections and Multiple Service Packets.
func MessageRouterPath() Path { return ObjectPath(ClassMessageRouter, 1) }

// ConnectionManagerPath is the path of the Connection Manager instance.
func ConnectionManagerPath() Path { return ObjectPath(ClassConnectionManager, 1) }

// Encode returns the padded encoding of the path.
func (p Path) Encode() ([]byte, error) { return p.AppendTo(nil, false) }

// EncodePacked returns the packed encoding of the path, as EDS files
// write it.
func (p Path) EncodePacked() ([]byte, error) { return p.AppendTo(nil, true) }

// AppendTo appends the encoding of the path.
func (p Path) AppendTo(b []byte, packed bool) ([]byte, error) {
	var err error
	for _, s := range p {
		if s == nil {
			return b, fmt.Errorf("%w: nil segment", ErrMalformed)
		}
		if b, err = s.appendTo(b, packed); err != nil {
			return b, err
		}
	}
	return b, nil
}

// Words returns the size of the padded encoding in 16-bit words, as the
// path size fields carry it, and fails when the path cannot be encoded or
// is longer than 255 words.
func (p Path) Words() (int, error) {
	b, err := p.Encode()
	if err != nil {
		return 0, err
	}
	if len(b)%2 != 0 || len(b)/2 > math.MaxUint8 {
		return 0, fmt.Errorf("%w: path of %d octets", ErrTooLarge, len(b))
	}
	return len(b) / 2, nil
}

// logical returns the value of the first logical segment of type t.
func (p Path) logical(t LogicalType) (uint32, bool) {
	for _, s := range p {
		if l, ok := s.(LogicalSegment); ok && l.Type == t {
			return l.Value, true
		}
	}
	return 0, false
}

// Class returns the first class ID of the path, or [ClassSymbol] for a path
// that starts with a symbol.
func (p Path) Class() (Class, bool) {
	if len(p) > 0 {
		if _, ok := p[0].(SymbolSegment); ok {
			return ClassSymbol, true
		}
	}
	v, ok := p.logical(LogicalClass)
	return Class(v), ok
}

// Instance returns the first instance ID of the path.
func (p Path) Instance() (uint32, bool) { return p.logical(LogicalInstance) }

// Attribute returns the first attribute ID of the path.
func (p Path) Attribute() (uint16, bool) {
	v, ok := p.logical(LogicalAttribute)
	return uint16(v), ok
}

// Member returns the first member ID of the path.
func (p Path) Member() (uint32, bool) { return p.logical(LogicalMember) }

// Symbolic reports whether the path starts with a symbol segment.
func (p Path) Symbolic() bool {
	if len(p) == 0 {
		return false
	}
	_, ok := p[0].(SymbolSegment)
	return ok
}

// String describes the path. A path of a class, an instance and optionally
// an attribute is written "@class/instance[/attribute]" with decimal
// numbers, as in "@1/1/7"; any other path as its segments in brackets.
func (p Path) String() string {
	if len(p) >= 1 && len(p) <= 3 {
		var parts []string
		want := []LogicalType{LogicalClass, LogicalInstance, LogicalAttribute}
		for i, s := range p {
			l, ok := s.(LogicalSegment)
			if !ok || l.Type != want[i] {
				parts = nil
				break
			}
			parts = append(parts, strconv.FormatUint(uint64(l.Value), 10))
		}
		if parts != nil {
			return "@" + strings.Join(parts, "/")
		}
	}
	var sb strings.Builder
	for i, s := range p {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte('[')
		if s == nil {
			sb.WriteString("nil")
		} else {
			sb.WriteString(s.String())
		}
		sb.WriteByte(']')
	}
	return sb.String()
}

// maxPathSegments bounds the segments DecodePath accepts, so that a peer
// cannot make a decoder allocate without limit.
const maxPathSegments = 256

// DecodePath decodes a padded EPATH that fills b exactly.
func DecodePath(b []byte) (Path, error) { return decodePath(b, false) }

// DecodePacked decodes a packed EPATH that fills b exactly.
func DecodePacked(b []byte) (Path, error) { return decodePath(b, true) }

func decodePath(b []byte, packed bool) (Path, error) {
	r := NewReader(b)
	var p Path
	for r.Len() > 0 {
		if len(p) >= maxPathSegments {
			return nil, fmt.Errorf("%w: more than %d segments", ErrTooLarge, maxPathSegments)
		}
		s, err := decodeSegment(r, packed)
		if err != nil {
			return nil, err
		}
		p = append(p, s)
	}
	return p, nil
}

func decodeSegment(r *Reader, packed bool) (Segment, error) {
	at := r.Offset()
	head := r.Uint8()
	var s Segment
	switch head >> 5 {
	case 0:
		s = decodePort(r, head, packed)
	case 1:
		if head == 0x34 {
			s = decodeKey(r)
			break
		}
		var err error
		if s, err = decodeLogical(r, head, packed); err != nil {
			return nil, fmt.Errorf("%w at offset %d", err, at)
		}
	case 2:
		sub := head & 0x1F
		if sub < 0x10 {
			s = NetworkSegment{Subtype: sub, Data: copyBytes(r.Bytes(1))}
		} else {
			n := int(r.Uint8())
			s = NetworkSegment{Subtype: sub, Data: copyBytes(r.Bytes(2 * n))}
		}
	case 3:
		n := int(head & 0x1F)
		if n == 0 {
			return nil, fmt.Errorf("%w: extended symbolic segment at offset %d", ErrMalformed, at)
		}
		s = SymbolSegment{Name: string(r.Bytes(n))}
	case 4:
		switch head {
		case 0x80:
			n := int(r.Uint8())
			s = DataSegment{Data: copyBytes(r.Bytes(2 * n))}
		case 0x91:
			n := int(r.Uint8())
			name := string(r.Bytes(n))
			if !packed && n%2 != 0 {
				r.Skip(1)
			}
			if n == 0 {
				return nil, fmt.Errorf("%w: empty symbol at offset %d", ErrMalformed, at)
			}
			s = SymbolSegment{Name: name}
		default:
			return nil, fmt.Errorf("%w: data segment 0x%02X at offset %d", ErrMalformed, head, at)
		}
	default:
		return nil, fmt.Errorf("%w: segment type 0x%02X at offset %d", ErrMalformed, head, at)
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func decodePort(r *Reader, head byte, packed bool) Segment {
	start := r.Offset() - 1
	var s PortSegment
	n := 1
	ext := head&0x10 != 0
	if ext {
		n = int(r.Uint8())
	}
	s.Port = uint16(head & 0x0F)
	if s.Port == 0x0F {
		s.Port = r.Uint16()
	}
	s.Link = copyBytes(r.Bytes(n))
	if !packed && (r.Offset()-start)%2 != 0 && r.Len() > 0 {
		r.Skip(1)
	}
	if r.Err() == nil && (n == 0 || s.Port == 0) {
		r.Fail(fmt.Errorf("%w: port segment with port %d and %d link octets", ErrMalformed, s.Port, n))
	}
	return s
}

func decodeKey(r *Reader) Segment {
	if f := r.Uint8(); f != 4 && r.Err() == nil {
		r.Fail(fmt.Errorf("%w: electronic key format %d", ErrMalformed, f))
		return nil
	}
	s := KeySegment{VendorID: r.Uint16(), DeviceType: r.Uint16(), ProductCode: r.Uint16()}
	major := r.Uint8()
	s.Major, s.Compatible = major&0x7F, major&0x80 != 0
	s.Minor = r.Uint8()
	return s
}

func decodeLogical(r *Reader, head byte, packed bool) (Segment, error) {
	t := LogicalType((head >> 2) & 7)
	if t == 5 || t == 7 {
		return nil, fmt.Errorf("%w: logical segment 0x%02X", ErrMalformed, head)
	}
	s := LogicalSegment{Type: t}
	switch head & 3 {
	case 0:
		s.Format, s.Value = Format8, uint32(r.Uint8())
	case 1:
		if !packed {
			r.Skip(1)
		}
		s.Format, s.Value = Format16, uint32(r.Uint16())
	default:
		// Format 3 is reserved; pycomm3 sends it for 32-bit values, so it is
		// read as 32 bits like format 2.
		//
		// 32-bit class, attribute and service IDs are not defined (the
		// encoder refuses them); accepting one would let Path.Class and
		// Path.Attribute silently truncate it to 16 bits.
		if t != LogicalInstance && t != LogicalMember && t != LogicalConnectionPoint {
			return nil, fmt.Errorf("%w: 32-bit %s segment 0x%02X", ErrMalformed, t, head)
		}
		if !packed {
			r.Skip(1)
		}
		s.Format, s.Value = Format32, r.Uint32()
	}
	return s, nil
}

// ParsePath parses the text form of a path:
//
//   - "@class/instance[/attribute]", numbers decimal or 0x-prefixed hex,
//     "@4/100/3", "@0x04/0x64/3";
//   - the hex octets of a padded EPATH, "20 04 24 64 30 03" (spaces
//     optional).
func ParsePath(s string) (Path, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@") {
		parts := strings.Split(s[1:], "/")
		if len(parts) < 1 || len(parts) > 3 {
			return nil, fmt.Errorf("%w: path %q: want @class/instance[/attribute]", ErrMalformed, s)
		}
		var p Path
		types := []LogicalType{LogicalClass, LogicalInstance, LogicalAttribute}
		limits := []uint64{math.MaxUint16, math.MaxUint32, math.MaxUint16}
		for i, part := range parts {
			v, err := strconv.ParseUint(strings.TrimSpace(part), 0, 32)
			if err != nil || v > limits[i] {
				return nil, fmt.Errorf("%w: path %q: bad %s %q", ErrMalformed, s, types[i], part)
			}
			p = append(p, LogicalSegment{Type: types[i], Value: uint32(v)})
		}
		return p, nil
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, fmt.Errorf("%w: path %q: neither @class/instance/attribute nor hex", ErrMalformed, s)
	}
	return DecodePath(b)
}

// ParseRoute parses a route path in the comma-separated form "port/link":
// "1/0" (backplane, slot 0), "1/0,2/192.168.1.10" (slot 0, then port 2 to
// a node by IP address). Numeric links of 0..255 are one octet; any other
// link is its text.
func ParseRoute(s string) (Path, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var p Path
	for _, hop := range strings.Split(s, ",") {
		port, link, ok := strings.Cut(strings.TrimSpace(hop), "/")
		if !ok {
			return nil, fmt.Errorf("%w: route hop %q: want port/link", ErrMalformed, hop)
		}
		pv, err := strconv.ParseUint(port, 0, 16)
		if err != nil || pv == 0 {
			return nil, fmt.Errorf("%w: route hop %q: bad port", ErrMalformed, hop)
		}
		seg := PortSegment{Port: uint16(pv)}
		if lv, err := strconv.ParseUint(link, 0, 8); err == nil {
			seg.Link = []byte{byte(lv)}
		} else if link != "" {
			seg.Link = []byte(link)
		} else {
			return nil, fmt.Errorf("%w: route hop %q: empty link", ErrMalformed, hop)
		}
		p = append(p, seg)
	}
	return p, nil
}
