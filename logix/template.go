// SPDX-License-Identifier: MIT

package logix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/otfabric/go-ethernetip/cip"
)

// SymbolType is the type word of a symbol (Symbol object attribute 2) and
// of a template member: an atomic type code, or a structure's template ID
// with the structure bit, plus the number of array dimensions.
type SymbolType uint16

// Symbol type bits.
const (
	symStruct   SymbolType = 0x8000
	symSystem   SymbolType = 0x1000
	symDimShift            = 13
)

// NewAtomicType returns the symbol type of an atomic type with dims array
// dimensions (0 to 3); for BOOL, bit is the bit position (0 to 7).
func NewAtomicType(t cip.DataType, dims int, bit int) SymbolType {
	st := SymbolType(t) | SymbolType(dims&3)<<symDimShift
	if t == cip.TypeBOOL {
		st |= SymbolType(bit&7) << 8
	}
	return st
}

// NewStructType returns the symbol type of a structure of template id with
// dims array dimensions.
func NewStructType(template uint16, dims int) SymbolType {
	return symStruct | SymbolType(template&0x0FFF) | SymbolType(dims&3)<<symDimShift
}

// IsStruct reports whether the type is a structure.
func (s SymbolType) IsStruct() bool { return s&symStruct != 0 }

// IsSystem reports whether the system bit is set (system tags, programs).
func (s SymbolType) IsSystem() bool { return s&symSystem != 0 }

// Dims returns the number of array dimensions.
func (s SymbolType) Dims() int { return int(s>>symDimShift) & 3 }

// Template returns the template ID of a structure type.
func (s SymbolType) Template() uint16 { return uint16(s & 0x0FFF) }

// Atomic returns the atomic type of a non-structure type.
func (s SymbolType) Atomic() cip.DataType { return cip.DataType(s & 0xFF) }

// Bit returns the bit position of a BOOL.
func (s SymbolType) Bit() int { return int(s>>8) & 7 }

// String returns for example "DINT[2 dims]" or "struct 0x0123".
func (s SymbolType) String() string {
	var t string
	if s.IsStruct() {
		t = fmt.Sprintf("struct 0x%03X", s.Template())
	} else {
		t = s.Atomic().String()
	}
	if d := s.Dims(); d > 0 {
		t += fmt.Sprintf("[%d dims]", d)
	}
	return t
}

// Member is a member of a structure template.
type Member struct {
	Name string
	// Type is the member's type; for a BOOL member Info is its bit number
	// in the host octet at Offset.
	Type SymbolType
	// Info is the array length of an array member, or the bit number of a
	// BOOL member.
	Info uint16
	// Offset is the member's offset in the structure, in octets.
	Offset uint32
}

// Hidden reports whether the member is a host of BOOL members or another
// compiler-generated member that is not part of the user's definition.
func (m Member) Hidden() bool {
	return strings.HasPrefix(m.Name, "ZZZZZZZZZZ") || strings.HasPrefix(m.Name, "__")
}

// Template is a structure definition of the Template object.
type Template struct {
	// ID is the template instance.
	ID uint16
	// Name is the structure's name ("ASCIISTRING82" for STRING).
	Name string
	// Handle is the structure handle that tag services carry.
	Handle uint16
	// Size is the size of the structure in octets (attribute 5).
	Size    uint32
	Members []Member
}

// memberCount returns attribute 2, the number of members; AddTemplate
// keeps it at most 65535.
func (t *Template) memberCount() uint16 {
	n := len(t.Members)
	if n > 0xFFFF {
		return 0xFFFF
	}
	return uint16(n)
}

// definition returns the template's definition as Read_Template returns
// it: 8 octets per member, then the name ("Name;n...") and each member's
// name, NUL-terminated.
func (t *Template) definition() []byte {
	var b []byte
	for _, m := range t.Members {
		typ := m.Type
		if !typ.IsStruct() && typ.Atomic() == cip.TypeBOOL && typ.Dims() == 0 {
			// Logix gives a BOOL member's bit in the info word only: its
			// type is plain BOOL (0x00C1), which pycomm3 relies on.
			typ &^= 7 << 8
		}
		b = binary.LittleEndian.AppendUint16(b, m.Info)
		b = binary.LittleEndian.AppendUint16(b, uint16(typ))
		b = binary.LittleEndian.AppendUint32(b, m.Offset)
	}
	b = append(b, t.Name+";n"...)
	b = append(b, 0)
	for _, m := range t.Members {
		b = append(b, m.Name...)
		b = append(b, 0)
	}
	return b
}

// definitionWords returns attribute 4, the size of the definition in
// 32-bit words: reading the definition takes words×4 − 23 octets (Logix
// 5000 Controllers Data Access, 1756-PM020), so n octets need
// ⌈(n + 23) / 4⌉ words.
// A definition beyond the 32-bit field is clamped (AddTemplate keeps a
// served definition far below it).
func definitionWords(n int) uint32 {
	if n < 0 {
		return 0
	}
	w := int64(n/4) + int64((n%4+26)/4)
	if w > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(w)
}

// readLen returns how many octets the client asks Read Template for, for
// a definition of words words: words×4 − 20, as RSLogix 5000 asks a
// 1756-L63 for its COUNTER (30 words, 100 octets) and TIMER (24 words, 76
// octets) templates, and the controller answers with that many octets and
// success (testdata/captures, controllogix-factorytalk frames 102 to 113).
// The − 23 of definitionLen would leave the last 3 octets, the end of the
// last member's name, unread. A server that holds less answers the rest.
// It does not overflow on 32-bit platforms (see definitionLen).
func readLen(words uint32) int {
	if words > 1<<28 {
		return 1 << 30
	}
	return int(words)*4 - 20
}

// definitionLen returns the octets of a definition of words words; it
// does not overflow on 32-bit platforms (a size above 1 GiB, which no
// caller accepts, is returned as 1 GiB).
func definitionLen(words uint32) int {
	if words > 1<<28 {
		return 1 << 30
	}
	return int(words)*4 - 23
}

// parseDefinition decodes a template definition of members members.
func parseDefinition(b []byte, members int) (string, []Member, error) {
	if members < 0 || members*8 > len(b) {
		return "", nil, fmt.Errorf("logix: template of %d members in %d octets", members, len(b))
	}
	ms := make([]Member, members)
	for i := range ms {
		p := b[8*i:]
		ms[i] = Member{
			Info:   binary.LittleEndian.Uint16(p),
			Type:   SymbolType(binary.LittleEndian.Uint16(p[2:])),
			Offset: binary.LittleEndian.Uint32(p[4:]),
		}
	}
	// Only the template's name and one name per member are used: what
	// follows them stays in one piece.
	names := bytes.SplitN(b[8*members:], []byte{0}, members+2)
	if len(names) < members+1 {
		return "", nil, fmt.Errorf("logix: template with %d names for %d members", len(names)-1, members)
	}
	name := string(names[0])
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	for i := range ms {
		ms[i].Name = string(names[i+1])
	}
	return name, ms, nil
}

// StringTemplate is the template of the predefined STRING type.
var StringTemplate = Template{
	ID:     0x0FCE,
	Name:   "ASCIISTRING82",
	Handle: StringHandle,
	Size:   StringSize,
	Members: []Member{
		{Name: "LEN", Type: NewAtomicType(cip.TypeDINT, 0, 0), Offset: 0},
		{Name: "DATA", Type: NewAtomicType(cip.TypeSINT, 1, 0), Info: StringCapacity, Offset: 4},
	},
}

// Field is a decoded structure member.
type Field struct {
	Name string
	// Value is the member's value; a BOOL member is one BOOL element.
	Value Value
	// Struct is the decoded value of a structure member, when its
	// template was available.
	Struct []Field
}

// Decode decodes one element of the structure from data (at least Size
// octets). Members of structure type are decoded with lookup when it finds
// their template, and are otherwise left raw in Value. Hidden members are
// left out. The fields' data is one copy of data, shared by members that
// overlap: what a Decode allocates grows with data and the number of
// members, not with their product.
func (t *Template) Decode(data []byte, lookup func(id uint16) *Template) ([]Field, error) {
	budget := maxFields
	return t.decode(append([]byte(nil), data...), lookup, 0, &budget)
}

// maxNesting bounds the nesting of structures Decode follows, so that a
// template that contains itself (directly or not) cannot recurse forever;
// maxFields bounds the fields of one Decode, so that templates whose
// members overlap cannot make the work grow exponentially with nesting.
const (
	maxNesting = 32
	maxFields  = 1 << 16
)

func (t *Template) decode(data []byte, lookup func(id uint16) *Template, depth int, budget *int) ([]Field, error) {
	if depth > maxNesting {
		return nil, fmt.Errorf("%w: structure %s nested more than %d deep", ErrType, t.Name, maxNesting)
	}
	if int64(len(data)) < int64(t.Size) {
		return nil, fmt.Errorf("%w: %d octets for structure %s of %d", ErrType, len(data), t.Name, t.Size)
	}
	var out []Field
	for _, m := range t.Members {
		if m.Hidden() {
			continue
		}
		if *budget--; *budget < 0 {
			return nil, fmt.Errorf("%w: structure %s has more than %d fields", ErrType, t.Name, maxFields)
		}
		count := 1
		if m.Type.Dims() > 0 || (m.Info > 0 && m.Type.Atomic() != cip.TypeBOOL) {
			count = int(m.Info)
		}
		f := Field{Name: m.Name}
		switch {
		case m.Type.IsStruct():
			var sub *Template
			if lookup != nil {
				sub = lookup(m.Type.Template())
			}
			if sub == nil {
				f.Value = Value{Handle: 0, Count: count, Data: tail(data, m.Offset, 0)}
				break
			}
			// In 64 bits: sub.Size is any 32-bit value of a controller,
			// count up to 65535.
			n := int64(sub.Size) * int64(count)
			if n > math.MaxInt32 {
				return nil, fmt.Errorf("%w: member %s of %d octets", ErrType, m.Name, n)
			}
			raw := tail(data, m.Offset, int(n))
			f.Value = Value{Handle: sub.Handle, Count: count, Data: raw}
			if count == 1 && int64(len(raw)) >= int64(sub.Size) {
				s, err := sub.decode(raw, lookup, depth+1, budget)
				if err != nil {
					return nil, err
				}
				f.Struct = s
			}
		case m.Type.Atomic() == cip.TypeBOOL && m.Type.Dims() == 0:
			if int64(m.Offset) >= int64(len(data)) {
				return nil, fmt.Errorf("%w: member %s beyond the structure", ErrType, m.Name)
			}
			bit := (data[m.Offset] >> (m.Info & 7)) & 1
			f.Value = Value{Type: cip.TypeBOOL, Count: 1, Data: []byte{bit}}
		default:
			at := m.Type.Atomic()
			size := at.Size()
			if size == 0 {
				return nil, fmt.Errorf("%w: member %s of type %s", ErrType, m.Name, at)
			}
			if at == cip.TypeBOOL {
				// BOOL arrays are DWORDs.
				at, size, count = cip.TypeDWORD, 4, (count+31)/32
			}
			raw := tail(data, m.Offset, size*count)
			if len(raw) < size*count {
				return nil, fmt.Errorf("%w: member %s beyond the structure", ErrType, m.Name)
			}
			f.Value = Value{Type: at, Count: count, Data: raw}
		}
		out = append(out, f)
	}
	return out, nil
}

// tail returns n octets of data from off (or the rest when n is 0),
// clamped to data. The result shares data, with its capacity cut so that
// an append to it does not write into data.
func tail(data []byte, off uint32, n int) []byte {
	if int64(off) >= int64(len(data)) {
		return nil
	}
	d := data[off:]
	if n > 0 && n < len(d) {
		d = d[:n]
	}
	return d[:len(d):len(d)]
}
