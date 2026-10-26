// SPDX-License-Identifier: MIT

// Package logix implements the Rockwell Automation Logix extensions of CIP:
// symbolic tag services (Read Tag, Write Tag, their fragmented forms,
// Read-Modify-Write), the tag list of the Symbol object, the Template
// object and the decoding of structures (UDTs).
//
// These services are vendor specific: they are not part of CIP and
// EtherNet/IP devices in general do not implement them. [Client] speaks to
// ControlLogix, CompactLogix and compatible controllers over any
// client.Doer (unconnected or Class 3); [TagServer] emulates a Logix tag
// database on a server.Server, for tests and simulators.
//
// The behaviour follows the publicly documented Logix 5000 Controllers
// Data Access manual (1756-PM020) and what independent implementations
// (pycomm3, cpppo) accept.
package logix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/otfabric/go-ethernetip/cip"
)

// ErrType reports a value used with a type it does not have.
var ErrType = errors.New("logix: wrong type")

// StructTypeCode is the type code that precedes a structure handle in tag
// services: 0x02A0.
const StructTypeCode uint16 = 0x02A0

// StringHandle is the structure handle of the predefined Logix STRING
// structure: a DINT length and 82 SINT characters, 88 octets with padding.
const StringHandle uint16 = 0x0FCE

// The capacity and size of a Logix STRING.
const (
	StringCapacity = 82
	StringSize     = 88
)

// Value is the value of a tag or of part of one: Count elements of an
// atomic type, or of a structure identified by its handle.
type Value struct {
	// Type is the atomic type; 0 for a structure.
	Type cip.DataType
	// Handle is the structure handle when Type is 0.
	Handle uint16
	// Count is the number of elements.
	Count int
	// Data holds the elements, little-endian, as the controller encodes
	// them.
	Data []byte
}

// IsStruct reports whether the value is a structure.
func (v Value) IsStruct() bool { return v.Type == 0 }

// ElemSize returns the size of one element: the type's size, or the data
// size divided by the count for a structure.
func (v Value) ElemSize() int {
	if v.IsStruct() {
		if v.Count == 0 {
			return 0
		}
		return len(v.Data) / v.Count
	}
	return v.Type.Size()
}

// String describes the value, for example "DINT[2] 0100000002000000".
func (v Value) String() string {
	t := v.Type.String()
	if v.IsStruct() {
		t = fmt.Sprintf("struct 0x%04X", v.Handle)
	}
	return fmt.Sprintf("%s[%d] %x", t, v.Count, v.Data)
}

// typeCode returns the type field of Read Tag replies and Write Tag
// requests.
func (v Value) appendType(b []byte) []byte {
	if v.IsStruct() {
		b = binary.LittleEndian.AppendUint16(b, StructTypeCode)
		return binary.LittleEndian.AppendUint16(b, v.Handle)
	}
	return binary.LittleEndian.AppendUint16(b, uint16(v.Type))
}

// decodeType reads the type field of a Read Tag reply.
func decodeType(r *cip.Reader) (cip.DataType, uint16) {
	code := r.Uint16()
	if code == StructTypeCode {
		return 0, r.Uint16()
	}
	return cip.DataType(code), 0
}

func (v Value) elem(i int) ([]byte, error) {
	n := v.ElemSize()
	if n == 0 || i < 0 || i >= v.Count || (i+1)*n > len(v.Data) {
		return nil, fmt.Errorf("%w: element %d of %s", ErrType, i, v)
	}
	return v.Data[i*n : (i+1)*n], nil
}

// Int returns element i of an integer value (SINT ... LINT, USINT ...
// ULINT, BYTE ... LWORD, BOOL) as int64; ULINT and LWORD values above
// MaxInt64 fail.
func (v Value) Int(i int) (int64, error) {
	b, err := v.elem(i)
	if err != nil {
		return 0, err
	}
	switch v.Type {
	case cip.TypeBOOL:
		if b[0] != 0 {
			return 1, nil
		}
		return 0, nil
	case cip.TypeSINT:
		return int64(int8(b[0])), nil
	case cip.TypeINT, cip.TypeITIME:
		return int64(int16(binary.LittleEndian.Uint16(b))), nil
	case cip.TypeDINT, cip.TypeSTIME, cip.TypeFTIME, cip.TypeTIME:
		return int64(int32(binary.LittleEndian.Uint32(b))), nil
	case cip.TypeLINT, cip.TypeLTIME:
		return int64(binary.LittleEndian.Uint64(b)), nil
	default:
		// Unsigned types below.
	}
	u, err := v.Uint(i)
	if err != nil {
		return 0, err
	}
	if u > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %d does not fit int64", ErrType, u)
	}
	return int64(u), nil
}

// Uint returns element i of an unsigned integer value.
func (v Value) Uint(i int) (uint64, error) {
	b, err := v.elem(i)
	if err != nil {
		return 0, err
	}
	if !v.Type.IsInteger() || v.Type.IsSigned() {
		return 0, fmt.Errorf("%w: %s is not unsigned", ErrType, v.Type)
	}
	switch len(b) {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	default:
		return binary.LittleEndian.Uint64(b), nil
	}
}

// Float returns element i of a REAL or LREAL value.
func (v Value) Float(i int) (float64, error) {
	b, err := v.elem(i)
	if err != nil {
		return 0, err
	}
	switch v.Type {
	case cip.TypeREAL:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), nil
	case cip.TypeLREAL:
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), nil
	default:
	}
	return 0, fmt.Errorf("%w: %s is not REAL or LREAL", ErrType, v.Type)
}

// Bool returns element i of a BOOL value, or bit i of a DWORD (BOOL
// arrays are DWORDs in Logix).
func (v Value) Bool(i int) (bool, error) {
	if v.Type == cip.TypeDWORD {
		if i < 0 {
			return false, fmt.Errorf("%w: bit %d of %s", ErrType, i, v)
		}
		w, err := v.elem(i / 32)
		if err != nil {
			return false, err
		}
		return binary.LittleEndian.Uint32(w)&(1<<(i%32)) != 0, nil
	}
	if v.Type != cip.TypeBOOL {
		return false, fmt.Errorf("%w: %s is not BOOL", ErrType, v.Type)
	}
	b, err := v.elem(i)
	if err != nil {
		return false, err
	}
	return b[0] != 0, nil
}

// Text returns the text of a Logix STRING value (element i).
func (v Value) Text(i int) (string, error) {
	if !v.IsStruct() || v.ElemSize() != StringSize {
		return "", fmt.Errorf("%w: %s is not a STRING", ErrType, v)
	}
	b, err := v.elem(i)
	if err != nil {
		return "", err
	}
	n := int(int32(binary.LittleEndian.Uint32(b)))
	if n < 0 || n > StringCapacity {
		return "", fmt.Errorf("%w: STRING length %d", ErrType, n)
	}
	return string(b[4 : 4+n]), nil
}

// Ints returns a value of integer type t with the elements vs; a value
// that does not fit t fails.
func Ints(t cip.DataType, vs ...int64) (Value, error) {
	if !t.IsInteger() && t != cip.TypeBOOL {
		return Value{}, fmt.Errorf("%w: %s is not an integer type", ErrType, t)
	}
	size := t.Size()
	data := make([]byte, 0, size*len(vs))
	for _, x := range vs {
		if t == cip.TypeBOOL {
			if x != 0 {
				data = append(data, 0xFF)
			} else {
				data = append(data, 0)
			}
			continue
		}
		bits := uint(8 * size)
		if t.IsSigned() {
			if bits < 64 && (x < -1<<(bits-1) || x > 1<<(bits-1)-1) {
				return Value{}, fmt.Errorf("%w: %d does not fit %s", ErrType, x, t)
			}
		} else if x < 0 || (bits < 64 && x > 1<<bits-1) {
			return Value{}, fmt.Errorf("%w: %d does not fit %s", ErrType, x, t)
		}
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], uint64(x))
		data = append(data, w[:size]...)
	}
	return Value{Type: t, Count: len(vs), Data: data}, nil
}

// Floats returns a REAL or LREAL value with the elements vs.
func Floats(t cip.DataType, vs ...float64) (Value, error) {
	if t != cip.TypeREAL && t != cip.TypeLREAL {
		return Value{}, fmt.Errorf("%w: %s is not REAL or LREAL", ErrType, t)
	}
	data := make([]byte, 0, 8*len(vs))
	for _, x := range vs {
		switch t {
		case cip.TypeREAL:
			data = cip.AppendFloat32(data, float32(x))
		default:
			data = cip.AppendFloat64(data, x)
		}
	}
	return Value{Type: t, Count: len(vs), Data: data}, nil
}

// Strings returns a Logix STRING value with the texts vs; a text longer
// than 82 octets fails.
func Strings(vs ...string) (Value, error) {
	data := make([]byte, 0, StringSize*len(vs))
	for _, s := range vs {
		if len(s) > StringCapacity {
			return Value{}, fmt.Errorf("%w: STRING of %d characters", ErrType, len(s))
		}
		var e [StringSize]byte
		binary.LittleEndian.PutUint32(e[:], uint32(len(s)))
		copy(e[4:], s)
		data = append(data, e[:]...)
	}
	return Value{Handle: StringHandle, Count: len(vs), Data: data}, nil
}
