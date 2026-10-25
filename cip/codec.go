// SPDX-License-Identifier: MIT

package cip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Errors of the codec. Decoding functions wrap them with detail; test with
// errors.Is.
var (
	// ErrTruncated reports data that ends before the structure it encodes.
	ErrTruncated = errors.New("cip: truncated")
	// ErrMalformed reports data that does not encode a valid structure: an
	// unknown segment type, an inconsistent length, an out-of-range value.
	ErrMalformed = errors.New("cip: malformed")
	// ErrTooLarge reports a value that does not fit the field that carries
	// its size (a path longer than 255 words, a string longer than its
	// length prefix allows, more than 65535 services in a packet).
	ErrTooLarge = errors.New("cip: too large")
)

// Reader decodes little-endian CIP values from a byte slice. It never reads
// past the slice: the first read that would fails sets a sticky error,
// [ErrTruncated], and every further read returns zero values. Check Err
// once after a sequence of reads.
//
// Byte slices returned by a Reader alias the input; copy them to keep them.
type Reader struct {
	b   []byte
	off int
	err error
}

// NewReader returns a Reader of b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Err returns the first error, or nil.
func (r *Reader) Err() error { return r.err }

// Len returns the number of unread octets.
func (r *Reader) Len() int { return len(r.b) - r.off }

// Offset returns the number of octets read.
func (r *Reader) Offset() int { return r.off }

// Fail records err as the reader's error unless one is already recorded.
func (r *Reader) Fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.off {
		r.err = fmt.Errorf("%w: need %d octets at offset %d, have %d", ErrTruncated, n, r.off, len(r.b)-r.off)
		return nil
	}
	p := r.b[r.off : r.off+n : r.off+n]
	r.off += n
	return p
}

// Uint8 reads a USINT, BYTE or SINT octet.
func (r *Reader) Uint8() uint8 {
	if p := r.take(1); p != nil {
		return p[0]
	}
	return 0
}

// Uint16 reads a UINT or WORD.
func (r *Reader) Uint16() uint16 {
	if p := r.take(2); p != nil {
		return binary.LittleEndian.Uint16(p)
	}
	return 0
}

// Uint32 reads a UDINT or DWORD.
func (r *Reader) Uint32() uint32 {
	if p := r.take(4); p != nil {
		return binary.LittleEndian.Uint32(p)
	}
	return 0
}

// Uint64 reads a ULINT or LWORD.
func (r *Reader) Uint64() uint64 {
	if p := r.take(8); p != nil {
		return binary.LittleEndian.Uint64(p)
	}
	return 0
}

// Int8 reads a SINT.
func (r *Reader) Int8() int8 { return int8(r.Uint8()) }

// Int16 reads an INT.
func (r *Reader) Int16() int16 { return int16(r.Uint16()) }

// Int32 reads a DINT.
func (r *Reader) Int32() int32 { return int32(r.Uint32()) }

// Int64 reads a LINT.
func (r *Reader) Int64() int64 { return int64(r.Uint64()) }

// Float32 reads a REAL.
func (r *Reader) Float32() float32 { return math.Float32frombits(r.Uint32()) }

// Float64 reads an LREAL.
func (r *Reader) Float64() float64 { return math.Float64frombits(r.Uint64()) }

// Bytes reads n octets. The result aliases the input.
func (r *Reader) Bytes(n int) []byte { return r.take(n) }

// Skip skips n octets.
func (r *Reader) Skip(n int) { r.take(n) }

// Rest returns the unread octets and consumes them.
func (r *Reader) Rest() []byte { return r.take(r.Len()) }

// ShortString reads a SHORT_STRING: a USINT length and that many
// characters.
func (r *Reader) ShortString() string {
	n := int(r.Uint8())
	return string(r.take(n))
}

// String reads a STRING: a UINT length and that many characters.
func (r *Reader) String() string {
	n := int(r.Uint16())
	return string(r.take(n))
}

// String2 reads a STRING2: a UINT length and that many 16-bit characters,
// decoded from UCS-2. Characters that are not valid code points become
// U+FFFD.
func (r *Reader) String2() string {
	n := int(r.Uint16())
	p := r.take(2 * n)
	if p == nil {
		return ""
	}
	rs := make([]rune, n)
	for i := range rs {
		c := rune(binary.LittleEndian.Uint16(p[2*i:]))
		if c >= 0xD800 && c <= 0xDFFF {
			c = 0xFFFD
		}
		rs[i] = c
	}
	return string(rs)
}

// AppendUint8 appends a USINT.
func AppendUint8(b []byte, v uint8) []byte { return append(b, v) }

// AppendUint16 appends a UINT.
func AppendUint16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }

// AppendUint32 appends a UDINT.
func AppendUint32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

// AppendUint64 appends a ULINT.
func AppendUint64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

// AppendFloat32 appends a REAL.
func AppendFloat32(b []byte, v float32) []byte { return AppendUint32(b, math.Float32bits(v)) }

// AppendFloat64 appends an LREAL.
func AppendFloat64(b []byte, v float64) []byte { return AppendUint64(b, math.Float64bits(v)) }

// AppendShortString appends a SHORT_STRING. It fails with [ErrTooLarge]
// for more than 255 octets.
func AppendShortString(b []byte, s string) ([]byte, error) {
	if len(s) > math.MaxUint8 {
		return b, fmt.Errorf("%w: SHORT_STRING of %d octets", ErrTooLarge, len(s))
	}
	return append(append(b, uint8(len(s))), s...), nil
}

// AppendString appends a STRING. It fails with [ErrTooLarge] for more than
// 65535 octets.
func AppendString(b []byte, s string) ([]byte, error) {
	if len(s) > math.MaxUint16 {
		return b, fmt.Errorf("%w: STRING of %d octets", ErrTooLarge, len(s))
	}
	return append(AppendUint16(b, uint16(len(s))), s...), nil
}

// AppendString2 appends a STRING2, encoding s in UCS-2. It fails with
// [ErrTooLarge] for more than 65535 characters and with [ErrMalformed] for
// a character outside the Basic Multilingual Plane.
func AppendString2(b []byte, s string) ([]byte, error) {
	rs := []rune(s)
	if len(rs) > math.MaxUint16 {
		return b, fmt.Errorf("%w: STRING2 of %d characters", ErrTooLarge, len(rs))
	}
	b = AppendUint16(b, uint16(len(rs)))
	for _, c := range rs {
		if c > 0xFFFF {
			return b, fmt.Errorf("%w: character %U does not fit STRING2", ErrMalformed, c)
		}
		b = AppendUint16(b, uint16(c))
	}
	return b, nil
}
