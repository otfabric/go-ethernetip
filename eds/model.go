// SPDX-License-Identifier: MIT

package eds

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/otfabric/go-ethernetip/cip"
)

// Device is the [Device] section: the identity of the device.
type Device struct {
	VendorID    uint16
	VendorName  string
	DeviceType  cip.DeviceType
	TypeName    string
	ProductCode uint16
	Revision    cip.Revision
	ProductName string
	Catalog     string
}

func parseUint(f Field, bits int) (uint64, error) {
	if f.Kind != FieldToken {
		return 0, fmt.Errorf("not a number: %s", f)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(f.Value), 0, bits)
	if err != nil {
		return 0, fmt.Errorf("not a %d-bit number: %s", bits, f.Value)
	}
	return v, nil
}

// parseWide reads an unsigned number of up to 64 bits; the callers check
// it against the width of their field, named by bits in the error.
func parseWide(f Field, bits int) (uint64, error) {
	if f.Kind != FieldToken {
		return 0, fmt.Errorf("not a number: %s", f)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(f.Value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("not a %d-bit number: %s", bits, f.Value)
	}
	return v, nil
}

// parseU8, parseU16 and parseU32 read a number of a field of that width;
// a value out of range is an error, never truncated.
func parseU8(f Field) (uint8, error) {
	v, err := parseWide(f, 8)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint8 {
		return 0, fmt.Errorf("not a 8-bit number: %s", f.Value)
	}
	return uint8(v), nil
}

func parseU16(f Field) (uint16, error) {
	v, err := parseWide(f, 16)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint16 {
		return 0, fmt.Errorf("not a 16-bit number: %s", f.Value)
	}
	return uint16(v), nil
}

func parseU32(f Field) (uint32, error) {
	v, err := parseWide(f, 32)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("not a 32-bit number: %s", f.Value)
	}
	return uint32(v), nil
}

// parseSize reads a size field of a bits-wide field whose values above
// limit (at most math.MaxInt32) are rejected, as an int.
func parseSize(f Field, bits int, limit uint64) (int, error) {
	v, err := parseWide(f, bits)
	if err != nil {
		return 0, err
	}
	if v>>bits != 0 {
		return 0, fmt.Errorf("not a %d-bit number: %s", bits, f.Value)
	}
	if v > limit || v > math.MaxInt32 {
		return 0, fmt.Errorf("%s is above %d", f.Value, limit)
	}
	return int(v & math.MaxInt32), nil
}

// signExtend returns the low bits of u as a two's complement number of
// that width: 0xFFFF of 16 bits is -1. bits is 1 to 64.
func signExtend(u uint64, bits int) int64 {
	if bits < 64 {
		u &= 1<<bits - 1
		if u&(1<<(bits-1)) != 0 {
			u |= ^uint64(0) << bits
		}
	}
	if u > math.MaxInt64 {
		// Negative: -(^u) - 1, where ^u is at most MaxInt64.
		n := ^u
		if n > math.MaxInt64 {
			return 0
		}
		return -int64(n) - 1
	}
	return int64(u)
}

func parseInt(f Field) (int64, error) {
	if f.Kind != FieldToken {
		return 0, fmt.Errorf("not a number: %s", f)
	}
	s := strings.TrimSpace(f.Value)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return signExtend(v, 64), err
	}
	return strconv.ParseInt(s, 10, 64)
}

// keyEntry returns the entry kw of a section.
func keyEntry(s *Section, kw string) (Entry, error) {
	e, ok := s.Entry(kw)
	if !ok {
		return Entry{}, fmt.Errorf("[%s] has no %s", s.Name, kw)
	}
	return e, nil
}

// keyU8 and keyU16 read an unsigned entry of a section.
func keyU8(s *Section, kw string) (uint8, error) {
	e, err := keyEntry(s, kw)
	if err != nil {
		return 0, err
	}
	v, err := parseU8(e.Field(0))
	if err != nil {
		return 0, fmt.Errorf("line %d: [%s] %s: %w", e.Line, s.Name, kw, err)
	}
	return v, nil
}

func keyU16(s *Section, kw string) (uint16, error) {
	e, err := keyEntry(s, kw)
	if err != nil {
		return 0, err
	}
	v, err := parseU16(e.Field(0))
	if err != nil {
		return 0, fmt.Errorf("line %d: [%s] %s: %w", e.Line, s.Name, kw, err)
	}
	return v, nil
}

func keyString(s *Section, kw string) string {
	e, _ := s.Entry(kw)
	return e.Field(0).Value
}

// Device returns the identity of the [Device] section.
func (f *File) Device() (Device, error) {
	s := f.Section("Device")
	if s == nil {
		return Device{}, fmt.Errorf("eds: no [Device] section")
	}
	var d Device
	var err error
	u16 := func(kw string) uint16 {
		if err != nil {
			return 0
		}
		var v uint16
		v, err = keyU16(s, kw)
		return v
	}
	u8 := func(kw string) uint8 {
		if err != nil {
			return 0
		}
		var v uint8
		v, err = keyU8(s, kw)
		return v
	}
	d.VendorID = u16("VendCode")
	d.DeviceType = cip.DeviceType(u16("ProdType"))
	d.ProductCode = u16("ProdCode")
	d.Revision.Major = u8("MajRev")
	d.Revision.Minor = u8("MinRev")
	if err != nil {
		return d, fmt.Errorf("eds: %w", err)
	}
	d.VendorName = keyString(s, "VendName")
	d.TypeName = keyString(s, "ProdTypeStr")
	d.ProductName = keyString(s, "ProdName")
	d.Catalog = keyString(s, "Catalog")
	return d, nil
}

// numbered returns the entries of s whose keyword is prefix followed by a
// number, sorted by the number.
func numbered(s *Section, prefix string) []numberedEntry {
	if s == nil {
		return nil
	}
	var out []numberedEntry
	for _, e := range s.Entries {
		if len(e.Keyword) <= len(prefix) || !strings.EqualFold(e.Keyword[:len(prefix)], prefix) {
			continue
		}
		n, err := strconv.Atoi(e.Keyword[len(prefix):])
		if err != nil || n < 0 {
			continue
		}
		out = append(out, numberedEntry{n, e})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].n < out[j].n })
	return out
}

type numberedEntry struct {
	n int
	e Entry
}

// Param is a ParamN entry of the [Params] section.
type Param struct {
	Number int
	// Path is the path of the attribute the parameter stands for, when
	// given.
	Path       cip.Path
	Descriptor uint16
	Type       cip.DataType
	Size       int
	Name       string
	Units      string
	Help       string
	// Min, Max and Default are as written: decimal or hex numbers, or
	// empty.
	Min, Max, Default string
	// Enum is the EnumN entry of the same number, if any.
	Enum []EnumValue
}

// EnumValue is one value of an EnumN entry.
type EnumValue struct {
	Value int64
	Name  string
}

// Param fields of a ParamN entry, by position.
const (
	paramLinkPath   = 2
	paramDescriptor = 3
	paramType       = 4
	paramSize       = 5
	paramName       = 6
	paramUnits      = 7
	paramHelp       = 8
	paramMin        = 9
	paramMax        = 10
	paramDefault    = 11
)

// Params returns the parameters of the [Params] section, by number.
func (f *File) Params() ([]Param, error) {
	s := f.Section("Params")
	enums := map[int][]EnumValue{}
	for _, ne := range numbered(s, "Enum") {
		var vals []EnumValue
		for i := 0; i+1 < len(ne.e.Fields); i += 2 {
			v, err := parseInt(ne.e.Fields[i])
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Enum%d value %d: %w", ne.e.Line, ne.n, i/2, err)
			}
			vals = append(vals, EnumValue{Value: v, Name: ne.e.Fields[i+1].Value})
		}
		enums[ne.n] = vals
	}
	var out []Param
	for _, ne := range numbered(s, "Param") {
		e := ne.e
		p := Param{Number: ne.n, Name: e.Field(paramName).Value, Units: e.Field(paramUnits).Value,
			Help: e.Field(paramHelp).Value, Min: e.Field(paramMin).Value, Max: e.Field(paramMax).Value,
			Default: e.Field(paramDefault).Value, Enum: enums[ne.n]}
		if lp := e.Field(paramLinkPath); lp.Kind == FieldString && strings.TrimSpace(lp.Value) != "" {
			path, err := ParseEPATH(lp.Value)
			if err == nil {
				p.Path = path
			}
		}
		if d := e.Field(paramDescriptor); d.Kind == FieldToken {
			v, err := parseU16(d)
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Param%d descriptor: %w", e.Line, ne.n, err)
			}
			p.Descriptor = v
		}
		t, err := parseU8(e.Field(paramType))
		if err != nil {
			return nil, fmt.Errorf("eds: line %d: Param%d data type: %w", e.Line, ne.n, err)
		}
		p.Type = cip.DataType(t)
		sz, err := parseSize(e.Field(paramSize), 16, math.MaxUint16)
		if err != nil {
			return nil, fmt.Errorf("eds: line %d: Param%d data size: %w", e.Line, ne.n, err)
		}
		p.Size = sz
		out = append(out, p)
	}
	return out, nil
}

// ParseEPATH parses the EPATH of an EDS: hex octets separated by spaces,
// "20 04 24 64 2C 65". It is packed (no pad octets).
func ParseEPATH(s string) (cip.Path, error) {
	var b []byte
	for tok := range strings.FieldsSeq(s) {
		if len(tok) != 2 {
			return nil, fmt.Errorf("eds: EPATH octet %q", tok)
		}
		v, err := hex.DecodeString(tok)
		if err != nil {
			return nil, fmt.Errorf("eds: EPATH octet %q", tok)
		}
		b = append(b, v...)
	}
	return cip.DecodePacked(b)
}

// FormatEPATH writes a path as an EDS EPATH.
func FormatEPATH(p cip.Path) (string, error) {
	b, err := p.EncodePacked()
	if err != nil {
		return "", err
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, " "), nil
}

// AssemblyMember is a member of an assembly: a size in bits and what
// fills it (a ParamN or AssemN reference, or nothing for padding).
type AssemblyMember struct {
	Bits int
	// Ref is "Param5", "Assem2" or "" for padding.
	Ref string
}

// MaxAssemblySize is the largest assembly size, in octets, an EDS can
// declare: the size field is 16 bits. A member larger than that, in bits
// 8*MaxAssemblySize, is rejected.
const MaxAssemblySize = 0xFFFF

// Assembly is an AssemN entry of the [Assembly] section.
type Assembly struct {
	Number int
	Name   string
	// Path is the assembly's path, usually @4/instance.
	Path cip.Path
	// Size is the size in octets; 0 when not given.
	Size       int
	Descriptor uint16
	Members    []AssemblyMember
}

// Instance returns the assembly instance of the path.
func (a Assembly) Instance() (uint32, bool) { return a.Path.Instance() }

// Assemblies returns the assemblies of the [Assembly] section.
func (f *File) Assemblies() ([]Assembly, error) {
	var out []Assembly
	for _, ne := range numbered(f.Section("Assembly"), "Assem") {
		e := ne.e
		a := Assembly{Number: ne.n, Name: e.Field(0).Value}
		if p := e.Field(1); strings.TrimSpace(p.Value) != "" {
			path, err := ParseEPATH(p.Value)
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Assem%d path: %w", e.Line, ne.n, err)
			}
			a.Path = path
		}
		if sz := e.Field(2); sz.Kind == FieldToken {
			v, err := parseSize(sz, 16, MaxAssemblySize)
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Assem%d size: %w", e.Line, ne.n, err)
			}
			a.Size = v
		}
		if d := e.Field(3); d.Kind == FieldToken {
			v, err := parseU16(d)
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Assem%d descriptor: %w", e.Line, ne.n, err)
			}
			a.Descriptor = v
		}
		for i := 6; i+1 < len(e.Fields); i += 2 {
			bits := 0
			if e.Fields[i].Kind == FieldToken {
				v, err := parseSize(e.Fields[i], 32, 8*MaxAssemblySize)
				if err != nil {
					return nil, fmt.Errorf("eds: line %d: Assem%d member size: %w", e.Line, ne.n, err)
				}
				bits = v
			}
			a.Members = append(a.Members, AssemblyMember{Bits: bits, Ref: e.Fields[i+1].Value})
		}
		out = append(out, a)
	}
	return out, nil
}

// Connection is a ConnectionN entry of the [Connection Manager] section.
type Connection struct {
	Number int
	// TriggerTransport and Params are the two bit-mask fields.
	TriggerTransport uint32
	Params           uint32
	// OTRPI and TORPI are the RPI fields: a number of microseconds, a
	// ParamN reference, or empty.
	OTRPI, TORPI string
	// OTSize, TOSize, OTFormat and TOFormat are the size and format
	// fields: numbers, ParamN or AssemN references, or empty.
	OTSize, OTFormat string
	TOSize, TOFormat string
	ConfigSize       string
	ConfigFormat     string
	Name             string
	Help             string
	// Path is the connection path; references inside it are left as
	// written in PathText.
	Path     cip.Path
	PathText string
}

// Connections returns the connections of the [Connection Manager] section.
func (f *File) Connections() ([]Connection, error) {
	var out []Connection
	for _, ne := range numbered(f.Section("Connection Manager"), "Connection") {
		e := ne.e
		c := Connection{Number: ne.n,
			OTRPI: e.Field(2).Value, OTSize: e.Field(3).Value, OTFormat: e.Field(4).Value,
			TORPI: e.Field(5).Value, TOSize: e.Field(6).Value, TOFormat: e.Field(7).Value,
			ConfigSize: e.Field(10).Value, ConfigFormat: e.Field(11).Value,
			Name: e.Field(12).Value, Help: e.Field(13).Value, PathText: e.Field(14).Value}
		for i, dst := range []*uint32{&c.TriggerTransport, &c.Params} {
			v, err := parseU32(e.Field(i))
			if err != nil {
				return nil, fmt.Errorf("eds: line %d: Connection%d field %d: %w", e.Line, ne.n, i+1, err)
			}
			*dst = v
		}
		if p, err := ParseEPATH(c.PathText); err == nil {
			c.Path = p
		}
		out = append(out, c)
	}
	return out, nil
}

// Class returns the transport class of the trigger and transport mask:
// bits 0..15 flag classes 0 to 15 (CIP Volume 1, 7-3.6.13 as EDS files use
// it); the lowest flagged class is returned.
func (c Connection) Class() int {
	for i := range 16 {
		if c.TriggerTransport&(1<<i) != 0 {
			return i
		}
	}
	return -1
}

// Format writes the file in canonical form: sections in their order,
// entries with their fields, one field per line for long entries. Comments
// are not kept. Format(Parse(x)) is stable: formatting the result again
// changes nothing.
func (f *File) Format() string {
	var sb strings.Builder
	for i, s := range f.Sections {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "[%s]\n", s.Name)
		for _, e := range s.Entries {
			fields := make([]string, len(e.Fields))
			width := len(e.Keyword) + 4
			for j, fd := range e.Fields {
				fields[j] = fd.String()
				width += len(fields[j]) + 2
			}
			if width <= 100 || len(fields) <= 1 {
				fmt.Fprintf(&sb, "\t%s = %s;\n", e.Keyword, strings.Join(fields, ", "))
				continue
			}
			fmt.Fprintf(&sb, "\t%s =\n", e.Keyword)
			for j, fd := range fields {
				sep := ","
				if j == len(fields)-1 {
					sep = ";"
				}
				fmt.Fprintf(&sb, "\t\t%s%s\n", fd, sep)
			}
		}
	}
	return sb.String()
}
