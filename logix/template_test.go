// SPDX-License-Identifier: MIT

package logix

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestSymbolType(t *testing.T) {
	b := NewAtomicType(cip.TypeBOOL, 0, 5)
	if b.IsStruct() || b.Dims() != 0 || b.Atomic() != cip.TypeBOOL || b.Bit() != 5 || b.String() != "BOOL" {
		t.Fatalf("BOOL bit 5: %04x %s", uint16(b), b)
	}
	d := NewAtomicType(cip.TypeDINT, 2, 7) // bit ignored for non-BOOL
	if d.Bit() != 0 || d.Dims() != 2 || d.Atomic() != cip.TypeDINT || d.String() != "DINT[2 dims]" {
		t.Fatalf("DINT[2]: %04x %s", uint16(d), d)
	}
	s := NewStructType(0x1123, 3)
	if !s.IsStruct() || s.Template() != 0x123 || s.Dims() != 3 || s.String() != "struct 0x123[3 dims]" {
		t.Fatalf("struct: %04x %s", uint16(s), s)
	}
	if s.IsSystem() || !SymbolType(0x1068).IsSystem() {
		t.Fatal("IsSystem")
	}
	if NewStructType(0xFCE, 0).String() != "struct 0xFCE" {
		t.Fatal(NewStructType(0xFCE, 0).String())
	}
}

func TestMemberHidden(t *testing.T) {
	for name, want := range map[string]bool{"ZZZZZZZZZZMotor0": true, "__host": true, "Speed": false, "ZZZ": false, "_x": false} {
		if (Member{Name: name}).Hidden() != want {
			t.Fatalf("%s hidden != %v", name, want)
		}
	}
}

// testTemplates is a set of nested templates: Inner {A INT, B BOOL}; Outer
// {X DINT, In Inner, Ins Inner[2], Flags BOOL[40], Raw SINT[3], Txt STRING}.
func testTemplates() (inner, outer Template) {
	inner = Template{ID: 0x10, Name: "Inner", Handle: 0x1111, Size: 4, Members: []Member{
		{Name: "A", Type: NewAtomicType(cip.TypeINT, 0, 0), Offset: 0},
		{Name: "ZZZZZZZZZZInner2", Type: NewAtomicType(cip.TypeSINT, 0, 0), Offset: 2},
		{Name: "B", Type: NewAtomicType(cip.TypeBOOL, 0, 0), Info: 3, Offset: 2},
	}}
	outer = Template{ID: 0x20, Name: "Outer", Handle: 0x2222, Size: 4 + 4 + 8 + 8 + 4 + 88, Members: []Member{
		{Name: "X", Type: NewAtomicType(cip.TypeDINT, 0, 0), Offset: 0},
		{Name: "In", Type: NewStructType(0x10, 0), Offset: 4},
		{Name: "Ins", Type: NewStructType(0x10, 1), Info: 2, Offset: 8},
		{Name: "Flags", Type: NewAtomicType(cip.TypeBOOL, 1, 0), Info: 40, Offset: 16},
		{Name: "Raw", Type: NewAtomicType(cip.TypeSINT, 1, 0), Info: 3, Offset: 24},
		{Name: "Txt", Type: NewStructType(StringTemplate.ID, 0), Offset: 28},
	}}
	return inner, outer
}

func TestDefinitionRoundTrip(t *testing.T) {
	_, outer := testTemplates()
	def := outer.definition()
	if !strings.Contains(string(def), "Outer;n\x00X\x00In\x00") {
		t.Fatalf("definition %q", def)
	}
	if got := definitionWords(len(def)); int(got)*4-21 < len(def) || int(got)*4-21 > len(def)+3 {
		t.Fatalf("definitionWords(%d) = %d", len(def), got)
	}
	name, ms, err := parseDefinition(def, len(outer.Members))
	if err != nil || name != "Outer" || !reflect.DeepEqual(ms, outer.Members) {
		t.Fatalf("parse %q %+v %v", name, ms, err)
	}
	// Padding after the names, as Read_Template returns it, is ignored.
	name, ms, err = parseDefinition(append(def, 0, 0, 0), len(outer.Members))
	if err != nil || name != "Outer" || len(ms) != 6 {
		t.Fatalf("padded %q %v", name, err)
	}
	// A name without ";n" is taken whole.
	name, _, err = parseDefinition([]byte("Plain\x00"), 0)
	if err != nil || name != "Plain" {
		t.Fatalf("plain %q %v", name, err)
	}
	if _, _, err := parseDefinition(def[:20], 3); err == nil {
		t.Fatal("3 members in 20 octets")
	}
	if _, _, err := parseDefinition(def, -1); err == nil {
		t.Fatal("negative members")
	}
	if _, _, err := parseDefinition(def[:8*6+len("Outer;n\x00X\x00")], 6); err == nil {
		t.Fatal("missing member names")
	}
}

func TestStringTemplateDecode(t *testing.T) {
	v, _ := Strings("abc")
	f, err := StringTemplate.Decode(v.Data, nil)
	if err != nil || len(f) != 2 {
		t.Fatalf("%+v %v", f, err)
	}
	if n, _ := f[0].Value.Int(0); f[0].Name != "LEN" || n != 3 {
		t.Fatalf("LEN %+v", f[0])
	}
	if f[1].Name != "DATA" || f[1].Value.Type != cip.TypeSINT || f[1].Value.Count != StringCapacity || string(f[1].Value.Data[:3]) != "abc" {
		t.Fatalf("DATA %+v", f[1])
	}
}

func outerData() []byte {
	d := make([]byte, 4+4+8+8+4+88)
	binary.LittleEndian.PutUint32(d, 0xFFFFFFFE) // X = -2
	binary.LittleEndian.PutUint16(d[4:], 7)      // In.A
	d[6] = 1 << 3                                // In.B
	binary.LittleEndian.PutUint16(d[8:], 8)      // Ins[0].A
	binary.LittleEndian.PutUint16(d[12:], 9)     // Ins[1].A
	binary.LittleEndian.PutUint32(d[16:], 1<<2)  // Flags[2]
	d[20] = 1 << 7                               // Flags[39]
	d[24], d[25], d[26] = 1, 2, 3
	binary.LittleEndian.PutUint32(d[28:], 2)
	copy(d[32:], "hi")
	return d
}

func TestTemplateDecodeNested(t *testing.T) {
	inner, outer := testTemplates()
	lookup := func(id uint16) *Template {
		switch id {
		case inner.ID:
			return &inner
		case StringTemplate.ID:
			return &StringTemplate
		}
		return nil
	}
	f, err := outer.Decode(outerData(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Field{}
	for _, x := range f {
		by[x.Name] = x
	}
	if len(f) != 6 {
		t.Fatalf("%d fields", len(f))
	}
	if x, _ := by["X"].Value.Int(0); x != -2 {
		t.Fatalf("X %d", x)
	}
	in := by["In"]
	if in.Value.Handle != inner.Handle || len(in.Struct) != 2 {
		t.Fatalf("In %+v", in)
	}
	if a, _ := in.Struct[0].Value.Int(0); a != 7 {
		t.Fatalf("In.A %d", a)
	}
	if b, _ := in.Struct[1].Value.Bool(0); !b || in.Struct[1].Name != "B" {
		t.Fatalf("In.B %+v", in.Struct[1])
	}
	ins := by["Ins"]
	if ins.Value.Count != 2 || len(ins.Value.Data) != 8 || ins.Struct != nil {
		t.Fatalf("Ins %+v", ins)
	}
	flags := by["Flags"].Value
	if flags.Type != cip.TypeDWORD || flags.Count != 2 {
		t.Fatalf("Flags %+v", flags)
	}
	for i, want := range map[int]bool{2: true, 3: false, 39: true} {
		if b, _ := flags.Bool(i); b != want {
			t.Fatalf("Flags[%d] %v", i, b)
		}
	}
	if r := by["Raw"].Value; r.Count != 3 || string(r.Data) != "\x01\x02\x03" {
		t.Fatalf("Raw %+v", r)
	}
	if s, _ := by["Txt"].Value.Text(0); s != "hi" || len(by["Txt"].Struct) != 2 {
		t.Fatalf("Txt %q", s)
	}

	// Without lookup, structure members stay raw.
	f, err = outer.Decode(outerData(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f[1].Struct != nil || f[1].Value.Handle != 0 || len(f[1].Value.Data) != len(outerData())-4 {
		t.Fatalf("raw In %+v", f[1])
	}
}

func TestTemplateDecodeErrors(t *testing.T) {
	_, outer := testTemplates()
	if _, err := outer.Decode(make([]byte, 10), nil); !errors.Is(err, ErrType) {
		t.Fatalf("short data: %v", err)
	}
	cases := []Template{
		{Name: "BoolBeyond", Size: 1, Members: []Member{{Name: "B", Type: NewAtomicType(cip.TypeBOOL, 0, 0), Offset: 4}}},
		{Name: "IntBeyond", Size: 2, Members: []Member{{Name: "I", Type: NewAtomicType(cip.TypeDINT, 0, 0), Offset: 0}}},
		{Name: "ArrBeyond", Size: 4, Members: []Member{{Name: "I", Type: NewAtomicType(cip.TypeINT, 1, 0), Info: 3, Offset: 0}}},
		{Name: "Sizeless", Size: 4, Members: []Member{{Name: "S", Type: NewAtomicType(cip.TypeSTRING, 0, 0), Offset: 0}}},
	}
	for _, c := range cases {
		if _, err := c.Decode(make([]byte, c.Size), nil); !errors.Is(err, ErrType) {
			t.Fatalf("%s: %v", c.Name, err)
		}
	}
	// A nested structure whose decoding fails fails the whole.
	bad := cases[1]
	bad.ID = 5
	host := Template{Name: "Host", Size: 8, Members: []Member{{Name: "Sub", Type: NewStructType(5, 0), Offset: 0}}}
	bad.Size = 2
	if _, err := host.Decode(make([]byte, 8), func(uint16) *Template { return &bad }); !errors.Is(err, ErrType) {
		t.Fatalf("nested failure: %v", err)
	}
	// A structure member past the data is left empty.
	far := Template{Name: "Far", Size: 4, Members: []Member{{Name: "S", Type: NewStructType(5, 0), Offset: 100}}}
	f, err := far.Decode(make([]byte, 4), nil)
	if err != nil || f[0].Value.Data != nil {
		t.Fatalf("far: %+v %v", f, err)
	}
}

// A template that contains itself used to recurse until the stack
// overflowed.
func TestTemplateDecodeSelfReference(t *testing.T) {
	self := Template{ID: 7, Name: "Self", Size: 4, Members: []Member{{Name: "S", Type: NewStructType(7, 0), Offset: 0}}}
	_, err := self.Decode(make([]byte, 4), func(uint16) *Template { return &self })
	if !errors.Is(err, ErrType) || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("self reference: %v", err)
	}
}

func TestTail(t *testing.T) {
	d := []byte{1, 2, 3, 4}
	if got := tail(d, 1, 2); string(got) != "\x02\x03" {
		t.Fatalf("%x", got)
	}
	if got := tail(d, 2, 0); string(got) != "\x03\x04" {
		t.Fatalf("%x", got)
	}
	if got := tail(d, 2, 10); string(got) != "\x03\x04" {
		t.Fatalf("%x", got)
	}
	if got := tail(d, 4, 1); got != nil {
		t.Fatalf("%x", got)
	}
	got := tail(d, 0, 0)
	got[0] = 9
	if d[0] != 1 {
		t.Fatal("tail aliases data")
	}
}

// Templates whose members overlap used to make the work grow exponentially
// with nesting (here 8^20 fields): Decode stops at maxFields fields.
func TestTemplateDecodeFieldBudget(t *testing.T) {
	chain := make([]Template, 21)
	for id := range chain {
		chain[id] = Template{ID: uint16(id), Name: "Chain", Size: 4}
		for i := 0; i < 8; i++ {
			m := Member{Name: "M", Type: NewStructType(uint16(id+1), 0)}
			if id == len(chain)-1 {
				m.Type = NewAtomicType(cip.TypeDINT, 0, 0)
			}
			chain[id].Members = append(chain[id].Members, m)
		}
	}
	_, err := chain[0].Decode(make([]byte, 4), func(id uint16) *Template { return &chain[id] })
	if !errors.Is(err, ErrType) || !strings.Contains(err.Error(), "fields") {
		t.Fatalf("overlapping chain: %v", err)
	}
	// Five levels decode: 8^5 fields and their parents fit.
	f, err := chain[16].Decode(make([]byte, 4), func(id uint16) *Template { return &chain[id] })
	if err != nil || len(f) != 8 || len(f[0].Struct) != 8 {
		t.Fatalf("short chain: %v", err)
	}
}
