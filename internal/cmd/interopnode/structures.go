// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"math"
	"strings"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/logix"
)

// FixtureTemplate is a structure template of a fixture.
type FixtureTemplate struct {
	Name    string          `json:"name"`
	ID      uint16          `json:"id"`
	Handle  uint16          `json:"handle"`
	Size    uint32          `json:"size"`
	Members []FixtureMember `json:"members"`
}

// FixtureMember is a member of a fixture template.
type FixtureMember struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
	Count  int    `json:"count"`
	Bit    int    `json:"bit"`
}

// templates are the fixture's templates by upper-case name, STRING
// predefined.
type templates map[string]*FixtureTemplate

// addTemplates adds the fixture's templates to ts, in order (a member may
// use an earlier template).
func addTemplates(ts *logix.TagServer, fts []FixtureTemplate) (templates, error) {
	byName := templates{}
	for i := range fts {
		ft := &fts[i]
		t := logix.Template{ID: ft.ID, Name: ft.Name, Handle: ft.Handle, Size: ft.Size}
		for _, m := range ft.Members {
			st, info, err := byName.memberType(m)
			if err != nil {
				return nil, fmt.Errorf("template %s member %s: %w", ft.Name, m.Name, err)
			}
			t.Members = append(t.Members, logix.Member{Name: m.Name, Type: st, Info: info, Offset: m.Offset})
		}
		if err := ts.AddTemplate(t); err != nil {
			return nil, err
		}
		byName[strings.ToUpper(ft.Name)] = ft
	}
	return byName, nil
}

// memberType returns the symbol type and the info word of a member.
func (byName templates) memberType(m FixtureMember) (logix.SymbolType, uint16, error) {
	dims, info := 0, uint16(0)
	if m.Count > 0 {
		dims, info = 1, uint16(m.Count)
	}
	switch tn := strings.ToUpper(m.Type); {
	case tn == "STRING":
		return logix.NewStructType(logix.StringTemplate.ID, dims), info, nil
	case byName[tn] != nil:
		return logix.NewStructType(byName[tn].ID, dims), info, nil
	}
	t, ok := cip.ParseDataType(m.Type)
	if !ok {
		return 0, 0, fmt.Errorf("type %q", m.Type)
	}
	if t == cip.TypeBOOL {
		if dims > 0 {
			return 0, 0, fmt.Errorf("BOOL array members are not supported")
		}
		return logix.NewAtomicType(t, 0, m.Bit), uint16(m.Bit), nil
	}
	return logix.NewAtomicType(t, dims, 0), info, nil
}

// encode writes the structure value fields of template ft into b, which
// is ft.Size octets.
func (byName templates) encode(ft *FixtureTemplate, fields map[string]any, b []byte) error {
	for _, m := range ft.Members {
		v, ok := fields[m.Name]
		if !ok {
			continue
		}
		vs := []any{v}
		if m.Count > 0 {
			arr, ok := v.([]any)
			if !ok || len(arr) != m.Count {
				return fmt.Errorf("member %s: want %d elements", m.Name, m.Count)
			}
			vs = arr
		}
		if err := byName.encodeMember(m, vs, b[m.Offset:]); err != nil {
			return fmt.Errorf("member %s: %w", m.Name, err)
		}
	}
	return nil
}

func (byName templates) encodeMember(m FixtureMember, vs []any, b []byte) error {
	switch tn := strings.ToUpper(m.Type); {
	case tn == "STRING":
		ss := make([]string, len(vs))
		for i, v := range vs {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("%v is not a string", v)
			}
			ss[i] = s
		}
		val, err := logix.Strings(ss...)
		if err != nil {
			return err
		}
		copy(b, val.Data)
		return nil
	case byName[tn] != nil:
		sub := byName[tn]
		for i, v := range vs {
			f, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%v is not an object", v)
			}
			if err := byName.encode(sub, f, b[uint32(i)*sub.Size:]); err != nil {
				return err
			}
		}
		return nil
	}
	t, _ := cip.ParseDataType(m.Type)
	nums := make([]float64, len(vs))
	for i, v := range vs {
		n, ok := v.(float64)
		if !ok {
			return fmt.Errorf("%v is not a number", v)
		}
		nums[i] = n
	}
	if t == cip.TypeBOOL {
		if nums[0] != 0 {
			b[0] |= 1 << m.Bit
		} else {
			b[0] &^= 1 << m.Bit
		}
		return nil
	}
	val, err := numbers(t, nums)
	if err != nil {
		return err
	}
	copy(b, val.Data)
	return nil
}

// numbers encodes values of an elementary type.
func numbers(t cip.DataType, vs []float64) (logix.Value, error) {
	if t.IsFloat() {
		return logix.Floats(t, vs...)
	}
	is := make([]int64, len(vs))
	for i, v := range vs {
		is[i] = int64(math.Round(v))
	}
	return logix.Ints(t, is...)
}

// addStructTag adds a STRING or structure tag with its initial value.
func addStructTag(ts *logix.TagServer, byName templates, t FixtureTag) error {
	n := t.Count
	var dims []int
	if n > 0 {
		dims = []int{n}
	} else {
		n = 1
	}
	if strings.EqualFold(t.Type, "STRING") {
		if err := ts.AddStructTag(t.Name, logix.StringTemplate.ID, dims...); err != nil {
			return err
		}
		if len(t.Strings) != n {
			return fmt.Errorf("tag %s: %d strings for %d elements", t.Name, len(t.Strings), n)
		}
		v, err := logix.Strings(t.Strings...)
		if err != nil {
			return err
		}
		return ts.Set(t.Name, v)
	}
	ft := byName[strings.ToUpper(t.Type)]
	if ft == nil {
		return fmt.Errorf("tag %s: type %q", t.Name, t.Type)
	}
	if err := ts.AddStructTag(t.Name, ft.ID, dims...); err != nil {
		return err
	}
	if len(t.Fields) != n {
		return fmt.Errorf("tag %s: %d field sets for %d elements", t.Name, len(t.Fields), n)
	}
	data := make([]byte, int(ft.Size)*n)
	for i, f := range t.Fields {
		if err := byName.encode(ft, f, data[uint32(i)*ft.Size:]); err != nil {
			return fmt.Errorf("tag %s[%d]: %w", t.Name, i, err)
		}
	}
	return ts.Set(t.Name, logix.Value{Handle: ft.Handle, Count: n, Data: data})
}
