// SPDX-License-Identifier: MIT

package logix

import (
	"context"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/server"
)

// fuzzServer returns a tag server with a few tags and templates attached
// to a server.
func fuzzServer(f *testing.F) (*TagServer, *server.Server) {
	ts := NewTagServer(WithMaxReply(64))
	inner, outer := testTemplates()
	for _, err := range []error{
		ts.AddTemplate(inner),
		ts.AddTemplate(outer),
		ts.AddTag("Count", cip.TypeDINT),
		ts.AddTag("Big", cip.TypeINT, 100),
		ts.AddTag("Grid", cip.TypeREAL, 3, 4),
		ts.AddTag("Bits", cip.TypeBOOL, 40),
		ts.AddTag("Flag", cip.TypeBOOL),
		ts.AddStructTag("Text", StringTemplate.ID),
		ts.AddStructTag("Outs", outer.ID, 2),
		ts.AddTag("Program:Main.Local", cip.TypeSINT),
	} {
		if err != nil {
			f.Fatal(err)
		}
	}
	srv, err := server.New()
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = srv.Close() })
	ts.Attach(srv)
	return ts, srv
}

func encodeSeed(f *testing.F, req cip.Request) {
	b, err := req.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, false)
	f.Add(b, true)
}

// FuzzServeSymbol sends arbitrary requests to the tag server, symbolic or
// to its objects: it must never panic.
func FuzzServeSymbol(f *testing.F) {
	ts, srv := fuzzServer(f)
	p := func(name string) cip.Path {
		tp, err := ParseTag(name)
		if err != nil {
			f.Fatal(err)
		}
		return tp.Path
	}
	for _, name := range []string{"Count", "Big[3]", "Grid[1,2]", "Bits[33]", "Outs[1].In.B", "Outs[0].Ins[1].A", "Outs[1].Flags[3]", "Outs[0].Txt.DATA[2]", "Program:Main.Local"} {
		encodeSeed(f, cip.Request{Service: cip.ServiceReadTag, Path: p(name), Data: []byte{1, 0}})
		encodeSeed(f, cip.Request{Service: cip.ServiceReadTagFragmented, Path: p(name), Data: []byte{1, 0, 0, 0, 0, 0}})
		encodeSeed(f, cip.Request{Service: cip.ServiceWriteTag, Path: p(name), Data: []byte{0xC4, 0, 1, 0, 1, 2, 3, 4}})
		encodeSeed(f, cip.Request{Service: cip.ServiceWriteTagFragmented, Path: p(name), Data: []byte{0xC3, 0, 2, 0, 2, 0, 0, 0, 1, 2}})
		encodeSeed(f, cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: p(name), Data: []byte{4, 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}})
	}
	encodeSeed(f, cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: cip.Path{cip.ClassSegment(cip.ClassSymbol), cip.InstanceSegment(0)}, Data: []byte{3, 0, 1, 0, 2, 0, 8, 0}})
	encodeSeed(f, cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: cip.Path{cip.SymbolSegment{Name: "Program:Main"}, cip.ClassSegment(cip.ClassSymbol), cip.InstanceSegment(0)}, Data: []byte{1, 0, 1, 0}})
	encodeSeed(f, cip.Request{Service: cip.ServiceReadTag, Path: append(cip.ObjectPath(cip.ClassSymbol, 2), cip.MemberSegment(1)), Data: []byte{1, 0}})
	encodeSeed(f, cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, 0x20), Data: []byte{4, 0, 4, 0, 5, 0, 2, 0, 1, 0}})
	encodeSeed(f, cip.Request{Service: cip.ServiceReadTemplate, Path: cip.ObjectPath(cip.ClassTemplate, 0x20), Data: []byte{0, 0, 0, 0, 0xFF, 0}})
	encodeSeed(f, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassProgramName, 1)})

	ctx := context.Background()
	f.Fuzz(func(t *testing.T, b []byte, connected bool) {
		req, err := cip.DecodeRequest(b)
		if err != nil {
			t.Skip()
		}
		r := &server.Request{Request: req, Connected: connected}
		// Always try the symbol handler directly, as an embedder may.
		ts.ServeSymbol(ctx, r)
		if req.Path.Symbolic() || len(req.Path) == 0 {
			return
		}
		// Route to the objects as the Message Router does.
		i := 0
		l, ok := req.Path[0].(cip.LogicalSegment)
		if !ok || l.Type != cip.LogicalClass {
			return
		}
		i++
		if i < len(req.Path) {
			if in, ok := req.Path[i].(cip.LogicalSegment); ok && in.Type == cip.LogicalInstance {
				r.Instance = in.Value
				i++
			}
		}
		if i < len(req.Path) {
			if at, ok := req.Path[i].(cip.LogicalSegment); ok && at.Type == cip.LogicalAttribute && at.Value <= 0xFFFF {
				r.Attribute, r.HasAttribute = uint16(at.Value), true
				i++
			}
		}
		r.Rest = req.Path[i:]
		for _, c := range []cip.Class{cip.ClassSymbol, cip.ClassTemplate, cip.ClassProgramName} {
			srv.Object(c).ServeCIP(ctx, r)
		}
	})
}

// FuzzTemplateDecode parses arbitrary definitions and decodes arbitrary
// data with them, with a lookup that returns the template itself: it must
// never panic or recurse without end.
func FuzzTemplateDecode(f *testing.F) {
	inner, outer := testTemplates()
	f.Add(outer.definition(), uint16(len(outer.Members)), uint32(outer.Size), outerData())
	f.Add(inner.definition(), uint16(len(inner.Members)), uint32(inner.Size), []byte{1, 2, 3, 4})
	f.Add(StringTemplate.definition(), uint16(2), uint32(StringSize), make([]byte, StringSize))
	self := Template{ID: 7, Name: "Self", Size: 4, Members: []Member{{Name: "S", Type: NewStructType(7, 0)}}}
	f.Add(self.definition(), uint16(1), uint32(4), []byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, def []byte, members uint16, size uint32, data []byte) {
		name, ms, err := parseDefinition(def, int(members))
		if err != nil {
			return
		}
		if len(ms) != int(members) {
			t.Fatalf("%d members of %d", len(ms), members)
		}
		tm := &Template{ID: 7, Name: name, Size: size % 4096, Members: ms}
		// Round trip through definition.
		name2, ms2, err := parseDefinition(tm.definition(), len(ms))
		if err == nil && name2 == name && len(ms2) == len(ms) {
			for i := range ms {
				if ms[i].Info != ms2[i].Info || ms[i].Type != ms2[i].Type || ms[i].Offset != ms2[i].Offset {
					t.Fatalf("member %d: %+v != %+v", i, ms[i], ms2[i])
				}
			}
		}
		lookups := []func(uint16) *Template{
			nil,
			func(uint16) *Template { return tm },
			func(id uint16) *Template {
				if id == StringTemplate.ID {
					return &StringTemplate
				}
				return &inner
			},
		}
		for _, lk := range lookups {
			fields, err := tm.Decode(data, lk)
			if err == nil {
				for _, fl := range fields {
					_ = fl.Value.String()
				}
			}
		}
	})
}
