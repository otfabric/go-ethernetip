// SPDX-License-Identifier: MIT

package logix

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/server"
)

type harness struct {
	t   *testing.T
	ts  *TagServer
	srv *server.Server
}

func newHarness(t *testing.T, opts ...TagServerOption) *harness {
	t.Helper()
	ts := NewTagServer(opts...)
	inner, outer := testTemplates()
	must(t, ts.AddTemplate(inner))
	must(t, ts.AddTemplate(outer))
	must(t, ts.AddTag("Count", cip.TypeDINT))
	must(t, ts.AddTag("Big", cip.TypeINT, 1000))
	must(t, ts.AddTag("Grid", cip.TypeREAL, 3, 4))
	must(t, ts.AddTag("Cube", cip.TypeSINT, 2, 3, 4))
	must(t, ts.AddTag("Bits", cip.TypeBOOL, 64))
	must(t, ts.AddTag("Flag", cip.TypeBOOL))
	must(t, ts.AddTag("Speed", cip.TypeREAL))
	must(t, ts.AddStructTag("Text", StringTemplate.ID))
	must(t, ts.AddStructTag("Outs", outer.ID, 2))
	must(t, ts.AddTag("Program:Main.Local", cip.TypeSINT))
	srv, err := server.New()
	must(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	ts.Attach(srv)
	return &harness{t: t, ts: ts, srv: srv}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// do routes a request as the server's Message Router does.
func (h *harness) do(req cip.Request, connected bool) cip.Response {
	r := &server.Request{Request: req, Connected: connected}
	if req.Path.Symbolic() {
		return h.ts.ServeSymbol(ctx, r)
	}
	i := 0
	class := req.Path[i].(cip.LogicalSegment).Value
	i++
	if i < len(req.Path) {
		if l, ok := req.Path[i].(cip.LogicalSegment); ok && l.Type == cip.LogicalInstance {
			r.Instance = l.Value
			i++
		}
	}
	r.Rest = req.Path[i:]
	o := h.srv.Object(cip.Class(class))
	if o == nil {
		h.t.Fatalf("no object 0x%X", class)
	}
	return o.ServeCIP(ctx, r)
}

func (h *harness) path(name string) cip.Path {
	tp, err := ParseTag(name)
	if err != nil {
		h.t.Fatal(err)
	}
	return tp.Path
}

func (h *harness) read(name string, count int) cip.Response {
	return h.do(cip.Request{Service: cip.ServiceReadTag, Path: h.path(name), Data: le16(uint16(count))}, false)
}

func (h *harness) write(name string, v Value) cip.Response {
	data := cat(v.appendType(nil), le16(uint16(v.Count)), v.Data)
	return h.do(cip.Request{Service: cip.ServiceWriteTag, Path: h.path(name), Data: data}, false)
}

func wantStatus(t *testing.T, what string, r cip.Response, st cip.GeneralStatus, ext ...uint16) {
	t.Helper()
	if r.Status != st || (len(ext) > 0 && !reflect.DeepEqual(r.Extended, ext)) {
		t.Fatalf("%s: status 0x%02X %v, want 0x%02X %v", what, uint8(r.Status), r.Extended, uint8(st), ext)
	}
}

func wantBeyond(t *testing.T, what string, r cip.Response) {
	t.Helper()
	wantStatus(t, what, r, cip.StatusGeneralError, ExtAccessBeyondEnd)
}

func wantTypeMismatch(t *testing.T, what string, r cip.Response) {
	t.Helper()
	wantStatus(t, what, r, cip.StatusGeneralError, ExtTypeMismatch)
}

func TestTagServerAddErrors(t *testing.T) {
	h := newHarness(t)
	ts := h.ts
	inv := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	inv("STRING type", ts.AddTag("S", cip.TypeSTRING))
	inv("unknown type", ts.AddTag("S", cip.DataType(0x99)))
	inv("4 dims", ts.AddTag("S", cip.TypeDINT, 1, 1, 1, 1))
	inv("space", ts.AddTag("Bad Name", cip.TypeDINT))
	inv("program only", ts.AddTag("Program:Main", cip.TypeDINT))
	inv("program bad tag", ts.AddTag("Program:Main.1x", cip.TypeDINT))
	inv("dim 0", ts.AddTag("S", cip.TypeDINT, 0))
	inv("dim huge", ts.AddTag("S", cip.TypeDINT, 1<<20+1))
	inv("too large", ts.AddTag("S", cip.TypeLINT, 1<<20, 4))
	inv("duplicate", ts.AddTag("COUNT", cip.TypeINT))
	inv("duplicate program tag", ts.AddTag("program:main.local", cip.TypeINT))
	inv("no template", ts.AddStructTag("S", 0x777))
	inv("struct 4 dims", ts.AddStructTag("S", 0x10, 1, 1, 1, 1))

	tm := func(id uint16, handle uint16, size uint32, ms ...Member) Template {
		return Template{ID: id, Name: "T", Handle: handle, Size: size, Members: ms}
	}
	inv("id 0", ts.AddTemplate(tm(0, 1, 4)))
	inv("id 0x1000", ts.AddTemplate(tm(0x1000, 1, 4)))
	inv("size 0", ts.AddTemplate(tm(1, 1, 0)))
	inv("no name", ts.AddTemplate(Template{ID: 1, Handle: 1, Size: 4}))
	inv("duplicate id", ts.AddTemplate(tm(0x10, 1, 4)))
	inv("duplicate handle", ts.AddTemplate(tm(1, 0x1111, 4)))
	inv("string handle", ts.AddTemplate(tm(1, StringHandle, 4)))
	inv("member beyond", ts.AddTemplate(tm(1, 1, 4, Member{Name: "A", Type: NewAtomicType(cip.TypeDINT, 0, 0), Offset: 1})))
	inv("array beyond", ts.AddTemplate(tm(1, 1, 8, Member{Name: "A", Type: NewAtomicType(cip.TypeINT, 1, 0), Info: 5})))
	inv("bool array beyond", ts.AddTemplate(tm(1, 1, 4, Member{Name: "A", Type: NewAtomicType(cip.TypeBOOL, 1, 0), Info: 33})))
	inv("bool beyond", ts.AddTemplate(tm(1, 1, 4, Member{Name: "A", Type: NewAtomicType(cip.TypeBOOL, 0, 0), Info: 1, Offset: 4})))
	inv("unknown member template", ts.AddTemplate(tm(1, 1, 4, Member{Name: "A", Type: NewStructType(0x777, 0)})))
	inv("self", ts.AddTemplate(tm(1, 1, 4, Member{Name: "A", Type: NewStructType(1, 0)})))
	inv("struct member beyond", ts.AddTemplate(tm(1, 1, 8, Member{Name: "A", Type: NewStructType(0x10, 1), Info: 3})))
	inv("sizeless member", ts.AddTemplate(tm(1, 1, 8, Member{Name: "A", Type: NewAtomicType(cip.TypeSTRING, 0, 0)})))
	inv("unknown member type", ts.AddTemplate(tm(1, 1, 8, Member{Name: "A", Type: SymbolType(0x99)})))
	must(t, ts.AddTemplate(tm(1, 1, 8, Member{Name: "A", Type: NewAtomicType(cip.TypeBOOL, 1, 0), Info: 64})))

	// The template's members are copied.
	ms := []Member{{Name: "A", Type: NewAtomicType(cip.TypeDINT, 0, 0)}}
	must(t, ts.AddTemplate(Template{ID: 2, Name: "C", Handle: 2, Size: 4, Members: ms}))
	ms[0].Name = "Changed"
	if ts.templates[2].Members[0].Name != "A" {
		t.Fatal("members not copied")
	}
}

func TestTagServerGetSet(t *testing.T) {
	h := newHarness(t)
	ts := h.ts
	if _, err := ts.Get("Nope"); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatal(err)
	}
	v, _ := Ints(cip.TypeDINT, 9)
	if err := ts.Set("Nope", v); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatal(err)
	}
	must(t, ts.Set("count", v))
	got, err := ts.Get("COUNT")
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("%+v %v", got, err)
	}
	got.Data[0] = 1 // a copy
	if g, _ := ts.Get("Count"); g.Data[0] != 9 {
		t.Fatal("Get aliases")
	}
	f, _ := Floats(cip.TypeREAL, 1)
	if err := ts.Set("Count", f); !errors.Is(err, ErrType) {
		t.Fatalf("REAL into DINT: %v", err)
	}
	two, _ := Ints(cip.TypeDINT, 1, 2)
	if err := ts.Set("Count", two); !errors.Is(err, ErrType) {
		t.Fatalf("size: %v", err)
	}
	b, _ := ts.Get("Bits")
	if b.Type != cip.TypeDWORD || b.Count != 2 || len(b.Data) != 8 {
		t.Fatalf("Bits %+v", b)
	}
	s, _ := ts.Get("Text")
	if s.Handle != StringHandle || s.Count != 1 || len(s.Data) != StringSize {
		t.Fatalf("Text %+v", s)
	}
	o, _ := ts.Get("Outs")
	if o.Handle != 0x2222 || o.Count != 2 || len(o.Data) != 2*116 {
		t.Fatalf("Outs %+v", o)
	}
	sv, _ := Strings("x")
	must(t, ts.Set("Text", sv))
	if err := ts.Set("Outs", sv); !errors.Is(err, ErrType) {
		t.Fatalf("STRING into Outer: %v", err)
	}
	l, _ := ts.Get("Program:Main.Local")
	if l.Type != cip.TypeSINT || l.Count != 1 {
		t.Fatalf("Local %+v", l)
	}
}

func TestTagServerRead(t *testing.T) {
	h := newHarness(t)
	ts := h.ts
	v, _ := Ints(cip.TypeDINT, -7)
	must(t, ts.Set("Count", v))
	r := h.read("Count", 1)
	if !r.OK() || !bytes.Equal(r.Data, []byte{0xC4, 0, 0xF9, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("Count %+v", r)
	}
	wantBeyond(t, "count 2", h.read("Count", 2))
	wantBeyond(t, "count 0", h.read("Count", 0))
	wantStatus(t, "no count", h.do(cip.Request{Service: cip.ServiceReadTag, Path: h.path("Count")}, false), cip.StatusNotEnoughData)
	wantStatus(t, "missing", h.read("Nope", 1), cip.StatusPathDestinationUnknown)

	// Program scope.
	l, _ := Ints(cip.TypeSINT, 5)
	must(t, ts.Set("Program:Main.Local", l))
	if r := h.read("Program:Main.Local", 1); !r.OK() || !bytes.Equal(r.Data, []byte{0xC2, 0, 5}) {
		t.Fatalf("Local %+v", r)
	}
	wantStatus(t, "unknown program", h.read("Program:Nope.Local", 1), cip.StatusPathDestinationUnknown)
	wantStatus(t, "program only", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{sym{Name: "Program:Main"}}, Data: le16(1)}, false), cip.StatusPathSegmentError)
	wantStatus(t, "program then index", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{sym{Name: "Program:Main"}, mem(0)}, Data: le16(1)}, false), cip.StatusPathSegmentError)
	wantStatus(t, "empty path", h.ts.ServeSymbol(ctx, &server.Request{Request: cip.Request{Service: cip.ServiceReadTag, Data: le16(1)}}), cip.StatusPathSegmentError)
	wantStatus(t, "logical first", h.ts.ServeSymbol(ctx, &server.Request{Request: cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{mem(1)}, Data: le16(1)}}), cip.StatusPathSegmentError)

	// Multi-dimensional arrays.
	grid := make([]float64, 12)
	for i := range grid {
		grid[i] = float64(i)
	}
	gv, _ := Floats(cip.TypeREAL, grid...)
	must(t, ts.Set("Grid", gv))
	if r := h.read("Grid[2,3]", 1); !r.OK() || !bytes.Equal(r.Data[2:], cip.AppendFloat32(nil, 11)) {
		t.Fatalf("Grid[2,3] %+v", r)
	}
	if r := h.read("Grid[1,1]", 7); !r.OK() || len(r.Data) != 2+28 || !bytes.Equal(r.Data[2:6], cip.AppendFloat32(nil, 5)) {
		t.Fatalf("Grid[1,1] x7 %+v", r)
	}
	wantBeyond(t, "Grid[1,1] x8", h.read("Grid[1,1]", 8))
	wantStatus(t, "one index of two", h.read("Grid[1]", 1), cip.StatusPathSegmentError)
	wantStatus(t, "three of two", h.read("Grid[1,1,1]", 1), cip.StatusPathSegmentError)
	wantBeyond(t, "Grid[3,0]", h.read("Grid[3,0]", 1))
	wantBeyond(t, "Grid[0,4]", h.read("Grid[0,4]", 1))
	cube := make([]int64, 24)
	for i := range cube {
		cube[i] = int64(i)
	}
	cv, _ := Ints(cip.TypeSINT, cube...)
	must(t, ts.Set("Cube", cv))
	if r := h.read("Cube[1,2,3]", 1); !r.OK() || r.Data[2] != 23 {
		t.Fatalf("Cube[1,2,3] %+v", r)
	}
	if r := h.read("Cube[1,0,0]", 1); !r.OK() || r.Data[2] != 12 {
		t.Fatalf("Cube[1,0,0] %+v", r)
	}
	wantStatus(t, "index of atomic", h.read("Count[0]", 1), cip.StatusPathSegmentError)
	wantStatus(t, "index twice", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{sym{Name: "Big"}, mem(1), sym{Name: "X"}}, Data: le16(1)}, false), cip.StatusPathSegmentError)
	wantStatus(t, "member of atomic", h.read("Count.X", 1), cip.StatusPathSegmentError)
	wantStatus(t, "non-member logical", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{sym{Name: "Big"}, cip.InstanceSegment(1)}, Data: le16(1)}, false), cip.StatusPathSegmentError)

	// BOOL arrays are DWORDs.
	bits, _ := Ints(cip.TypeDWORD, 0, 1<<8)
	must(t, ts.Set("Bits", bits))
	// The index counts DWORDs: Bits[1] is bits 32 to 63.
	if r := h.read("Bits[1]", 1); !r.OK() || !bytes.Equal(r.Data, []byte{0xD3, 0, 0, 1, 0, 0}) {
		t.Fatalf("Bits[1] %+v", r)
	}
	wantBeyond(t, "Bits[1] x2", h.read("Bits[1]", 2))
	wantBeyond(t, "Bits[2]", h.read("Bits[2]", 1))
	if r := h.read("Bits", 2); !r.OK() || len(r.Data) != 10 {
		t.Fatalf("Bits %+v", r)
	}
	if r := h.read("Flag", 1); !r.OK() || !bytes.Equal(r.Data, []byte{0xC1, 0, 0}) {
		t.Fatalf("Flag %+v", r)
	}
}

func TestTagServerStructMembers(t *testing.T) {
	h := newHarness(t)
	ts := h.ts
	data := append(make([]byte, 116), outerData()...)
	must(t, ts.Set("Outs", Value{Handle: 0x2222, Count: 2, Data: data}))
	cases := []struct {
		name  string
		count int
		want  []byte
	}{
		{"Outs[1].X", 1, []byte{0xC4, 0, 0xFE, 0xFF, 0xFF, 0xFF}},
		{"Outs[1].In.A", 1, []byte{0xC3, 0, 7, 0}},
		{"outs[1].in.b", 1, []byte{0xC1, 0, 1}},
		{"Outs[0].In.B", 1, []byte{0xC1, 0, 0}},
		{"Outs[1].Ins[1].A", 1, []byte{0xC3, 0, 9, 0}},
		{"Outs[1].Ins[0]", 2, cat([]byte{0xA0, 2, 0x11, 0x11}, outerData()[8:16])},
		{"Outs[1].In", 1, cat([]byte{0xA0, 2, 0x11, 0x11}, outerData()[4:8])},
		{"Outs[1].Flags[1]", 1, []byte{0xD3, 0, 0x80, 0, 0, 0}},
		{"Outs[1].Flags[0]", 2, []byte{0xD3, 0, 4, 0, 0, 0, 0x80, 0, 0, 0}},
		{"Outs[1].Flags", 2, []byte{0xD3, 0, 4, 0, 0, 0, 0x80, 0, 0, 0}},
		{"Outs[1].Raw[1]", 2, []byte{0xC2, 0, 2, 3}},
		{"Outs[1].Raw", 3, []byte{0xC2, 0, 1, 2, 3}},
		{"Outs[1].Txt.LEN", 1, []byte{0xC4, 0, 2, 0, 0, 0}},
		{"Outs[1].Txt.DATA[1]", 1, []byte{0xC2, 0, 'i'}},
		{"Outs[1]", 1, cat([]byte{0xA0, 2, 0x22, 0x22}, outerData())},
	}
	for _, c := range cases {
		r := h.read(c.name, c.count)
		if !r.OK() || !bytes.Equal(r.Data, c.want) {
			t.Fatalf("%s: %x %x, want %x", c.name, uint8(r.Status), r.Data, c.want)
		}
	}
	if r := h.read("Outs[1].Txt", 1); !r.OK() || !bytes.Equal(r.Data[:4], []byte{0xA0, 2, 0xCE, 0x0F}) || len(r.Data) != 4+88 {
		t.Fatalf("Txt %+v", r)
	}
	wantBeyond(t, "member count 2", h.read("Outs[1].X", 2))
	wantBeyond(t, "bit count 2", h.read("Outs[1].In.B", 2))
	wantBeyond(t, "Raw x4", h.read("Outs[1].Raw", 4))
	wantBeyond(t, "Raw[3]", h.read("Outs[1].Raw[3]", 1))
	wantBeyond(t, "Flags[2]", h.read("Outs[1].Flags[2]", 1))
	wantBeyond(t, "Outs[2]", h.read("Outs[2].X", 1))
	wantStatus(t, "member of array", h.read("Outs.X", 1), cip.StatusPathSegmentError)
	wantStatus(t, "unknown member", h.read("Outs[0].Nope", 1), cip.StatusPathDestinationUnknown)
	wantStatus(t, "hidden member", h.read("Outs[0].In.ZZZZZZZZZZInner2", 1), cip.StatusPathDestinationUnknown)
	wantStatus(t, "member of member atomic", h.read("Outs[0].X.Y", 1), cip.StatusPathSegmentError)
	wantStatus(t, "index of struct member", h.read("Outs[0].In[0]", 1), cip.StatusPathSegmentError)

	// A member whose template was removed behind the server's back.
	delete(ts.templates, 0x10)
	wantStatus(t, "lost template", h.read("Outs[0].In.A", 1), cip.StatusPathDestinationUnknown)
}

func TestTagServerReadLimits(t *testing.T) {
	h := newHarness(t, WithMaxReply(100), WithMaxReply(10))
	big := make([]int64, 1000)
	for i := range big {
		big[i] = int64(i)
	}
	bv, _ := Ints(cip.TypeINT, big...)
	must(t, h.ts.Set("Big", bv))
	req := cip.Request{Service: cip.ServiceReadTag, Path: h.path("Big"), Data: le16(1000)}
	r := h.do(req, false)
	wantStatus(t, "unconnected", r, cip.StatusPartialTransfer)
	if len(r.Data) != 480 || !bytes.Equal(r.Data[2:], bv.Data[:478]) {
		t.Fatalf("unconnected %d octets", len(r.Data))
	}
	r = h.do(req, true)
	wantStatus(t, "connected", r, cip.StatusPartialTransfer)
	if len(r.Data) != 100 {
		t.Fatalf("connected %d octets", len(r.Data))
	}
	frag := func(count uint16, off uint32) cip.Response {
		return h.do(cip.Request{Service: cip.ServiceReadTagFragmented, Path: h.path("Big"), Data: cat(le16(count), le32(off))}, true)
	}
	// Reassemble as the client does.
	var got []byte
	for {
		r := frag(1000, uint32(len(got)))
		if !r.OK() && r.Status != cip.StatusPartialTransfer {
			t.Fatalf("fragment at %d: %+v", len(got), r)
		}
		if !bytes.Equal(r.Data[:2], []byte{0xC3, 0}) {
			t.Fatalf("type %x", r.Data[:2])
		}
		got = append(got, r.Data[2:]...)
		if r.OK() {
			break
		}
	}
	if !bytes.Equal(got, bv.Data) {
		t.Fatal("fragmented read differs")
	}
	if r := frag(1000, 2000); !r.OK() || len(r.Data) != 2 {
		t.Fatalf("offset at the end %+v", r)
	}
	wantStatus(t, "offset beyond", frag(1000, 2001), cip.StatusInvalidParameter)
	wantStatus(t, "no offset", h.do(cip.Request{Service: cip.ServiceReadTagFragmented, Path: h.path("Big"), Data: le16(1)}, true), cip.StatusNotEnoughData)
	// An Outer element (116 octets) does not fit 98 octets of room.
	wantStatus(t, "struct larger than a reply", h.do(cip.Request{Service: cip.ServiceReadTag, Path: h.path("Outs"), Data: le16(2)}, true), cip.StatusReplyDataTooLarge)
}

func TestTagServerWrite(t *testing.T) {
	h := newHarness(t)
	var written []string
	h.ts.OnWrite(func(name string) { written = append(written, name) })

	v, _ := Ints(cip.TypeDINT, 77)
	if r := h.write("Count", v); !r.OK() {
		t.Fatalf("%+v", r)
	}
	if g, _ := h.ts.Get("Count"); !bytes.Equal(g.Data, v.Data) {
		t.Fatalf("Count %x", g.Data)
	}
	l, _ := Ints(cip.TypeSINT, -1)
	if r := h.write("program:main.LOCAL", l); !r.OK() {
		t.Fatalf("%+v", r)
	}
	f, _ := Floats(cip.TypeREAL, 1)
	wantTypeMismatch(t, "REAL into DINT", h.write("Count", f))
	s, _ := Strings("hello")
	wantTypeMismatch(t, "STRING into Outer", h.write("Outs[0]", s))
	wantTypeMismatch(t, "DINT into struct", h.write("Text", v))
	if r := h.write("Text", s); !r.OK() {
		t.Fatalf("Text %+v", r)
	}
	if g, _ := h.ts.Get("Text"); func() string { x, _ := g.Text(0); return x }() != "hello" {
		t.Fatal("Text not written")
	}
	two, _ := Ints(cip.TypeDINT, 1, 2)
	wantBeyond(t, "count 2", h.write("Count", two))
	wantBeyond(t, "count 0", h.write("Count", Value{Type: cip.TypeDINT, Data: v.Data}))
	// Extra octets after the elements are ignored (see TestTagServerWriteTrailingData).
	wantStatus(t, "trailing octets", h.write("Count", Value{Type: cip.TypeDINT, Count: 1, Data: make([]byte, 5)}), cip.StatusSuccess)
	wantStatus(t, "not enough", h.write("Count", Value{Type: cip.TypeDINT, Count: 1, Data: make([]byte, 3)}), cip.StatusNotEnoughData)
	wantStatus(t, "no header", h.do(cip.Request{Service: cip.ServiceWriteTag, Path: h.path("Count"), Data: []byte{0xC4, 0}}, false), cip.StatusNotEnoughData)
	wantStatus(t, "unknown tag", h.write("Nope", v), cip.StatusPathDestinationUnknown)

	// Elements and members.
	x, _ := Ints(cip.TypeINT, 3, 4)
	if r := h.write("Big[998]", x); !r.OK() {
		t.Fatalf("%+v", r)
	}
	wantBeyond(t, "Big[999] x2", h.write("Big[999]", x))
	if r := h.write("Outs[1].Ins[1].A", Value{Type: cip.TypeINT, Count: 1, Data: []byte{5, 0}}); !r.OK() {
		t.Fatalf("%+v", r)
	}
	g, _ := h.ts.Get("Outs")
	if binary.LittleEndian.Uint16(g.Data[116+12:]) != 5 {
		t.Fatal("Outs[1].Ins[1].A not written")
	}

	// BOOL members.
	on, _ := Ints(cip.TypeBOOL, 1)
	off, _ := Ints(cip.TypeBOOL, 0)
	if r := h.write("Outs[1].In.B", on); !r.OK() {
		t.Fatalf("%+v", r)
	}
	g, _ = h.ts.Get("Outs")
	if g.Data[116+6] != 1<<3 {
		t.Fatalf("In.B host %x", g.Data[116+6])
	}
	if r := h.write("Outs[1].In.B", off); !r.OK() {
		t.Fatalf("%+v", r)
	}
	g, _ = h.ts.Get("Outs")
	if g.Data[116+6] != 0 {
		t.Fatalf("In.B host %x", g.Data[116+6])
	}
	// Trailing octets are ignored (pycomm3 repeats the request); none is
	// not enough.
	if r := h.write("Outs[1].In.B", Value{Type: cip.TypeBOOL, Count: 1, Data: []byte{1, 1}}); !r.OK() {
		t.Fatalf("bit with 2 octets %+v", r)
	}
	if r := h.write("Outs[1].In.B", Value{Type: cip.TypeBOOL, Count: 1}); r.Status != cip.StatusNotEnoughData {
		t.Fatalf("bit without data %+v", r)
	}
	wantBeyond(t, "bit fragmented", h.do(cip.Request{Service: cip.ServiceWriteTagFragmented, Path: h.path("Outs[1].In.B"), Data: cat([]byte{0xC1, 0, 1, 0}, le32(1), []byte{1})}, false))
	wantTypeMismatch(t, "INT into BOOL member", h.write("Outs[1].In.B", x))

	// BOOL arrays take DWORDs.
	dw, _ := Ints(cip.TypeDWORD, 1<<5)
	if r := h.write("Bits[1]", dw); !r.OK() {
		t.Fatalf("%+v", r)
	}
	if b, _ := h.ts.Get("Bits"); b.Data[4] != 1<<5 {
		t.Fatalf("Bits %x", b.Data)
	}

	want := []string{"Count", "Program:Main.Local", "Text", "Count", "Big", "Outs", "Outs", "Outs", "Outs", "Bits"}
	if !reflect.DeepEqual(written, want) {
		t.Fatalf("OnWrite %v, want %v", written, want)
	}
}

func TestTagServerWriteFragmented(t *testing.T) {
	h := newHarness(t)
	big := make([]int64, 1000)
	for i := range big {
		big[i] = int64(1000 - i)
	}
	bv, _ := Ints(cip.TypeINT, big...)
	frag := func(off int, chunk []byte) cip.Response {
		data := cat([]byte{0xC3, 0}, le16(1000), le32(uint32(off)), chunk)
		return h.do(cip.Request{Service: cip.ServiceWriteTagFragmented, Path: h.path("Big"), Data: data}, false)
	}
	for off := 0; off < len(bv.Data); off += 400 {
		if r := frag(off, bv.Data[off:min(off+400, len(bv.Data))]); !r.OK() {
			t.Fatalf("at %d: %+v", off, r)
		}
	}
	if g, _ := h.ts.Get("Big"); !bytes.Equal(g.Data, bv.Data) {
		t.Fatal("fragmented write differs")
	}
	wantStatus(t, "beyond", frag(1999, []byte{1, 2}), cip.StatusTooMuchData)
	wantStatus(t, "no offset", h.do(cip.Request{Service: cip.ServiceWriteTagFragmented, Path: h.path("Big"), Data: []byte{0xC3, 0, 1, 0}}, false), cip.StatusNotEnoughData)
	// A short fragment is fine.
	if r := frag(0, []byte{9}); !r.OK() {
		t.Fatalf("%+v", r)
	}
}

func TestTagServerReadModifyWrite(t *testing.T) {
	h := newHarness(t)
	v, _ := Ints(cip.TypeDINT, 0x0F0)
	must(t, h.ts.Set("Count", v))
	rmw := func(name string, data []byte) cip.Response {
		return h.do(cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: h.path(name), Data: data}, false)
	}
	// Set bit 0, clear bit 4.
	if r := rmw("Count", cat(le16(4), []byte{1, 0, 0, 0}, []byte{0xEF, 0xFF, 0xFF, 0xFF})); !r.OK() {
		t.Fatalf("%+v", r)
	}
	if g, _ := h.ts.Get("Count"); binary.LittleEndian.Uint32(g.Data) != 0x0E1 {
		t.Fatalf("Count %x", g.Data)
	}
	// pycomm3 sends 8 octets of AND mask: the rest is ignored.
	if r := rmw("Count", cat(le16(4), []byte{0, 1, 0, 0}, []byte{0xFE, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0})); !r.OK() {
		t.Fatalf("pycomm3 %+v", r)
	}
	if g, _ := h.ts.Get("Count"); binary.LittleEndian.Uint32(g.Data) != 0x1E0 {
		t.Fatalf("Count %x", g.Data)
	}
	// A smaller mask touches the low octets only.
	if r := rmw("Count", cat(le16(1), []byte{0x0F}, []byte{0x0F})); !r.OK() {
		t.Fatalf("1 octet %+v", r)
	}
	if g, _ := h.ts.Get("Count"); binary.LittleEndian.Uint32(g.Data) != 0x10F {
		t.Fatalf("Count %x", g.Data)
	}
	// BOOL arrays are DWORDs, integers.
	if r := rmw("Bits[1]", cat(le16(4), []byte{0, 0, 0, 0x80}, []byte{0xFF, 0xFF, 0xFF, 0xFF})); !r.OK() {
		t.Fatalf("Bits %+v", r)
	}
	if b, _ := h.ts.Get("Bits"); b.Data[7] != 0x80 {
		t.Fatalf("Bits %x", b.Data)
	}
	wantTypeMismatch(t, "mask larger than DINT", rmw("Count", cat(le16(8), make([]byte, 16))))
	wantTypeMismatch(t, "REAL", rmw("Speed", cat(le16(4), make([]byte, 8))))
	wantTypeMismatch(t, "BOOL", rmw("Flag", cat(le16(1), make([]byte, 2))))
	wantTypeMismatch(t, "struct", rmw("Text", cat(le16(4), make([]byte, 8))))
	wantTypeMismatch(t, "bit member", rmw("Outs[0].In.B", cat(le16(1), make([]byte, 2))))
	wantStatus(t, "size 0", rmw("Count", le16(0)), cip.StatusNotEnoughData)
	wantStatus(t, "short masks", rmw("Count", cat(le16(4), make([]byte, 6))), cip.StatusNotEnoughData)
	wantStatus(t, "unknown", rmw("Nope", cat(le16(4), make([]byte, 8))), cip.StatusPathDestinationUnknown)
}

func TestTagServerServiceNotSupported(t *testing.T) {
	h := newHarness(t)
	wantStatus(t, "symbolic", h.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: h.path("Count")}, false), cip.StatusServiceNotSupported)
	wantStatus(t, "template", h.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassTemplate, 0x10)}, false), cip.StatusServiceNotSupported)
	wantStatus(t, "program name", h.do(cip.Request{Service: cip.ServiceSetAttributesAll, Path: cip.ObjectPath(cip.ClassProgramName, 1)}, false), cip.StatusServiceNotSupported)
}

func TestTagServerInstanceAddressing(t *testing.T) {
	h := newHarness(t)
	v, _ := Ints(cip.TypeDINT, 12)
	must(t, h.ts.Set("Count", v))
	inst := h.ts.tags["count"].inst
	r := h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.ObjectPath(cip.ClassSymbol, inst), Data: le16(1)}, true)
	if !r.OK() || !bytes.Equal(r.Data, []byte{0xC4, 0, 12, 0, 0, 0}) {
		t.Fatalf("%+v", r)
	}
	gi := h.ts.tags["grid"].inst
	path := append(cip.ObjectPath(cip.ClassSymbol, gi), mem(0), mem(1))
	if r := h.do(cip.Request{Service: cip.ServiceReadTag, Path: path, Data: le16(1)}, true); !r.OK() || len(r.Data) != 6 {
		t.Fatalf("Grid[0,1] %+v", r)
	}
	oi := h.ts.tags["outs"].inst
	path = append(cip.ObjectPath(cip.ClassSymbol, oi), mem(1), sym{Name: "X"})
	w := Value{Type: cip.TypeDINT, Count: 1, Data: []byte{3, 0, 0, 0}}
	if r := h.do(cip.Request{Service: cip.ServiceWriteTag, Path: path, Data: cat(w.appendType(nil), le16(1), w.Data)}, true); !r.OK() {
		t.Fatalf("Outs[1].X %+v", r)
	}
	wantStatus(t, "unknown instance", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.ObjectPath(cip.ClassSymbol, 9999), Data: le16(1)}, true), cip.StatusPathDestinationUnknown)
}

// listReq builds a Get Instance Attribute List request.
func listReq(prefix cip.Path, start uint32, attrs ...uint16) cip.Request {
	p := append(append(cip.Path{}, prefix...), cip.ClassSegment(cip.ClassSymbol), cip.InstanceSegment(start))
	data := le16(uint16(len(attrs)))
	for _, a := range attrs {
		data = append(data, le16(a)...)
	}
	return cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: p, Data: data}
}

type listed struct {
	inst uint32
	name string
	typ  SymbolType
	dims [3]uint32
}

func parseList(t *testing.T, b []byte) []listed {
	t.Helper()
	r := cip.NewReader(b)
	var out []listed
	for r.Len() > 0 {
		e := listed{inst: r.Uint32(), name: r.String(), typ: SymbolType(r.Uint16())}
		for i := range e.dims {
			e.dims[i] = r.Uint32()
		}
		if r.Err() != nil {
			t.Fatalf("list: %v", r.Err())
		}
		out = append(out, e)
	}
	return out
}

func TestTagServerListTags(t *testing.T) {
	h := newHarness(t)
	r := h.do(listReq(nil, 0, 1, 2, 8), false)
	if !r.OK() {
		t.Fatalf("%+v", r)
	}
	l := parseList(t, r.Data)
	by := map[string]listed{}
	for i, e := range l {
		by[e.name] = e
		if i > 0 && l[i-1].inst >= e.inst {
			t.Fatal("not sorted")
		}
	}
	if len(l) != 10 || by["Local"].name != "" {
		t.Fatalf("%d entries %+v", len(l), l)
	}
	if p := by["Program:Main"]; p.typ != 0x1068 || !p.typ.IsSystem() {
		t.Fatalf("program %+v", p)
	}
	if g := by["Grid"]; g.dims != [3]uint32{3, 4, 0} || g.typ.Atomic() != cip.TypeREAL || g.typ.Dims() != 2 {
		t.Fatalf("Grid %+v", g)
	}
	if o := by["Outs"]; !o.typ.IsStruct() || o.typ.Template() != 0x20 || o.dims[0] != 2 {
		t.Fatalf("Outs %+v", o)
	}

	// Paging from an instance.
	start := by["Grid"].inst
	r = h.do(listReq(nil, start, 1, 2, 8), false)
	if l2 := parseList(t, r.Data); !r.OK() || l2[0].name != "Grid" || len(l2) != len(l)-int(start)+1 {
		t.Fatalf("from %d: %+v", start, l2)
	}

	// Program scope, via the symbol handler.
	r = h.do(listReq(cip.Path{sym{Name: "Program:Main"}}, 0, 1, 2, 8), false)
	if pl := parseList(t, r.Data); !r.OK() || len(pl) != 1 || pl[0].name != "Local" {
		t.Fatalf("program list %+v", pl)
	}
	wantStatus(t, "unknown program", h.do(listReq(cip.Path{sym{Name: "Program:Nope"}}, 0, 1), false), cip.StatusPathDestinationUnknown)

	// Attribute selection.
	r = h.do(listReq(nil, 0, 3, 5, 6, 7, 10), false)
	if !r.OK() || len(r.Data) != 10*(4+4+4+4+2+1) {
		t.Fatalf("attributes 3,5,6,7,10: %d octets", len(r.Data))
	}
	r = h.do(listReq(nil, 0), false)
	wantStatus(t, "no attributes", r, cip.StatusNotEnoughData)
	wantStatus(t, "17 attributes", h.do(listReq(nil, 0, make([]uint16, 17)...), false), cip.StatusNotEnoughData)
	short := listReq(nil, 0, 1, 2)
	short.Data = short.Data[:4]
	wantStatus(t, "short list", h.do(short, false), cip.StatusNotEnoughData)
	for _, a := range []uint16{0, 4, 9, 11} {
		wantStatus(t, "attribute", h.do(listReq(nil, 0, 1, a), false), cip.StatusAttributeNotSupported)
	}

	// Path errors.
	sr := func(p cip.Path) cip.Response {
		return h.ts.listTags(&server.Request{Request: cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: p, Data: []byte{1, 0, 1, 0}}})
	}
	wantStatus(t, "program only", sr(cip.Path{sym{Name: "Program:Main"}}), cip.StatusPathSegmentError)
	wantStatus(t, "wrong class", sr(cip.Path{cip.ClassSegment(cip.ClassTemplate), cip.InstanceSegment(0)}), cip.StatusPathSegmentError)
	wantStatus(t, "not logical", sr(cip.Path{sym{Name: "Program:Main"}, sym{Name: "X"}}), cip.StatusPathSegmentError)
	if r := sr(cip.Path{cip.ClassSegment(cip.ClassSymbol)}); !r.OK() || len(parseListNames(r.Data)) != 10 {
		t.Fatalf("class only %+v", r)
	}
	if r := sr(cip.Path{cip.ClassSegment(cip.ClassSymbol), cip.AttributeSegment(1)}); !r.OK() {
		t.Fatalf("no instance %+v", r)
	}
}

// parseListNames reads entries of attribute 1 only.
func parseListNames(b []byte) []string {
	r := cip.NewReader(b)
	var out []string
	for r.Len() > 0 && r.Err() == nil {
		r.Uint32()
		out = append(out, r.String())
	}
	return out
}

func TestTagServerListPaging(t *testing.T) {
	ts := NewTagServer(WithMaxReply(64))
	for _, n := range []string{"Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Program:P.Eta"} {
		must(t, ts.AddTag(n, cip.TypeDINT))
	}
	srv, _ := server.New()
	defer func() { _ = srv.Close() }()
	ts.Attach(srv)
	sym := srv.Object(cip.ClassSymbol)
	var names []string
	start := uint32(0)
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("no end")
		}
		req := listReq(nil, start, 1, 2, 8)
		r := sym.ServeCIP(ctx, &server.Request{Request: req, Instance: start, Connected: true})
		if !r.OK() && r.Status != cip.StatusPartialTransfer {
			t.Fatalf("%+v", r)
		}
		if len(r.Data) > 64 {
			t.Fatalf("page of %d", len(r.Data))
		}
		l := parseList(t, r.Data)
		for _, e := range l {
			names = append(names, e.name)
		}
		if r.OK() {
			break
		}
		start = l[len(l)-1].inst + 1
	}
	want := []string{"Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Program:P"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("%v", names)
	}
	// An entry larger than a reply.
	ts2 := NewTagServer(WithMaxReply(64))
	must(t, ts2.AddTag(strings.Repeat("N", 40), cip.TypeDINT))
	r := ts2.listTags(&server.Request{Request: listReq(nil, 0, 1, 2, 3, 5, 6, 7, 8, 10), Connected: true})
	wantStatus(t, "entry too large", r, cip.StatusReplyDataTooLarge)
}

func TestTagServerTemplateObject(t *testing.T) {
	h := newHarness(t, WithMaxReply(64))
	_, outer := testTemplates()
	attrs := func(inst uint32, ids ...uint16) cip.Response {
		data := le16(uint16(len(ids)))
		for _, id := range ids {
			data = append(data, le16(id)...)
		}
		return h.do(cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, inst), Data: data}, false)
	}
	def := outer.definition()
	words := definitionWords(len(def))
	r := attrs(0x20, 4, 5, 2, 1)
	want := cat(le16(4), le16(4), le16(0), le32(words), le16(5), le16(0), le32(116), le16(2), le16(0), le16(6), le16(1), le16(0), le16(0x2222))
	if !r.OK() || !bytes.Equal(r.Data, want) {
		t.Fatalf("attributes %x, want %x", r.Data, want)
	}
	r = attrs(0x20, 1, 3)
	wantStatus(t, "attribute 3", r, cip.StatusAttributeListError)
	if !bytes.Equal(r.Data, cat(le16(2), le16(1), le16(0), le16(0x2222), le16(3), le16(uint16(cip.StatusAttributeNotSupported)))) {
		t.Fatalf("list error %x", r.Data)
	}
	wantStatus(t, "no attributes", attrs(0x20), cip.StatusNotEnoughData)
	wantStatus(t, "unknown template", attrs(0x30, 1), cip.StatusPathDestinationUnknown)
	wantStatus(t, "instance above 16 bits", attrs(0x10020, 1), cip.StatusPathDestinationUnknown)
	if r := attrs(uint32(StringTemplate.ID), 1); !r.OK() || !bytes.Equal(r.Data[6:], le16(StringHandle)) {
		t.Fatalf("STRING template %+v", r)
	}

	read := func(off uint32, n uint16, connected bool) cip.Response {
		return h.do(cip.Request{Service: cip.ServiceReadTemplate, Path: cip.ObjectPath(cip.ClassTemplate, 0x20), Data: cat(le32(off), le16(n))}, connected)
	}
	total := definitionLen(words) // 1756-PM020: words×4 − 23
	var got []byte
	for {
		r := read(uint32(len(got)), uint16(total-len(got)), true)
		if !r.OK() && r.Status != cip.StatusPartialTransfer {
			t.Fatalf("%+v", r)
		}
		if len(r.Data) > 64 || (r.Status == cip.StatusPartialTransfer && len(r.Data)%4 != 0) {
			t.Fatalf("chunk of %d", len(r.Data))
		}
		got = append(got, r.Data...)
		if r.OK() {
			break
		}
	}
	if len(got) != total {
		t.Fatalf("%d of %d", len(got), total)
	}
	name, ms, err := parseDefinition(got, 6)
	if err != nil || name != "Outer" || !reflect.DeepEqual(ms, outer.Members) {
		t.Fatalf("%q %+v %v", name, ms, err)
	}
	if r := read(0, 0xFFFF, false); !r.OK() || len(r.Data) != total {
		t.Fatalf("unconnected %d", len(r.Data))
	}
	// A read starting at the end is refused: a client looping until it
	// has its computed size stops (pylogix asks for the size rounded up).
	wantStatus(t, "at the end", read(uint32(total), 10, false), cip.StatusInvalidParameter)
	wantStatus(t, "beyond", read(uint32(total)+1, 1, false), cip.StatusInvalidParameter)
	if r := read(uint32(total-1), 10, false); !r.OK() || len(r.Data) != 1 {
		t.Fatalf("the last octet, asking for more: %+v", r)
	}
	wantStatus(t, "short", h.do(cip.Request{Service: cip.ServiceReadTemplate, Path: cip.ObjectPath(cip.ClassTemplate, 0x20), Data: le32(0)}, false), cip.StatusNotEnoughData)
}

func TestTagServerProgramName(t *testing.T) {
	h := newHarness(t, WithProgramName("Plant"))
	r := h.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassProgramName, 1)}, false)
	if !r.OK() || string(r.Data) != "\x05\x00Plant" {
		t.Fatalf("%+v", r)
	}
	wantStatus(t, "instance 2", h.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassProgramName, 2)}, false), cip.StatusPathDestinationUnknown)
	if NewTagServer().programName != "OTFabric" {
		t.Fatal("default program name")
	}
	for _, c := range []cip.Class{cip.ClassSymbol, cip.ClassTemplate, cip.ClassProgramName} {
		if o := h.srv.Object(c); o == nil || o.Class() != c {
			t.Fatalf("class 0x%X not attached", uint16(c))
		}
	}
}

// tsDoer routes client requests to a harness, unconnected.
type tsDoer struct{ h *harness }

func (d tsDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	resp := d.h.do(req, false)
	return resp, client.ResponseError(req, resp)
}

// Partial transfers end on element boundaries: cpppo's client cannot
// parse a reply that ends with half an element.
func TestTagServerPartialElementBoundary(t *testing.T) {
	h := newHarness(t)
	must(t, h.ts.AddTag("Dints", cip.TypeDINT, 500))
	must(t, h.ts.AddTag("Lreals", cip.TypeLREAL, 200))
	must(t, h.ts.AddStructTag("Inners", 0x10, 300))
	must(t, h.ts.AddStructTag("Texts", StringTemplate.ID, 10))
	fill := func(name string) []byte {
		g, _ := h.ts.Get(name)
		for i := range g.Data {
			g.Data[i] = byte(i * 7)
		}
		must(t, h.ts.Set(name, g))
		return g.Data
	}
	cases := []struct {
		name     string
		count    int
		head     int
		elemSize int
		want     int // data octets of the first partial reply
	}{
		{"Dints", 500, 2, 4, 476},
		{"Big", 1000, 2, 2, 478},
		{"Lreals", 200, 2, 8, 472},
		{"Inners", 300, 4, 4, 476},
		{"Texts", 10, 4, 88, 440},
	}
	c := NewClient(tsDoer{h})
	for _, cs := range cases {
		all := fill(cs.name)
		frag := func(off int) cip.Response {
			return h.do(cip.Request{Service: cip.ServiceReadTagFragmented, Path: h.path(cs.name), Data: cat(le16(uint16(cs.count)), le32(uint32(off)))}, false)
		}
		off := 0
		for first := true; ; first = false {
			r := frag(off)
			if !r.OK() && r.Status != cip.StatusPartialTransfer {
				t.Fatalf("%s at %d: %+v", cs.name, off, r)
			}
			n := len(r.Data) - cs.head
			if r.Status == cip.StatusPartialTransfer && n%cs.elemSize != 0 {
				t.Fatalf("%s at %d: %d octets, not a multiple of %d", cs.name, off, n, cs.elemSize)
			}
			if first && n != cs.want {
				t.Fatalf("%s: first reply %d octets, want %d", cs.name, n, cs.want)
			}
			if len(r.Data) > 480 {
				t.Fatalf("%s: reply of %d", cs.name, len(r.Data))
			}
			off += n
			if r.OK() {
				break
			}
		}
		if off != len(all) {
			t.Fatalf("%s: %d of %d octets", cs.name, off, len(all))
		}
		// The client reassembles by octet offset.
		v, err := c.Read(ctx, cs.name, cs.count)
		if err != nil || !bytes.Equal(v.Data, all) {
			t.Fatalf("%s: client read %v", cs.name, err)
		}
	}
	// A bit member is one octet and never partial.
	if r := h.read("Outs[0].In.B", 1); !r.OK() || len(r.Data) != 3 {
		t.Fatalf("bit %+v", r)
	}
}

// TestTagServerWriteTrailingData writes DINT 77 to Counter as pycomm3 1.2.16
// sends it: the request repeated after the value, in the same message.
func TestTagServerWriteTrailingData(t *testing.T) {
	ts := NewTagServer()
	if err := ts.AddTag("Counter", cip.TypeDINT); err != nil {
		t.Fatal(err)
	}
	data := []byte{0xC4, 0x00, 0x01, 0x00, 0x4D, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x4D, 0x05, 0x91, 0x07, 'C', 'o', 'u', 'n', 't', 'e', 'r', 0x00, 0xC4, 0x00, 0x01, 0x00, 0x4D, 0x00, 0x00, 0x00}
	r := &server.Request{Request: cip.Request{Service: cip.ServiceWriteTag, Path: cip.Path{cip.SymbolSegment{Name: "Counter"}}, Data: data}, Connected: true}
	if resp := ts.ServeSymbol(context.Background(), r); !resp.OK() {
		t.Fatalf("status %s", resp.Status)
	}
	v, _ := ts.Get("Counter")
	if n, _ := v.Int(0); n != 77 {
		t.Fatalf("Counter = %d", n)
	}
	// Fragmented writes still may not run past the tag.
	frag := append([]byte{0xC4, 0x00, 0x01, 0x00, 0, 0, 0, 0}, 1, 2, 3, 4, 5)
	r.Service, r.Data = cip.ServiceWriteTagFragmented, frag
	if resp := ts.ServeSymbol(context.Background(), r); resp.Status != cip.StatusTooMuchData {
		t.Fatalf("fragmented status %s", resp.Status)
	}
}

// TestTagServerConnectionSize checks that a connected reply fits the
// connection's size: a Read Tag on a small connection is a partial
// transfer within it.
func TestTagServerConnectionSize(t *testing.T) {
	ts := NewTagServer()
	must(t, ts.AddTag("Big", cip.TypeINT, 1000))
	req := func(maxReply int) cip.Response {
		return ts.ServeSymbol(context.Background(), &server.Request{
			Request:   cip.Request{Service: cip.ServiceReadTag, Path: cip.Path{cip.SymbolSegment{Name: "Big"}}, Data: le16(1000)},
			Connected: true, MaxReply: maxReply})
	}
	r := req(504 - 6)
	if r.Status != cip.StatusPartialTransfer || len(r.Data) > 504-6 {
		t.Fatalf("on a 504-octet connection: status %v, %d octets", r.Status, len(r.Data))
	}
	// Without a connection size the server's own limit applies: the 2002
	// octets fit it.
	if r := req(0); !r.OK() || len(r.Data) != 2+2000 {
		t.Fatalf("without a size: status %v, %d octets", r.Status, len(r.Data))
	}
}
