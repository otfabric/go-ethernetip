// SPDX-License-Identifier: MIT

package logix

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
)

// fakeDoer records requests and answers each with the next scripted
// response; errors are built as the real client builds them.
type fakeDoer struct {
	t     *testing.T
	reqs  []cip.Request
	resps []cip.Response
	err   error // returned instead of a response when set
}

func (f *fakeDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return cip.Response{}, f.err
	}
	if len(f.resps) == 0 {
		f.t.Fatalf("unexpected request %+v", req)
	}
	resp := f.resps[0]
	f.resps = f.resps[1:]
	return resp, client.ResponseError(req, resp)
}

// multiDoer adds a Multiple Service Packet method.
type multiDoer struct {
	fakeDoer
	batches [][]cip.Request
	answer  func(cip.Request) cip.Response
	mspErr  error
}

func (m *multiDoer) MultipleService(_ context.Context, reqs []cip.Request) ([]cip.Response, error) {
	m.batches = append(m.batches, reqs)
	if m.mspErr != nil {
		return nil, m.mspErr
	}
	out := make([]cip.Response, len(reqs))
	for i, r := range reqs {
		out[i] = m.answer(r)
	}
	return out, nil
}

func ok(data ...byte) cip.Response { return cip.Response{Data: data} }

func partial(data ...byte) cip.Response {
	return cip.Response{Status: cip.StatusPartialTransfer, Data: data}
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

var ctx = context.Background()

func TestClientReadSimple(t *testing.T) {
	d := &fakeDoer{t: t, resps: []cip.Response{ok(0xC4, 0, 0xD6, 0xFF, 0xFF, 0xFF)}}
	c := NewClient(d)
	v, err := c.Read(ctx, "Program:Main.Count", 1)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := v.Int(0); x != -42 || v.Type != cip.TypeDINT || v.Count != 1 {
		t.Fatalf("%+v", v)
	}
	r := d.reqs[0]
	if r.Service != cip.ServiceReadTag || !bytes.Equal(r.Data, []byte{1, 0}) ||
		!reflect.DeepEqual(r.Path, cip.Path{sym{Name: "Program:Main"}, sym{Name: "Count"}}) {
		t.Fatalf("request %+v", r)
	}
}

func TestClientReadFragmented(t *testing.T) {
	d := &fakeDoer{t: t, resps: []cip.Response{
		partial(0xC3, 0, 1, 0, 2, 0),
		partial(0xC3, 0, 3, 0),
		ok(0xC3, 0, 4, 0),
	}}
	v, err := NewClient(d).Read(ctx, "Arr[2]", 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if x, _ := v.Int(i); x != int64(i+1) {
			t.Fatalf("[%d] = %d", i, x)
		}
	}
	if len(d.reqs) != 3 {
		t.Fatalf("%d requests", len(d.reqs))
	}
	for i, off := range []uint32{4, 6} {
		r := d.reqs[i+1]
		if r.Service != cip.ServiceReadTagFragmented || !bytes.Equal(r.Data, cat(le16(4), le32(off))) {
			t.Fatalf("fragment %d: %+v", i, r)
		}
	}
}

func TestClientReadStruct(t *testing.T) {
	d := &fakeDoer{t: t, resps: []cip.Response{ok(cat([]byte{0xA0, 0x02, 0xCE, 0x0F}, make([]byte, 88))...)}}
	v, err := NewClient(d).Read(ctx, "Txt", 1)
	if err != nil || !v.IsStruct() || v.Handle != StringHandle || len(v.Data) != 88 {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestClientReadErrors(t *testing.T) {
	c := NewClient(&fakeDoer{t: t})
	for _, n := range []string{"Bad Name", "Flags.3"} {
		if _, err := c.Read(ctx, n, 1); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Fatalf("%s: %v", n, err)
		}
	}
	for _, n := range []int{0, 0x10000} {
		if _, err := c.Read(ctx, "A", n); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Fatalf("count %d: %v", n, err)
		}
	}
	cases := []struct {
		name  string
		resps []cip.Response
		want  error
	}{
		{"status", []cip.Response{{Status: cip.StatusPathDestinationUnknown}}, nil},
		{"short reply", []cip.Response{ok(0xC4)}, ethernetip.ErrProtocol},
		{"size mismatch", []cip.Response{ok(0xC4, 0, 1, 0)}, ethernetip.ErrProtocol},
		{"empty partial", []cip.Response{partial(0xC4, 0, 1, 0), partial(0xC4, 0)}, ethernetip.ErrProtocol},
		{"fragment status", []cip.Response{partial(0xC4, 0, 1, 0), {Status: cip.StatusGeneralError}}, nil},
		{"fragment short", []cip.Response{partial(0xC4, 0, 1, 0), ok(1)}, ethernetip.ErrProtocol},
	}
	for _, cs := range cases {
		d := &fakeDoer{t: t, resps: cs.resps}
		_, err := NewClient(d).Read(ctx, "A", 1)
		if err == nil {
			t.Fatalf("%s: no error", cs.name)
		}
		if cs.want != nil && !errors.Is(err, cs.want) {
			t.Fatalf("%s: %v", cs.name, err)
		}
		if cs.want == nil {
			var ce *ethernetip.CIPError
			if !errors.As(err, &ce) {
				t.Fatalf("%s: %v", cs.name, err)
			}
		}
	}
	d := &fakeDoer{t: t, err: ethernetip.ErrClosed}
	if _, err := NewClient(d).Read(ctx, "A", 1); !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("transport: %v", err)
	}
}

// fragmentDoer always answers with a partial transfer of 1 MiB.
type fragmentDoer struct{ n int }

func (f *fragmentDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	f.n++
	resp := cip.Response{Status: cip.StatusPartialTransfer, Data: append([]byte{0xC2, 0}, make([]byte, 1<<20)...)}
	return resp, client.ResponseError(req, resp)
}

func TestClientReadUnbounded(t *testing.T) {
	f := &fragmentDoer{}
	if _, err := NewClient(f).Read(ctx, "A", 1); !errors.Is(err, ethernetip.ErrProtocol) || f.n > 20 {
		t.Fatalf("%v after %d requests", err, f.n)
	}
}

func TestClientWrite(t *testing.T) {
	d := &fakeDoer{t: t, resps: []cip.Response{ok()}}
	v, _ := Ints(cip.TypeDINT, 7)
	if err := NewClient(d).Write(ctx, "Count", v); err != nil {
		t.Fatal(err)
	}
	if r := d.reqs[0]; r.Service != cip.ServiceWriteTag || !bytes.Equal(r.Data, []byte{0xC4, 0, 1, 0, 7, 0, 0, 0}) {
		t.Fatalf("%+v", r)
	}
	s, _ := Strings("x")
	d = &fakeDoer{t: t, resps: []cip.Response{ok()}}
	if err := NewClient(d).Write(ctx, "Txt", s); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(d.reqs[0].Data, []byte{0xA0, 0x02, 0xCE, 0x0F, 1, 0, 1, 0, 0, 0, 'x'}) {
		t.Fatalf("struct write %x", d.reqs[0].Data[:12])
	}
	c := NewClient(&fakeDoer{t: t})
	if err := c.Write(ctx, "Bad Name", v); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatal(err)
	}
	for _, bad := range []Value{{Type: cip.TypeDINT}, {Type: cip.TypeDINT, Count: 1}, {Type: cip.TypeSINT, Count: 0x10000, Data: []byte{1}}} {
		if err := c.Write(ctx, "A", bad); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	d = &fakeDoer{t: t, resps: []cip.Response{{Status: cip.StatusGeneralError, Extended: []uint16{ExtTypeMismatch}}}}
	if err := NewClient(d).Write(ctx, "A", v); err == nil {
		t.Fatal("status not reported")
	}
}

func TestClientWriteFragmented(t *testing.T) {
	// 100 DINTs with a maximum of 70 octets: chunks of 68 (aligned to 4).
	vals := make([]int64, 100)
	for i := range vals {
		vals[i] = int64(i)
	}
	v, _ := Ints(cip.TypeDINT, vals...)
	d := &fakeDoer{t: t}
	for i := 0; i < 6; i++ {
		d.resps = append(d.resps, ok())
	}
	if err := NewClient(d, WithMaxData(70), WithMaxData(10)).Write(ctx, "Arr", v); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for i, r := range d.reqs {
		if r.Service != cip.ServiceWriteTagFragmented {
			t.Fatalf("%d: service %v", i, r.Service)
		}
		if !bytes.Equal(r.Data[:4], []byte{0xC4, 0, 100, 0}) {
			t.Fatalf("%d: header %x", i, r.Data[:4])
		}
		if off := binary.LittleEndian.Uint32(r.Data[4:]); int(off) != len(got) || off%4 != 0 {
			t.Fatalf("%d: offset %d", i, off)
		}
		chunk := r.Data[8:]
		if len(chunk) > 68 {
			t.Fatalf("%d: chunk of %d", i, len(chunk))
		}
		got = append(got, chunk...)
	}
	if len(d.reqs) != 6 || !bytes.Equal(got, v.Data) {
		t.Fatalf("%d requests, data %d octets", len(d.reqs), len(got))
	}

	// An error stops the transfer.
	d = &fakeDoer{t: t, resps: []cip.Response{ok(), {Status: cip.StatusTooMuchData}}}
	if err := NewClient(d, WithMaxData(70)).Write(ctx, "Arr", v); err == nil || len(d.reqs) != 2 {
		t.Fatalf("%v after %d", err, len(d.reqs))
	}
}

func TestClientWriteBit(t *testing.T) {
	cases := []struct {
		tag     string
		size    int
		set     bool
		or, and []byte
	}{
		{"Flags.5", 4, true, []byte{0x20, 0, 0, 0}, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"Flags.9", 2, false, []byte{0, 0}, []byte{0xFF, 0xFD}},
		{"B.0", 1, true, []byte{1}, []byte{0xFF}},
		{"L.63", 8, false, make([]byte, 8), []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}},
	}
	for _, c := range cases {
		d := &fakeDoer{t: t, resps: []cip.Response{ok()}}
		if err := NewClient(d).WriteBit(ctx, c.tag, c.size, c.set); err != nil {
			t.Fatalf("%s: %v", c.tag, err)
		}
		r := d.reqs[0]
		want := cat(le16(uint16(c.size)), c.or, c.and)
		if r.Service != cip.ServiceReadModifyWriteTag || !bytes.Equal(r.Data, want) || len(r.Path) != 1 {
			t.Fatalf("%s: %+v, want %x", c.tag, r, want)
		}
	}
	c := NewClient(&fakeDoer{t: t})
	for _, bad := range []struct {
		tag  string
		size int
	}{{"Flags", 4}, {"Flags.8", 1}, {"Flags.1", 3}, {"Flags.32", 4}, {"Bad Name.1", 4}} {
		if err := c.WriteBit(ctx, bad.tag, bad.size, true); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
}

func readAnswer(r cip.Request) cip.Response {
	name := r.Path[0].(cip.SymbolSegment).Name
	switch name {
	case "Missing":
		return cip.Response{Status: cip.StatusPathDestinationUnknown}
	case "Short":
		return ok(0xC4)
	}
	return ok(0xC2, 0, byte(len(name)))
}

func TestClientReadMany(t *testing.T) {
	m := &multiDoer{fakeDoer: fakeDoer{t: t}, answer: readAnswer}
	tags := []string{"A", "Missing", "Bad Name", "Short", "Long_name_number_one", "Long_name_number_two", "Long_name_number_three"}
	res, err := NewClient(m, WithMaxData(64)).ReadMany(ctx, tags)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.batches) < 2 {
		t.Fatalf("%d batches", len(m.batches))
	}
	n := 0
	for _, b := range m.batches {
		size := 2
		for _, r := range b {
			enc, _ := r.Encode()
			size += 2 + len(enc)
			if r.Service != cip.ServiceReadTag || !bytes.Equal(r.Data, []byte{1, 0}) {
				t.Fatalf("request %+v", r)
			}
		}
		if size > 64 {
			t.Fatalf("batch of %d octets", size)
		}
		n += len(b)
	}
	if n != len(tags)-1 {
		t.Fatalf("%d requests sent", n)
	}
	for i, r := range res {
		if r.Tag != tags[i] {
			t.Fatalf("result %d is %q", i, r.Tag)
		}
	}
	if x, _ := res[0].Value.Int(0); res[0].Err != nil || x != 1 || res[0].Value.Count != 1 {
		t.Fatalf("A %+v", res[0])
	}
	if st, _ := ethernetip.StatusOf(res[1].Err); st != cip.StatusPathDestinationUnknown {
		t.Fatalf("Missing %v", res[1].Err)
	}
	if !errors.Is(res[2].Err, ethernetip.ErrInvalidOption) {
		t.Fatalf("Bad Name %v", res[2].Err)
	}
	if !errors.Is(res[3].Err, ethernetip.ErrProtocol) {
		t.Fatalf("Short %v", res[3].Err)
	}
	if x, _ := res[6].Value.Int(0); x != int64(len(tags[6])) {
		t.Fatalf("last %+v", res[6])
	}

	// An over-long name does not encode.
	long := "A"
	for len(long) < 700 {
		long += ".Abcdefghij"
	}
	res, err = NewClient(m).ReadMany(ctx, []string{long + "[1]"})
	if err != nil || res[0].Err == nil {
		t.Fatalf("long path: %+v %v", res, err)
	}
	_ = res

	// Nothing valid: nothing sent.
	m.batches = nil
	if _, err := NewClient(m).ReadMany(ctx, []string{"Bad Name"}); err != nil || m.batches != nil {
		t.Fatalf("%v %d", err, len(m.batches))
	}

	// Exchange errors are returned.
	m.mspErr = ethernetip.ErrTimeout
	if _, err := NewClient(m, WithMaxData(64)).ReadMany(ctx, tags); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("msp error: %v", err)
	}
	if _, err := NewClient(m).ReadMany(ctx, tags); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("final flush error: %v", err)
	}

	// A doer without MultipleService.
	if _, err := NewClient(&fakeDoer{t: t}).ReadMany(ctx, []string{"A"}); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Fatalf("no msp: %v", err)
	}
}

func symbolEntry(inst uint32, name string, typ SymbolType, dims ...uint32) []byte {
	b := le32(inst)
	b, _ = cip.AppendString(b, name)
	b = append(b, le16(uint16(typ))...)
	var d [3]uint32
	copy(d[:], dims)
	for _, x := range d {
		b = append(b, le32(x)...)
	}
	return b
}

func TestClientListTags(t *testing.T) {
	d := &fakeDoer{t: t, resps: []cip.Response{
		partial(cat(symbolEntry(1, "A", NewAtomicType(cip.TypeDINT, 0, 0)), symbolEntry(5, "B", NewAtomicType(cip.TypeREAL, 2, 0), 3, 4))...),
		ok(symbolEntry(9, "C", NewStructType(0x123, 0))...),
	}}
	tags, err := NewClient(d).ListTags(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 || tags[1].Name != "B" || tags[1].Dims != [3]uint32{3, 4, 0} || tags[2].Type.Template() != 0x123 || tags[2].Instance != 9 {
		t.Fatalf("%+v", tags)
	}
	for i, inst := range []uint32{0, 6} {
		r := d.reqs[i]
		want := cip.Path{cip.ClassSegment(cip.ClassSymbol), cip.InstanceSegment(inst)}
		if r.Service != cip.ServiceGetInstanceAttributeList || !reflect.DeepEqual(r.Path, want) || !bytes.Equal(r.Data, []byte{3, 0, 1, 0, 2, 0, 8, 0}) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}

	for _, prog := range []string{"Main", "program:Main"} {
		d = &fakeDoer{t: t, resps: []cip.Response{ok(symbolEntry(3, "L", NewAtomicType(cip.TypeSINT, 0, 0))...)}}
		tags, err = NewClient(d).ListTags(ctx, prog)
		wantProg := "Program:Main"
		if prog != "Main" {
			wantProg = prog
		}
		if err != nil || len(tags) != 1 || tags[0].Name != wantProg+".L" {
			t.Fatalf("%s: %+v %v", prog, tags, err)
		}
		if p := d.reqs[0].Path; len(p) != 3 || p[0] != (sym{Name: wantProg}) {
			t.Fatalf("program path %v", p)
		}
	}

	cases := []struct {
		name  string
		resps []cip.Response
		n     int
	}{
		{"status", []cip.Response{{Status: cip.StatusPathDestinationUnknown}}, 0},
		{"truncated", []cip.Response{ok(append(symbolEntry(1, "A", 0xC4), 1, 2)...)}, 1},
		{"empty partial", []cip.Response{partial()}, 0},
		{"no progress", []cip.Response{partial(symbolEntry(4, "A", 0xC4)...), partial(symbolEntry(2, "B", 0xC4)...)}, 2},
		{"wrap", []cip.Response{partial(symbolEntry(0xFFFFFFFF, "A", 0xC4)...)}, 1},
	}
	for _, c := range cases {
		d := &fakeDoer{t: t, resps: c.resps}
		tags, err := NewClient(d).ListTags(ctx, "")
		if err == nil || len(tags) != c.n {
			t.Fatalf("%s: %+v %v", c.name, tags, err)
		}
	}
}

// templateAttrs returns a Get_Attribute_List reply for a template.
func templateAttrs(t *Template) cip.Response {
	def := t.definition()
	b := le16(4)
	b = cat(b, le16(4), le16(0), le32(definitionWords(len(def))))
	b = cat(b, le16(5), le16(0), le32(t.Size))
	b = cat(b, le16(2), le16(0), le16(uint16(len(t.Members))))
	b = cat(b, le16(1), le16(0), le16(t.Handle))
	return ok(b...)
}

func TestClientTemplate(t *testing.T) {
	inner, outer := testTemplates()
	def := outer.definition()
	total := int(definitionWords(len(def)))*4 - 21
	padded := append(append([]byte(nil), def...), make([]byte, total-len(def))...)
	d := &fakeDoer{t: t, resps: []cip.Response{
		templateAttrs(&outer),
		partial(padded[:20]...),
		partial(padded[20:40]...),
		ok(padded[40:]...),
	}}
	c := NewClient(d)
	got, err := c.Template(ctx, outer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Outer" || got.Handle != outer.Handle || got.Size != outer.Size || !reflect.DeepEqual(got.Members, outer.Members) || got.ID != outer.ID {
		t.Fatalf("%+v", got)
	}
	r := d.reqs[0]
	if r.Service != cip.ServiceGetAttributeList || !reflect.DeepEqual(r.Path, cip.ObjectPath(cip.ClassTemplate, uint32(outer.ID))) {
		t.Fatalf("attributes request %+v", r)
	}
	for i, off := range []int{0, 20, 40} {
		r := d.reqs[i+1]
		want := cat(le32(uint32(off)), le16(uint16(total-off)))
		if r.Service != cip.ServiceReadTemplate || !bytes.Equal(r.Data, want) {
			t.Fatalf("read %d: %x, want %x", i, r.Data, want)
		}
	}
	// Cached.
	if again, err := c.Template(ctx, outer.ID); err != nil || again != got || len(d.reqs) != 4 {
		t.Fatalf("cache: %v %d requests", err, len(d.reqs))
	}
	// STRING needs no request.
	if s, err := c.Template(ctx, StringTemplate.ID); err != nil || s.Name != "ASCIISTRING82" || len(d.reqs) != 4 {
		t.Fatalf("STRING %+v %v", s, err)
	}

	// An empty reply ends the definition.
	idef := inner.definition()
	d = &fakeDoer{t: t, resps: []cip.Response{templateAttrs(&inner), partial(idef...), partial()}}
	if got, err := NewClient(d).Template(ctx, inner.ID); err != nil || got.Name != "Inner" {
		t.Fatalf("inner %+v %v", got, err)
	}
}

func TestClientTemplateErrors(t *testing.T) {
	inner, _ := testTemplates()
	good := templateAttrs(&inner)
	attrs := func(n uint16, entries ...[]byte) cip.Response {
		return ok(cat(append([][]byte{le16(n)}, entries...)...)...)
	}
	cases := []struct {
		name  string
		resps []cip.Response
		want  error
	}{
		{"status", []cip.Response{{Status: cip.StatusPathDestinationUnknown}}, nil},
		{"count", []cip.Response{attrs(3)}, ethernetip.ErrProtocol},
		{"short", []cip.Response{ok(4)}, ethernetip.ErrProtocol},
		{"attribute status", []cip.Response{attrs(4, le16(4), le16(0x14))}, ethernetip.ErrProtocol},
		{"truncated", []cip.Response{attrs(4, le16(4), le16(0), le32(10))}, ethernetip.ErrProtocol},
		{"zero words", []cip.Response{attrs(4, le16(4), le16(0), le32(5), le16(5), le16(0), le32(4), le16(2), le16(0), le16(0), le16(1), le16(0), le16(1))}, ethernetip.ErrProtocol},
		{"huge", []cip.Response{attrs(4, le16(4), le16(0), le32(1<<20), le16(5), le16(0), le32(4), le16(2), le16(0), le16(0), le16(1), le16(0), le16(1))}, ethernetip.ErrProtocol},
		{"read status", []cip.Response{good, {Status: cip.StatusInvalidParameter}}, nil},
		{"bad definition", []cip.Response{good, ok(1, 2, 3)}, ethernetip.ErrProtocol},
	}
	for _, c := range cases {
		d := &fakeDoer{t: t, resps: c.resps}
		_, err := NewClient(d).Template(ctx, inner.ID)
		if err == nil {
			t.Fatalf("%s: no error", c.name)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
		var ce *ethernetip.CIPError
		if c.want == nil && !errors.As(err, &ce) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
}

func TestClientDecodeStruct(t *testing.T) {
	inner, outer := testTemplates()
	pad := func(tm *Template) []byte {
		def := tm.definition()
		return append(def, make([]byte, int(definitionWords(len(def)))*4-21-len(def))...)
	}
	d := &fakeDoer{t: t, resps: []cip.Response{
		templateAttrs(&outer), ok(pad(&outer)...),
		templateAttrs(&inner), ok(pad(&inner)...),
	}}
	c := NewClient(d)
	v := Value{Handle: outer.Handle, Count: 1, Data: outerData()}
	f, err := c.DecodeStruct(ctx, outer.ID, v)
	if err != nil {
		t.Fatal(err)
	}
	if f[1].Name != "In" || len(f[1].Struct) != 2 || len(f[5].Struct) != 2 {
		t.Fatalf("%+v", f)
	}
	if a, _ := f[1].Struct[0].Value.Int(0); a != 7 {
		t.Fatalf("In.A %d", a)
	}
	// Handle mismatch, and an atomic value.
	for _, bad := range []Value{{Handle: 1, Count: 1, Data: outerData()}, {Type: cip.TypeDINT, Count: 1, Data: make([]byte, 4)}} {
		if _, err := c.DecodeStruct(ctx, outer.ID, bad); !errors.Is(err, ErrType) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	// The template itself fails.
	d = &fakeDoer{t: t, resps: []cip.Response{{Status: cip.StatusPathDestinationUnknown}}}
	if _, err := NewClient(d).DecodeStruct(ctx, outer.ID, v); err == nil {
		t.Fatal("no template error")
	}
	// A nested template fails: the fields come back with the error.
	d = &fakeDoer{t: t, resps: []cip.Response{
		templateAttrs(&outer), ok(pad(&outer)...),
		{Status: cip.StatusPathDestinationUnknown},
		{Status: cip.StatusPathDestinationUnknown},
	}}
	f, err = NewClient(d).DecodeStruct(ctx, outer.ID, v)
	if st, _ := ethernetip.StatusOf(err); st != cip.StatusPathDestinationUnknown || len(f) != 6 || f[1].Struct != nil {
		t.Fatalf("nested lookup: %+v %v", f, err)
	}
}

func TestClientProgramName(t *testing.T) {
	b, _ := cip.AppendString(nil, "Plant")
	d := &fakeDoer{t: t, resps: []cip.Response{ok(b...), ok(5, 0, 'a'), {Status: cip.StatusServiceNotSupported}}}
	c := NewClient(d)
	if n, err := c.ProgramName(ctx); err != nil || n != "Plant" {
		t.Fatalf("%q %v", n, err)
	}
	if r := d.reqs[0]; r.Service != cip.ServiceGetAttributesAll || !reflect.DeepEqual(r.Path, cip.ObjectPath(cip.ClassProgramName, 1)) {
		t.Fatalf("%+v", r)
	}
	if _, err := c.ProgramName(ctx); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := c.ProgramName(ctx); err == nil {
		t.Fatal("status")
	}
}
