// SPDX-License-Identifier: MIT

package logix

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/server"
)

func TestFieldConversions(t *testing.T) {
	if n, err := elementCount(0xFFFF); err != nil || n != 0xFFFF {
		t.Fatalf("elementCount(65535) = %d %v", n, err)
	}
	for _, n := range []int{0, -1, 0x10000} {
		if _, err := elementCount(n); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("elementCount(%d) = %v", n, err)
		}
	}
	if o, err := fragmentOffset(maxReadData); err != nil || o != maxReadData {
		t.Fatalf("fragmentOffset(max) = %d %v", o, err)
	}
	if _, err := fragmentOffset(maxReadData + 1); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Errorf("fragmentOffset(max+1) = %v", err)
	}
	if _, err := fragmentOffset(-1); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("fragmentOffset(-1) = %v", err)
	}
	if offsetOf(7) != 7 {
		t.Error("offsetOf")
	}
	if strconv.IntSize < 64 {
		return
	}
	top := int64(math.MaxUint32)
	if int64(offsetOf(math.MaxUint32)) != top {
		t.Error("offsetOf(max)")
	}
}

func TestDefinitionSizeClamps(t *testing.T) {
	for n, want := range map[int]uint32{-1: 0, 0: 6, 1: 6, 2: 7} {
		if got := definitionWords(n); got != want {
			t.Errorf("definitionWords(%d) = %d, want %d", n, got, want)
		}
	}
	if definitionLen(1<<28) != 1<<30-23 || definitionLen(1<<28+1) != 1<<30 || definitionLen(math.MaxUint32) != 1<<30 {
		t.Error("definitionLen clamp")
	}
	if readLen(30) != 100 || readLen(1<<28) != 1<<30-20 || readLen(1<<28+1) != 1<<30 {
		t.Error("readLen")
	}
	if strconv.IntSize < 64 {
		return
	}
	top := 4*int64(math.MaxUint32) - 26
	if got := definitionWords(int(top)); got != math.MaxUint32 {
		t.Errorf("definitionWords(largest) = %d", got)
	}
	if got := definitionWords(int(top + 4)); got != math.MaxUint32 {
		t.Errorf("definitionWords(beyond) = %d", got)
	}
}

func TestTwosComplement(t *testing.T) {
	for _, x := range []int64{0, 1, -1, math.MaxInt64, math.MinInt64, -42} {
		if got := signed64(unsigned64(x)); got != x {
			t.Errorf("round trip %d = %d", x, got)
		}
	}
	if unsigned64(-1) != math.MaxUint64 || signed64(1<<63) != math.MinInt64 {
		t.Error("two's complement bits")
	}
	cases := []struct {
		t    cip.DataType
		data []byte
		want int64
	}{
		{cip.TypeSINT, []byte{0x80}, math.MinInt8},
		{cip.TypeSINT, []byte{0x7F}, math.MaxInt8},
		{cip.TypeINT, []byte{0x00, 0x80}, math.MinInt16},
		{cip.TypeINT, []byte{0xFF, 0x7F}, math.MaxInt16},
		{cip.TypeDINT, []byte{0, 0, 0, 0x80}, math.MinInt32},
		{cip.TypeDINT, []byte{0xFF, 0xFF, 0xFF, 0x7F}, math.MaxInt32},
		{cip.TypeLINT, []byte{0, 0, 0, 0, 0, 0, 0, 0x80}, math.MinInt64},
		{cip.TypeLINT, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, -1},
	}
	for _, c := range cases {
		v := Value{Type: c.t, Count: 1, Data: c.data}
		if got, err := v.Int(0); err != nil || got != c.want {
			t.Errorf("%s %x = %d %v, want %d", c.t, c.data, got, err, c.want)
		}
		back, err := Ints(c.t, c.want)
		if err != nil || string(back.Data) != string(c.data) {
			t.Errorf("Ints(%s, %d) = %x %v", c.t, c.want, back.Data, err)
		}
	}
}

func TestTextLengthField(t *testing.T) {
	v, err := Strings(strings.Repeat("x", StringCapacity))
	if err != nil {
		t.Fatal(err)
	}
	if s, err := v.Text(0); err != nil || len(s) != StringCapacity {
		t.Fatalf("82 characters: %d %v", len(s), err)
	}
	// A length of 83, and one with the top bit set (once negative), fail.
	for _, n := range [][]byte{{83, 0, 0, 0}, {0xFF, 0xFF, 0xFF, 0xFF}} {
		copy(v.Data, n)
		if _, err := v.Text(0); !errors.Is(err, ErrType) {
			t.Errorf("length %x: %v", n, err)
		}
	}
	if _, err := Strings(strings.Repeat("x", StringCapacity+1)); !errors.Is(err, ErrType) {
		t.Errorf("83 characters: %v", err)
	}
}

func TestReadHostileReplies(t *testing.T) {
	// A type code above one octet is not an atomic type.
	d := &fakeDoer{t: t, resps: []cip.Response{ok(0xC4, 0x01, 1, 0, 0, 0)}}
	if _, err := NewClient(d).Read(ctx, "X", 1); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("type 0x01C4: %v", err)
	}
	// A fragment of another type.
	d = &fakeDoer{t: t, resps: []cip.Response{partial(0xC3, 0, 1, 0), ok(0xC4, 0, 2, 0)}}
	if _, err := NewClient(d).Read(ctx, "X", 2); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("fragment of another type: %v", err)
	}
	// A controller that keeps sending partial transfers beyond the
	// requested elements is stopped at once.
	d = &fakeDoer{t: t, resps: []cip.Response{partial(0xC3, 0, 1, 0, 2, 0, 3, 0), partial(0xC3, 0, 4, 0)}}
	if _, err := NewClient(d).Read(ctx, "X", 1); !errors.Is(err, ethernetip.ErrProtocol) || len(d.reqs) != 1 {
		t.Fatalf("beyond the elements: %v after %d requests", err, len(d.reqs))
	}
	// Exactly the requested elements in fragments is fine.
	d = &fakeDoer{t: t, resps: []cip.Response{partial(0xC3, 0, 1, 0), ok(0xC3, 0, 2, 0)}}
	if v, err := NewClient(d).Read(ctx, "X", 2); err != nil || len(v.Data) != 4 {
		t.Fatalf("two fragments: %+v %v", v, err)
	}
}

// endlessDoer answers every request with a partial transfer of a
// structure: size octets each time.
type endlessDoer struct {
	size  int
	calls int
}

func (e *endlessDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	e.calls++
	resp := partial(append([]byte{0xA0, 0x02, 0x34, 0x12}, make([]byte, e.size)...)...)
	return resp, client.ResponseError(req, resp)
}

func TestReadEndlessStructure(t *testing.T) {
	d := &endlessDoer{size: 1 << 16}
	_, err := NewClient(d).Read(ctx, "S", 1)
	if !errors.Is(err, ethernetip.ErrProtocol) || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("endless partial transfers: %v", err)
	}
	if want := maxReadData/d.size + 2; d.calls > want {
		t.Fatalf("%d requests, want at most %d", d.calls, want)
	}
}

func TestTemplateAttributesHostile(t *testing.T) {
	entry16 := func(id, v uint16) []byte { return cat(le16(id), le16(0), le16(v)) }
	entry32 := func(id uint16, v uint32) []byte { return cat(le16(id), le16(0), le32(v)) }
	good := [][]byte{entry32(4, 10), entry32(5, 4), entry16(2, 1), entry16(1, 0x1111)}
	a, err := decodeTemplateAttributes(cat(append([][]byte{le16(4)}, good...)...))
	if err != nil || a.handle != 0x1111 || a.members != 1 || a.words != 10 || a.size != 4 {
		t.Fatalf("%+v %v", a, err)
	}
	for name, entries := range map[string][][]byte{
		"unrequested": {entry32(4, 10), entry32(5, 4), entry16(2, 1), entry16(3, 0)},
		"twice":       {entry32(4, 10), entry32(4, 10), entry16(2, 1), entry16(1, 0x1111)},
	} {
		if _, err := decodeTemplateAttributes(cat(append([][]byte{le16(4)}, entries...)...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The largest definition is read; one octet more is refused before
	// any Read_Template.
	attrs := func(words uint32) cip.Response {
		return ok(cat(le16(4), entry32(4, words), entry32(5, 4), entry16(2, 1), entry16(1, 0x1111))...)
	}
	words := uint32(maxDefinition+23) / 4
	d := &fakeDoer{t: t, resps: []cip.Response{attrs(words), {Status: cip.StatusInvalidParameter}}}
	_, err = NewClient(d).Template(ctx, 0x30)
	var ce *ethernetip.CIPError
	if !errors.As(err, &ce) || len(d.reqs) != 2 || d.reqs[1].Service != cip.ServiceReadTemplate {
		t.Fatalf("largest definition: %v after %d requests", err, len(d.reqs))
	}
	d = &fakeDoer{t: t, resps: []cip.Response{attrs(words + 1)}}
	if _, err := NewClient(d).Template(ctx, 0x30); !errors.Is(err, ethernetip.ErrProtocol) || len(d.reqs) != 1 {
		t.Fatalf("definition above the limit: %v after %d requests", err, len(d.reqs))
	}
}

func TestAddTemplateMemberLimit(t *testing.T) {
	ms := make([]Member, 0x10000)
	for i := range ms {
		ms[i] = Member{Name: "M", Type: NewAtomicType(cip.TypeSINT, 0, 0)}
	}
	ts := NewTagServer()
	if err := ts.AddTemplate(Template{ID: 1, Name: "Many", Handle: 1, Size: 1, Members: ms}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("65536 members: %v", err)
	}
	tm := Template{ID: 2, Name: "Most", Handle: 2, Size: 1, Members: ms[:0xFFFF]}
	if err := ts.AddTemplate(tm); err != nil {
		t.Fatalf("65535 members: %v", err)
	}
	if tm.memberCount() != 0xFFFF || (&Template{Members: ms}).memberCount() != 0xFFFF {
		t.Error("memberCount")
	}
	// A member beyond the size fails without overflow.
	big := Template{ID: 3, Name: "Big", Handle: 3, Size: 4, Members: []Member{{Name: "A", Type: NewAtomicType(cip.TypeDINT, 1, 0), Info: 0xFFFF, Offset: math.MaxUint32}}}
	if err := ts.AddTemplate(big); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("member beyond the size: %v", err)
	}
}

func TestTagServerHostileRequests(t *testing.T) {
	h := newHarness(t)
	// A type code above one octet whose low octet is the tag's type.
	r := h.do(cip.Request{Service: cip.ServiceWriteTag, Path: h.path("Count"), Data: cat(le16(0x01C4), le16(1), le32(5))}, false)
	wantStatus(t, "type 0x01C4", r, errType.Status, ExtTypeMismatch)
	r = h.do(cip.Request{Service: cip.ServiceWriteTag, Path: h.path("Count"), Data: cat(le16(0x00C4), le16(1), le32(5))}, false)
	if !r.OK() {
		t.Fatalf("type 0x00C4: %+v", r)
	}
	// A fragmented write whose offset is near the top of 32 bits.
	r = h.do(cip.Request{Service: cip.ServiceWriteTagFragmented, Path: h.path("Big"), Data: cat(le16(0x00C3), le16(1000), le32(math.MaxUint32), le16(1))}, false)
	wantStatus(t, "offset 0xFFFFFFFF", r, cip.StatusTooMuchData)
	// A Symbol class above 16 bits whose low 16 bits are 0x6B.
	p := cip.Path{cip.LogicalSegment{Type: cip.LogicalClass, Value: 0x1006B}}
	r = h.ts.listTags(&server.Request{Request: cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: p, Data: []byte{1, 0, 1, 0}}})
	wantStatus(t, "class 0x1006B", r, cip.StatusPathSegmentError)
}

// countedDoer answers a structure read with one-octet partial transfers
// and makes reply number last (from 1) the final one.
type countedDoer struct{ n, last int }

func (c *countedDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	c.n++
	resp := partial(0xA0, 0x02, 0x34, 0x12, 0x55)
	if c.n == c.last {
		resp.Status = cip.StatusSuccess
	}
	return resp, client.ResponseError(req, resp)
}

func TestReadFragmentLimit(t *testing.T) {
	d := &countedDoer{last: maxReadFragments}
	if v, err := NewClient(d).Read(ctx, "S", 1); err != nil || len(v.Data) != maxReadFragments {
		t.Fatalf("%d replies: %d octets, %v", maxReadFragments, len(v.Data), err)
	}
	d = &countedDoer{last: maxReadFragments + 1}
	if _, err := NewClient(d).Read(ctx, "S", 1); !errors.Is(err, ethernetip.ErrProtocol) || d.n != maxReadFragments {
		t.Fatalf("%d replies: %v after %d", maxReadFragments+1, err, d.n)
	}
}

// A write is bounded like a read: more than maxReadData octets is refused
// before anything is sent; the largest is sent in fragments.
func TestWriteSizeBound(t *testing.T) {
	ctx := context.Background()
	d := &fakeDoer{t: t}
	big := Value{Type: cip.TypeSINT, Count: 0xFFFF, Data: make([]byte, maxReadData+1)}
	if err := NewClient(d).Write(ctx, "X", big); !errors.Is(err, ethernetip.ErrInvalidOption) || len(d.reqs) != 0 {
		t.Fatalf("write of %d octets: %v, %d requests", len(big.Data), err, len(d.reqs))
	}
}

// Count 0 and 65536 are refused before anything is sent.
func TestReadCountBound(t *testing.T) {
	d := &fakeDoer{t: t}
	for _, n := range []int{0, 0x10000} {
		if _, err := NewClient(d).Read(context.Background(), "X", n); !errors.Is(err, ethernetip.ErrInvalidOption) || len(d.reqs) != 0 {
			t.Errorf("Read count %d: %v, %d requests", n, err, len(d.reqs))
		}
	}
}

// A Read_Template reply that carries no data ends the read, even as a
// partial transfer: the short definition is a protocol error, not a loop.
func TestTemplateEmptyFragment(t *testing.T) {
	entry16 := func(id, v uint16) []byte { return cat(le16(id), le16(0), le16(v)) }
	entry32 := func(id uint16, v uint32) []byte { return cat(le16(id), le16(0), le32(v)) }
	attrs := ok(cat(le16(4), entry32(4, 10), entry32(5, 4), entry16(2, 1), entry16(1, 0x1111))...)
	for name, empty := range map[string]cip.Response{
		"success": ok(),
		"partial": {Status: cip.StatusPartialTransfer},
	} {
		d := &fakeDoer{t: t, resps: []cip.Response{attrs, empty}}
		if _, err := NewClient(d).Template(context.Background(), 0x30); !errors.Is(err, ethernetip.ErrProtocol) || len(d.reqs) != 2 {
			t.Errorf("%s: %v after %d requests", name, err, len(d.reqs))
		}
	}
}

// tagListDoer answers the tag list with partial transfers of one entry
// whose instance advances, each with a name of nameLen octets, and makes
// reply number last (from 1) the final one.
type tagListDoer struct{ n, last, nameLen int }

func (d *tagListDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	d.n++
	name := strings.Repeat("A", d.nameLen)
	resp := partial(cat(le32(uint32(d.n)), le16(uint16(len(name))), []byte(name), le16(0x00C4), le32(0), le32(0), le32(0))...)
	if d.n == d.last {
		resp.Status = cip.StatusSuccess
	}
	return resp, client.ResponseError(req, resp)
}

// The tag list is bounded like a fragmented read: at most
// maxReadFragments replies and maxReadData octets of them.
func TestListTagsReplyLimit(t *testing.T) {
	d := &tagListDoer{last: maxReadFragments, nameLen: 1}
	if tags, err := NewClient(d).ListTags(ctx, ""); err != nil || len(tags) != maxReadFragments {
		t.Fatalf("%d replies: %d tags, %v", maxReadFragments, len(tags), err)
	}
	d = &tagListDoer{last: maxReadFragments + 1, nameLen: 1}
	if _, err := NewClient(d).ListTags(ctx, ""); !errors.Is(err, ethernetip.ErrProtocol) || d.n != maxReadFragments {
		t.Fatalf("%d replies: %v after %d", maxReadFragments+1, err, d.n)
	}
	// Replies of almost 64 KiB each: 16 MiB is reached after 257.
	d = &tagListDoer{last: -1, nameLen: 0xFFFF}
	_, err := NewClient(d).ListTags(ctx, "")
	if !errors.Is(err, ethernetip.ErrProtocol) || d.n > maxReadData/0xFFFF+1 {
		t.Fatalf("large replies: %v after %d", err, d.n)
	}
}

// Read_Template is bounded like a fragmented read: a target that answers
// one octet at a time stops the client after maxReadFragments replies.
func TestTemplateReplyLimit(t *testing.T) {
	words := uint32((maxDefinition + 20) / 4)
	h := &hostileDoer{limit: 4 * maxReadFragments, answer: func(_ int, req cip.Request) cip.Response {
		if req.Service == cip.ServiceGetAttributeList {
			return ok(cat(le16(4),
				le16(4), le16(0), le32(words),
				le16(5), le16(0), le32(8),
				le16(2), le16(0), le16(1),
				le16(1), le16(0), le16(0x1234))...)
		}
		return partial(0)
	}}
	_, err := NewClient(h).Template(ctx, 0x20)
	if !errors.Is(err, ethernetip.ErrProtocol) || h.n != 1+maxReadFragments {
		t.Fatalf("one-octet definition: %v after %d requests", err, h.n)
	}
}

// What follows the member names of a definition stays in one piece.
func TestParseDefinitionTrailingNames(t *testing.T) {
	def := cat(le16(0), le16(0x00C4), le32(0), []byte("T;n\x00A\x00"), make([]byte, 1<<16), []byte("B\x00"))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 10 {
		name, ms, err := parseDefinition(def, 1)
		if err != nil || name != "T" || len(ms) != 1 || ms[0].Name != "A" {
			t.Fatalf("parse %q %+v %v", name, ms, err)
		}
	}
	runtime.ReadMemStats(&after)
	// Splitting at every NUL would allocate 1.5 MiB per parse.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<10 {
		t.Fatalf("10 parses of one member allocated %d KiB", alloc>>10)
	}
}

// A structure member whose size is beyond 2 GiB is refused on every
// platform, rather than wrapping an int on 32-bit ones.
func TestTemplateDecodeMemberSize(t *testing.T) {
	sub := &Template{ID: 2, Name: "Sub", Handle: 2, Size: 0x10000}
	tmpl := Template{ID: 1, Name: "T", Size: 4, Members: []Member{{Name: "S", Type: NewStructType(2, 1), Info: 0x8000}}}
	if _, err := tmpl.Decode(make([]byte, 4), func(uint16) *Template { return sub }); !errors.Is(err, ErrType) {
		t.Fatalf("member of 2 GiB: %v", err)
	}
	sub.Size = math.MaxUint32
	tmpl.Members[0].Info = 1
	if _, err := tmpl.Decode(make([]byte, 4), func(uint16) *Template { return sub }); !errors.Is(err, ErrType) {
		t.Fatalf("member of 4 GiB: %v", err)
	}
}

// A BOOL array index is a 32-bit value: indices with the top bit set are
// beyond the array, for a tag and for a template member, with every tag
// service.
func TestTagServerBOOLArrayIndexTopBit(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"Bits", "Outs[1].Flags"} {
		base := h.path(name)
		for _, idx := range []uint32{2, 0x7FFFFFFF, 0x80000000, 0xC0000000, 0xFFFFFFFF} {
			wire, err := append(append(cip.Path{}, base...), cip.LogicalSegment{Type: cip.LogicalMember, Format: cip.Format32, Value: idx}).Encode()
			must(t, err)
			path, err := cip.DecodePath(wire)
			must(t, err)
			for _, req := range []cip.Request{
				{Service: cip.ServiceReadTag, Path: path, Data: le16(1)},
				{Service: cip.ServiceWriteTag, Path: path, Data: cat(le16(0x00D3), le16(1), le32(math.MaxUint32))},
				{Service: cip.ServiceReadModifyWriteTag, Path: path, Data: cat(le16(4), le32(1), le32(math.MaxUint32))},
			} {
				wantBeyond(t, fmt.Sprintf("%s[0x%08X] service 0x%02X", name, idx, uint8(req.Service)), h.do(req, false))
			}
		}
	}
	// The last DWORD of each is still addressed.
	wantStatus(t, "Bits[1]", h.read("Bits[1]", 1), cip.StatusSuccess)
	wantStatus(t, "Outs[1].Flags[1]", h.read("Outs[1].Flags[1]", 1), cip.StatusSuccess)
}

// Read-Modify-Write of an array member of no elements has nothing to
// modify; at the end of the tag it would reach beyond the data.
func TestTagServerReadModifyWriteEmptyArray(t *testing.T) {
	ts := NewTagServer()
	tmpl := Template{ID: 0x30, Name: "E", Handle: 0x3030, Size: 4, Members: []Member{
		{Name: "X", Type: NewAtomicType(cip.TypeDINT, 0, 0)},
		{Name: "None", Type: NewAtomicType(cip.TypeDINT, 1, 0), Offset: 4},
	}}
	must(t, ts.AddTemplate(tmpl))
	must(t, ts.AddStructTag("E", 0x30))
	path, err := ParseTag("E.None")
	must(t, err)
	r := ts.ServeSymbol(ctx, &server.Request{Request: cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: path.Path, Data: cat(le16(4), le32(1), le32(math.MaxUint32))}})
	wantBeyond(t, "RMW of DINT[0]", r)
	path, err = ParseTag("E.X")
	must(t, err)
	r = ts.ServeSymbol(ctx, &server.Request{Request: cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: path.Path, Data: cat(le16(4), le32(1), le32(math.MaxUint32))}})
	wantStatus(t, "RMW of DINT", r, cip.StatusSuccess)
}

// A Template Get_Attribute_List reply is bounded by the reply size: a
// request that repeats an attribute gets up to 4 times its size back.
func TestTemplateAttributeListReplyBound(t *testing.T) {
	h := newHarness(t)
	ids := le16(200)
	for range 200 {
		ids = append(ids, le16(5)...)
	}
	req := cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, 0x20), Data: ids}
	wantStatus(t, "200 attributes", h.do(req, false), cip.StatusReplyDataTooLarge)
	req.Data = cat(le16(4), le16(4), le16(5), le16(2), le16(1))
	wantStatus(t, "4 attributes", h.do(req, false), cip.StatusSuccess)
}

// A tag's size is computed without int overflow: dimensions whose product
// wraps an int, or a template above 16 MiB, are refused.
func TestTagServerTagSizeOverflow(t *testing.T) {
	ts := NewTagServer()
	must(t, ts.AddTemplate(Template{ID: 0x40, Name: "Huge", Handle: 0x4040, Size: math.MaxUint32}))
	must(t, ts.AddTemplate(Template{ID: 0x41, Name: "Small", Handle: 0x4141, Size: 4}))
	for name, err := range map[string]error{
		"huge":       ts.AddStructTag("H", 0x40),
		"huge array": ts.AddStructTag("HA", 0x40, 1<<20, 1<<20, 1<<20),
		"3D struct":  ts.AddStructTag("SA", 0x41, 1<<20, 1<<20, 1<<20),
		"3D DINT":    ts.AddTag("DA", cip.TypeDINT, 1<<20, 1<<20, 1<<20),
		"3D BOOL":    ts.AddTag("BA", cip.TypeBOOL, 1<<20, 1<<20, 1<<20),
	} {
		if !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("%s: %v", name, err)
		}
	}
	must(t, ts.AddTag("MaxBOOL", cip.TypeBOOL, 1<<20, 1<<7))
	must(t, ts.AddStructTag("MaxStruct", 0x41, 1<<20, 4))
}
