// SPDX-License-Identifier: MIT

package logix

import (
	"context"
	"errors"
	"runtime"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
)

// The tests of this file play a hostile controller against the Logix
// client: fragmented reads that never end, fragments that change type,
// templates whose members make decoding allocate without bound.

// errHostileStop ends a hostile doer that the client did not stop.
var errHostileStop = errors.New("hostile doer: the client kept asking")

// hostileDoer answers every request with answer(n), n counting from 0,
// and gives up with errHostileStop after limit requests.
type hostileDoer struct {
	n      int
	limit  int
	answer func(n int, req cip.Request) cip.Response
}

func (h *hostileDoer) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	if h.n >= h.limit {
		return cip.Response{}, errHostileStop
	}
	resp := h.answer(h.n, req)
	h.n++
	return resp, client.ResponseError(req, resp)
}

// TestHostileReadTinyFragments answers a read of one DINT with partial
// transfers of one octet, forever: the client stops once it has the
// octets the type and count need.
func TestHostileReadTinyFragments(t *testing.T) {
	h := &hostileDoer{limit: 1000, answer: func(int, cip.Request) cip.Response {
		return partial(0xC4, 0, 0x55)
	}}
	_, err := NewClient(h).Read(ctx, "A", 1)
	if errors.Is(err, errHostileStop) || h.n > 10 {
		t.Fatalf("%d requests for one DINT: %v", h.n, err)
	}
	if !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("endless fragments: %v", err)
	}
}

// TestHostileReadStructTinyFragments does the same for a structure, whose
// size the client cannot know from the reply: one octet per round trip
// must not keep the client asking for 16 MiB (16 million requests).
func TestHostileReadStructTinyFragments(t *testing.T) {
	h := &hostileDoer{limit: 100000, answer: func(int, cip.Request) cip.Response {
		return partial(0xA0, 0x02, 0x34, 0x12, 0x55)
	}}
	_, err := NewClient(h).Read(ctx, "S", 1)
	if errors.Is(err, errHostileStop) {
		t.Fatalf("structure read still asking after %d one-octet fragments", h.n)
	}
	if !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("endless structure fragments: %v", err)
	}
}

// TestHostileReadFragmentTypeChange changes the type between fragments:
// the data would mix two types.
func TestHostileReadFragmentTypeChange(t *testing.T) {
	for _, second := range [][]byte{
		{0xC3, 0, 1, 2},             // INT after DINT
		{0xA0, 0x02, 0x34, 0x12, 1}, // a structure after DINT
		{0xFF},                      // half a type code
		{},                          // no type at all
	} {
		h := &hostileDoer{limit: 10, answer: func(n int, _ cip.Request) cip.Response {
			if n == 0 {
				return partial(0xC4, 0, 1, 2, 3, 4)
			}
			return cip.Response{Data: second}
		}}
		_, err := NewClient(h).Read(ctx, "A", 2)
		if !errors.Is(err, ethernetip.ErrProtocol) {
			t.Fatalf("fragment % X after DINT: %v", second, err)
		}
	}
}

// TestHostileReadServiceMismatch answers with garbage statuses and data
// on every service the client uses.
func TestHostileReadServiceMismatch(t *testing.T) {
	answers := []cip.Response{
		{Status: cip.StatusPartialTransfer}, // partial without data
		{Status: cip.StatusPartialTransfer, Data: []byte{0xC4}},
		{Data: []byte{0xC4, 0}},                   // no data for one element
		{Data: []byte{0xC4, 0, 1, 2, 3, 4, 5, 6}}, // too much for one element
		{Status: cip.StatusGeneralError, Extended: []uint16{0xFFFF, 0xFFFF}},
	}
	for _, a := range answers {
		h := &hostileDoer{limit: 10, answer: func(int, cip.Request) cip.Response { return a }}
		if _, err := NewClient(h).Read(ctx, "A", 1); err == nil || errors.Is(err, errHostileStop) {
			t.Fatalf("reply %+v: %v after %d requests", a, err, h.n)
		}
	}
}

// TestHostileTemplateDecodeAllocation decodes a structure whose template
// (as a controller returns it, up to 65535 members) has every member at
// offset 0 and of a structure type without a template: each field copies
// the rest of the data, so 65535 fields of a 2 KiB value allocate 128 MiB.
// What one Decode allocates must be bounded by its input, not by members
// times data.
func TestHostileTemplateDecodeAllocation(t *testing.T) {
	const members = 0xFFFF
	data := make([]byte, 2048)
	tmpl := Template{ID: 1, Name: "Evil", Size: uint32(len(data))}
	for range members {
		tmpl.Members = append(tmpl.Members, Member{Name: "M", Type: NewStructType(0x0999, 0), Offset: 0})
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f, err := tmpl.Decode(data, nil)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("%d fields, %v, %d MiB allocated", len(f), err, alloc>>20)
	if alloc > 64<<20 {
		t.Fatalf("decoding %d octets with %d members allocated %d MiB", len(data), members, alloc>>20)
	}
}

// TestHostileTemplateAttributes answers the template attributes with
// sizes a controller would never report: the client refuses them before
// reading the definition.
func TestHostileTemplateAttributes(t *testing.T) {
	attrs := func(words uint32, members uint16) []byte {
		return cat(le16(4),
			le16(4), le16(0), le32(words),
			le16(5), le16(0), le32(8),
			le16(2), le16(0), le16(members),
			le16(1), le16(0), le16(0x1234))
	}
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"definition of 0xFFFFFFFF words", attrs(0xFFFFFFFF, 1)},
		{"definition of 2^28 words", attrs(1<<28, 1)},
		{"definition of 0 words", attrs(0, 1)},
		{"definition of 5 words (negative length)", attrs(5, 1)},
		{"65535 members in 10 words", attrs(10, 0xFFFF)},
		{"truncated", attrs(10, 1)[:9]},
		{"count 0xFFFF", append(le16(0xFFFF), attrs(10, 1)[2:]...)},
	} {
		h := &hostileDoer{limit: 1000, answer: func(n int, req cip.Request) cip.Response {
			if req.Service == cip.ServiceGetAttributeList {
				return ok(c.data...)
			}
			// Read_Template: whatever was asked, one octet more to come.
			return partial(0)
		}}
		_, err := NewClient(h).Template(ctx, 0x20)
		if err == nil || errors.Is(err, errHostileStop) {
			t.Fatalf("%s: %v after %d requests", c.name, err, h.n)
		}
	}
}

// TestHostileListTagsStuck answers the tag list with partial transfers
// that repeat the same instance: the client stops.
func TestHostileListTagsStuck(t *testing.T) {
	entry := cat(le32(7), le16(1), []byte("A"), le16(0x00C4), le32(0), le32(0), le32(0))
	h := &hostileDoer{limit: 1000, answer: func(int, cip.Request) cip.Response { return partial(entry...) }}
	_, err := NewClient(h).ListTags(ctx, "")
	if !errors.Is(err, ethernetip.ErrProtocol) || h.n > 3 {
		t.Fatalf("stuck tag list: %v after %d requests", err, h.n)
	}
	// A truncated entry in a partial transfer.
	h = &hostileDoer{limit: 1000, answer: func(int, cip.Request) cip.Response { return partial(entry[:9]...) }}
	if _, err := NewClient(h).ListTags(ctx, ""); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("truncated tag list: %v", err)
	}
}
