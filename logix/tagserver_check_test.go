// SPDX-License-Identifier: MIT

package logix

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

// TestTagServerCheckRead: a read CheckRead refuses is answered with its
// status, by name and by instance, for the whole tag and a part of it; the
// rest are served.
func TestTagServerCheckRead(t *testing.T) {
	h := newHarness(t)
	var asked []string
	h.ts.CheckRead(func(name string) cip.GeneralStatus {
		asked = append(asked, name)
		if name == "Count" || name == "Program:Main.Local" {
			return cip.StatusDeviceStateConflict
		}
		return cip.StatusSuccess
	})
	wantStatus(t, "refused", h.read("Count", 1), cip.StatusDeviceStateConflict)
	wantStatus(t, "program", h.read("Program:Main.Local", 1), cip.StatusDeviceStateConflict)
	inst := h.ts.tags["count"].inst
	wantStatus(t, "by instance", h.do(cip.Request{Service: cip.ServiceReadTag, Path: cip.ObjectPath(cip.ClassSymbol, inst), Data: le16(1)}, true), cip.StatusDeviceStateConflict)
	frag := h.do(cip.Request{Service: cip.ServiceReadTagFragmented, Path: h.path("Count"), Data: cat(le16(1), make([]byte, 4))}, true)
	wantStatus(t, "fragmented", frag, cip.StatusDeviceStateConflict)
	if r := h.read("Big[3]", 1); !r.OK() {
		t.Fatalf("served %+v", r)
	}
	want := []string{"Count", "Program:Main.Local", "Count", "Count", "Big"}
	if len(asked) != len(want) {
		t.Fatalf("asked %v, want %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Fatalf("asked %v, want %v", asked, want)
		}
	}
	// A tag that does not exist is not asked about.
	wantStatus(t, "unknown", h.read("Nope", 1), cip.StatusPathDestinationUnknown)
	if len(asked) != len(want) {
		t.Fatalf("asked about an unknown tag: %v", asked)
	}
	h.ts.CheckRead(nil)
	if r := h.read("Count", 1); !r.OK() {
		t.Fatalf("without a check %+v", r)
	}
}

// TestTagServerCheckWrite: CheckWrite sees the whole tag as the write
// would leave it; a refusal is its status and the tag (and OnWrite) is
// untouched, an acceptance stores the write.
func TestTagServerCheckWrite(t *testing.T) {
	h := newHarness(t)
	var written []string
	h.ts.OnWrite(func(name string) { written = append(written, name) })
	refuse := cip.StatusPrivilegeViolation
	var seen []Value
	var names []string
	h.ts.CheckWrite(func(_ context.Context, name string, v Value) cip.GeneralStatus {
		names = append(names, name)
		seen = append(seen, v)
		// While it is asked, the tag still reads its old value.
		if g, _ := h.ts.Get(name); bytes.Equal(g.Data, v.Data) && name == "Count" {
			t.Errorf("the tag holds the value before it is taken")
		}
		return refuse
	})
	old, _ := Ints(cip.TypeDINT, 5)
	must(t, h.ts.Set("Count", old))
	v, _ := Ints(cip.TypeDINT, 77)
	wantStatus(t, "refused", h.write("Count", v), cip.StatusPrivilegeViolation)
	if g, _ := h.ts.Get("Count"); !bytes.Equal(g.Data, old.Data) {
		t.Fatalf("Count %x after a refused write", g.Data)
	}
	if len(written) != 0 {
		t.Fatalf("OnWrite %v after a refused write", written)
	}
	if len(seen) != 1 || names[0] != "Count" || !bytes.Equal(seen[0].Data, v.Data) || seen[0].Type != cip.TypeDINT {
		t.Fatalf("asked %v %+v", names, seen)
	}

	refuse = cip.StatusSuccess
	if r := h.write("Count", v); !r.OK() {
		t.Fatalf("taken %+v", r)
	}
	if g, _ := h.ts.Get("Count"); !bytes.Equal(g.Data, v.Data) {
		t.Fatalf("Count %x after a taken write", g.Data)
	}
	if len(written) != 1 || written[0] != "Count" {
		t.Fatalf("OnWrite %v", written)
	}

	// An element: the whole array as it would be.
	e, _ := Ints(cip.TypeINT, 9)
	if r := h.write("Big[2]", e); !r.OK() {
		t.Fatalf("element %+v", r)
	}
	last := seen[len(seen)-1]
	if names[len(names)-1] != "Big" || last.Count != 1000 || binary.LittleEndian.Uint16(last.Data[4:]) != 9 {
		t.Fatalf("element: asked %s %d elements", names[len(names)-1], last.Count)
	}
	// A program's tag by its full name, a BOOL, by instance, and Read-Modify-Write.
	l, _ := Ints(cip.TypeSINT, -1)
	if r := h.write("program:main.LOCAL", l); !r.OK() || names[len(names)-1] != "Program:Main.Local" {
		t.Fatalf("program %+v %v", r, names)
	}
	inst := h.ts.tags["count"].inst
	d, _ := Ints(cip.TypeDINT, 3)
	data := cat(d.appendType(nil), le16(1), d.Data)
	if r := h.do(cip.Request{Service: cip.ServiceWriteTag, Path: cip.ObjectPath(cip.ClassSymbol, inst), Data: data}, true); !r.OK() {
		t.Fatalf("by instance %+v", r)
	}
	if !bytes.Equal(seen[len(seen)-1].Data, d.Data) {
		t.Fatalf("by instance asked %x", seen[len(seen)-1].Data)
	}
	refuse = cip.StatusDeviceStateConflict
	rmw := h.do(cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: h.path("Count"), Data: cat(le16(4), []byte{0xF0, 0, 0, 0}, []byte{0xFF, 0xFF, 0xFF, 0xFF})}, false)
	wantStatus(t, "read-modify-write", rmw, cip.StatusDeviceStateConflict)
	if g, _ := h.ts.Get("Count"); !bytes.Equal(g.Data, d.Data) || binary.LittleEndian.Uint32(seen[len(seen)-1].Data) != 0xF3 {
		t.Fatalf("Count %x, asked %x", g.Data, seen[len(seen)-1].Data)
	}

	// A write the database refuses is not asked about.
	n := len(seen)
	r, _ := Floats(cip.TypeREAL, 1)
	wantTypeMismatch(t, "type", h.write("Count", r))
	if len(seen) != n {
		t.Fatal("asked about a write of the wrong type")
	}
}

// TestTagServerCheckWriteKeepsWhatChangedMeanwhile: what another write or
// Set changes while CheckWrite runs stays; the octets of the write are
// stored over it.
func TestTagServerCheckWriteKeepsWhatChangedMeanwhile(t *testing.T) {
	h := newHarness(t)
	h.ts.CheckWrite(func(_ context.Context, name string, _ Value) cip.GeneralStatus {
		// Meanwhile the application sets the whole array: element 2 changes too.
		all := make([]int64, 1000)
		all[2], all[7] = 4, 8
		v, _ := Ints(cip.TypeINT, all...)
		if err := h.ts.Set(name, v); err != nil {
			t.Error(err)
		}
		return cip.StatusSuccess
	})
	e, _ := Ints(cip.TypeINT, 9)
	if r := h.write("Big[2]", e); !r.OK() {
		t.Fatalf("%+v", r)
	}
	g, _ := h.ts.Get("Big")
	if x, _ := g.Int(2); x != 9 {
		t.Fatalf("element 2 is %d, want the write's 9", x)
	}
	if x, _ := g.Int(7); x != 8 {
		t.Fatalf("element 7 is %d, want the Set's 8", x)
	}
}

// TestTagServerCheckWriteConcurrent: reads go on while a write waits on
// CheckWrite (the database is not locked).
func TestTagServerCheckWriteConcurrent(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	asked := make(chan struct{})
	h.ts.CheckWrite(func(context.Context, string, Value) cip.GeneralStatus {
		close(asked)
		<-release
		return cip.StatusSuccess
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		v, _ := Ints(cip.TypeDINT, 1)
		if r := h.write("Count", v); !r.OK() {
			t.Errorf("%+v", r)
		}
	}()
	<-asked
	if r := h.read("Count", 1); !r.OK() {
		t.Fatalf("read while a write is checked %+v", r)
	}
	close(release)
	wg.Wait()
	if g, _ := h.ts.Get("Count"); binary.LittleEndian.Uint32(g.Data) != 1 {
		t.Fatalf("Count %x", g.Data)
	}
}
