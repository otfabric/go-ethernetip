// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/logix"
)

// motorTemplate is a UDT: Speed REAL, Count DINT[4], Running BOOL (bit 0
// of a hidden host SINT), Name STRING.
var motorTemplate = logix.Template{
	ID: 0x123, Name: "Motor", Handle: 0xBEEF, Size: 4 + 16 + 4 + 88,
	Members: []logix.Member{
		{Name: "Speed", Type: logix.NewAtomicType(cip.TypeREAL, 0, 0), Offset: 0},
		{Name: "Count", Type: logix.NewAtomicType(cip.TypeDINT, 1, 0), Info: 4, Offset: 4},
		{Name: "ZZZZZZZZZZMotor0", Type: logix.NewAtomicType(cip.TypeSINT, 0, 0), Offset: 20},
		{Name: "Running", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 0, Offset: 20},
		{Name: "Name", Type: logix.NewStructType(logix.StringTemplate.ID, 0), Offset: 24},
	},
}

func startLogix(t *testing.T) (*adapter, *logix.TagServer) {
	t.Helper()
	a := startAdapter(t)
	ts := logix.NewTagServer(logix.WithProgramName("e2e-project"))
	must(t, ts.AddTemplate(motorTemplate))
	must(t, ts.AddTag("Count", cip.TypeDINT))
	must(t, ts.AddTag("Flags", cip.TypeDINT))
	must(t, ts.AddTag("Big", cip.TypeINT, 1000))
	must(t, ts.AddTag("Grid", cip.TypeREAL, 3, 4))
	must(t, ts.AddTag("Bits", cip.TypeBOOL, 64))
	must(t, ts.AddStructTag("Text", logix.StringTemplate.ID))
	must(t, ts.AddStructTag("Motors", motorTemplate.ID, 2))
	must(t, ts.AddTag("Program:Main.Local", cip.TypeSINT))
	ts.Attach(a.srv)
	return a, ts
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testLogix(t *testing.T, ctx context.Context, lc *logix.Client, ts *logix.TagServer) {
	v, _ := logix.Ints(cip.TypeDINT, -42)
	must(t, lc.Write(ctx, "Count", v))
	got, err := lc.Read(ctx, "count", 1)
	must(t, err)
	if x, _ := got.Int(0); x != -42 {
		t.Fatalf("Count = %d", x)
	}

	big := make([]int64, 1000)
	for i := range big {
		big[i] = int64(i*7 - 3000)
	}
	bv, _ := logix.Ints(cip.TypeINT, big...)
	must(t, lc.Write(ctx, "Big", bv))
	got, err = lc.Read(ctx, "Big", 1000)
	must(t, err)
	for i, x := range big {
		if y, _ := got.Int(i); y != x {
			t.Fatalf("Big[%d] = %d, want %d", i, y, x)
		}
	}
	got, err = lc.Read(ctx, "Big[998]", 2)
	must(t, err)
	if y, _ := got.Int(1); y != big[999] {
		t.Fatalf("Big[999] = %d", y)
	}

	fv, _ := logix.Floats(cip.TypeREAL, 1.5)
	must(t, lc.Write(ctx, "Grid[2,3]", fv))
	got, err = lc.Read(ctx, "Grid", 12)
	must(t, err)
	if f, _ := got.Float(11); f != 1.5 {
		t.Fatalf("Grid[2,3] = %v", f)
	}

	must(t, lc.WriteBit(ctx, "Flags.5", 4, true))
	must(t, lc.WriteBit(ctx, "Flags.0", 4, true))
	must(t, lc.WriteBit(ctx, "Flags.0", 4, false))
	got, _ = lc.Read(ctx, "Flags", 1)
	if x, _ := got.Int(0); x != 32 {
		t.Fatalf("Flags = %d", x)
	}

	sv, _ := logix.Strings("hello logix")
	must(t, lc.Write(ctx, "Text", sv))
	got, err = lc.Read(ctx, "Text", 1)
	must(t, err)
	if s, _ := got.Text(0); s != "hello logix" {
		t.Fatalf("Text = %q", s)
	}

	must(t, lc.Write(ctx, "Motors[1].Speed", fv))
	cv, _ := logix.Ints(cip.TypeDINT, 9)
	must(t, lc.Write(ctx, "Motors[1].Count[3]", cv))
	nv, _ := logix.Strings("pump")
	must(t, lc.Write(ctx, "Motors[1].Name", nv))
	bv1, _ := logix.Ints(cip.TypeBOOL, 1)
	must(t, lc.Write(ctx, "Motors[1].Running", bv1))
	got, err = lc.Read(ctx, "Motors[1]", 1)
	must(t, err)
	fields, err := lc.DecodeStruct(ctx, motorTemplate.ID, got)
	must(t, err)
	byName := map[string]logix.Field{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	if f, _ := byName["Speed"].Value.Float(0); f != 1.5 {
		t.Fatalf("Speed %v", f)
	}
	if c, _ := byName["Count"].Value.Int(3); c != 9 {
		t.Fatalf("Count[3] %v", c)
	}
	if b, _ := byName["Running"].Value.Bool(0); !b {
		t.Fatal("Running false")
	}
	if len(byName["Name"].Struct) != 2 {
		t.Fatalf("Name not decoded: %+v", byName["Name"])
	}
	if s, _ := byName["Name"].Value.Text(0); s != "pump" {
		t.Fatalf("Name %q", s)
	}
	if _, hidden := byName["ZZZZZZZZZZMotor0"]; hidden {
		t.Fatal("hidden member decoded")
	}
	run, err := lc.Read(ctx, "Motors[1].Running", 1)
	must(t, err)
	if b, _ := run.Bool(0); !b {
		t.Fatal("Running read false")
	}

	res, err := lc.ReadMany(ctx, []string{"Count", "Nope", "Flags", "Bad Name"})
	must(t, err)
	if res[1].Err == nil || res[3].Err == nil || res[0].Err != nil || res[2].Err != nil {
		t.Fatalf("ReadMany %+v", res)
	}
	if x, _ := res[2].Value.Int(0); x != 32 {
		t.Fatalf("Flags via ReadMany %d", x)
	}

	tags, err := lc.ListTags(ctx, "")
	must(t, err)
	names := map[string]logix.Tag{}
	for _, tg := range tags {
		names[tg.Name] = tg
	}
	if names["Grid"].Dims != [3]uint32{3, 4} || names["Motors"].Type.Template() != motorTemplate.ID || names["Program:Main"].Name == "" {
		t.Fatalf("tag list %+v", tags)
	}
	ptags, err := lc.ListTags(ctx, "Main")
	must(t, err)
	if len(ptags) != 1 || ptags[0].Name != "Program:Main.Local" {
		t.Fatalf("program tags %+v", ptags)
	}
	v8, _ := logix.Ints(cip.TypeSINT, -5)
	must(t, lc.Write(ctx, "Program:Main.Local", v8))
	if x, _ := ts.Get("Program:Main.Local"); x.Data[0] != 0xFB {
		t.Fatalf("Local %x", x.Data)
	}
	name, err := lc.ProgramName(ctx)
	if err != nil || name != "e2e-project" {
		t.Fatalf("program name %q %v", name, err)
	}

	errs := []struct {
		tag    string
		write  bool
		status cip.GeneralStatus
	}{
		{"Missing", false, cip.StatusPathDestinationUnknown},
		{"Big[1000]", false, cip.StatusGeneralError},
		{"Count[1]", false, cip.StatusPathSegmentError},
		{"Motors[0].Nope", false, cip.StatusPathDestinationUnknown},
		{"Count", true, cip.StatusGeneralError}, // REAL into DINT
	}
	for _, e := range errs {
		var err error
		if e.write {
			err = lc.Write(ctx, e.tag, fv)
		} else {
			_, err = lc.Read(ctx, e.tag, 1)
		}
		if st, ok := ethernetip.StatusOf(err); !ok || st != e.status {
			t.Fatalf("%s: %v, want %s", e.tag, err, e.status)
		}
	}
	if _, err := lc.Read(ctx, "Big", 1001); err == nil {
		t.Fatal("read past the end")
	}
}

func TestLogixUnconnected(t *testing.T) {
	a, ts := startLogix(t)
	route, _ := cip.ParseRoute("1/0")
	c := dial(t, a.addr, client.WithRoute(route))
	ctx := ctxT(t)
	testLogix(t, ctx, logix.NewClient(c), ts)
}

func TestLogixConnected(t *testing.T) {
	a, ts := startLogix(t)
	c := dial(t, a.addr)
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{Large: true})
	must(t, err)
	defer cn.Close(ctx)
	testLogix(t, ctx, logix.NewClient(cn, logix.WithMaxData(3900)), ts)
	// Instance addressing, as pycomm3 uses with firmware 21 and later.
	tags, err := logix.NewClient(cn).ListTags(ctx, "")
	must(t, err)
	var inst uint32
	for _, tg := range tags {
		if tg.Name == "Count" {
			inst = tg.Instance
		}
	}
	resp, err := cn.Do(ctx, cip.Request{Service: cip.ServiceReadTag,
		Path: cip.Path{cip.ClassSegment(cip.ClassSymbol), cip.LogicalSegment{Type: cip.LogicalInstance, Value: inst, Format: cip.Format16}},
		Data: []byte{1, 0}})
	must(t, err)
	if len(resp.Data) != 6 || resp.Data[0] != byte(cip.TypeDINT) {
		t.Fatalf("instance read %x", resp.Data)
	}
	if _, err := cn.Do(ctx, cip.Request{Service: cip.ServiceReadTag, Path: cip.ObjectPath(cip.ClassSymbol, 9999), Data: []byte{1, 0}}); !errors.Is(err, err) || err == nil {
		t.Fatal("unknown instance read")
	}
}
