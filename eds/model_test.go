// SPDX-License-Identifier: MIT

package eds

import (
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func sample(t testing.TB) *File {
	t.Helper()
	return mustParse(t, readTestdata(t, "otfabric_adapter.eds"))
}

func TestDevice(t *testing.T) {
	d, err := sample(t).Device()
	if err != nil {
		t.Fatal(err)
	}
	want := Device{VendorID: 65535, VendorName: "OT Fabric", DeviceType: 12, TypeName: "Communications Adapter",
		ProductCode: 42, Revision: cip.Revision{Major: 3, Minor: 7}, ProductName: "e2e adapter", Catalog: "OTF-EIP-1"}
	if d != want {
		t.Fatalf("%+v\nwant %+v", d, want)
	}
	// Hex numbers are numbers.
	d, err = mustParse(t, "[Device]\nVendCode=0x10;ProdType=2;ProdCode=0X0F;MajRev=1;MinRev=0;").Device()
	if err != nil || d.VendorID != 16 || d.ProductCode != 15 || d.ProductName != "" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestDeviceErrors(t *testing.T) {
	const ok = "VendCode=1;ProdType=2;ProdCode=3;MajRev=1;MinRev=0;"
	for _, tc := range []struct{ src, msg string }{
		{"[File]\n", "no [Device] section"},
		{"[Device]\nVendCode=1;ProdType=2;MajRev=1;MinRev=0;", "eds: [Device] has no ProdCode"},
		{"[Device]\n" + strings.Replace(ok, "VendCode=1", "VendCode=70000", 1), "VendCode: not a 16-bit number: 70000"},
		{"[Device]\n" + strings.Replace(ok, "MajRev=1", "MajRev=256", 1), "MajRev: not a 8-bit number: 256"},
		{"[Device]\n" + strings.Replace(ok, "MinRev=0", `MinRev="0"`, 1), `MinRev: not a number: "0"`},
		{"[Device]\n" + strings.Replace(ok, "ProdType=2", "ProdType=-2", 1), "ProdType: not a 16-bit number: -2"},
	} {
		_, err := mustParse(t, tc.src).Device()
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%q: %v, want %q", tc.src, err, tc.msg)
		}
	}
}

func TestParams(t *testing.T) {
	ps, err := sample(t).Params()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 5 {
		t.Fatalf("%d params", len(ps))
	}
	want := Param{Number: 1, Type: cip.TypeUDINT, Size: 4, Name: "RPI", Units: "us", Help: "Requested packet interval",
		Min: "1000", Max: "3600000000", Default: "10000"}
	if !reflect.DeepEqual(ps[0], want) {
		t.Errorf("Param1 %+v\nwant %+v", ps[0], want)
	}
	wantEnum := []EnumValue{{0, "Stopped"}, {1, "Running"}, {2, "Faulted"}}
	if ps[2].Number != 3 || ps[2].Type != cip.TypeSINT || !reflect.DeepEqual(ps[2].Enum, wantEnum) {
		t.Errorf("Param3 %+v", ps[2])
	}
	if ps[3].Type != cip.TypeREAL || ps[3].Min != "-40" {
		t.Errorf("Param4 %+v", ps[3])
	}
}

func TestParamsDetails(t *testing.T) {
	f := mustParse(t, `[Params]
	Param10 = 0, 6, "20 01 24 01 30 07", 0x0010, 0xC7, 2, "Ten", "", "", 0, 0xFFFF, 0x10;
	Param2 = 0, 4, "zz", , 0xC6, 1, "Bad path", "", "";
	ParamX = 0, ,, 0, 0, 0;
	Param = 1;
	Param-1 = 1;
	Param3 = 0, ,, 0, 0xD0, 0;
	Enum10 = 0, "Zero", 0x10, "Sixteen", -1, "Minus", 9;
	EnumY = 1, "x";
`)
	ps, err := f.Params()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[0].Number != 2 || ps[1].Number != 3 || ps[2].Number != 10 {
		t.Fatalf("params not by number: %+v", ps)
	}
	p := ps[2]
	if p.Path.String() != "@1/1/7" || p.Descriptor != 0x10 || p.Type != cip.TypeUINT || p.Size != 2 || p.Max != "0xFFFF" || p.Default != "0x10" {
		t.Errorf("Param10 %+v", p)
	}
	if want := []EnumValue{{0, "Zero"}, {16, "Sixteen"}, {-1, "Minus"}}; !reflect.DeepEqual(p.Enum, want) {
		t.Errorf("Enum10 %v, the odd last field is dropped", p.Enum)
	}
	// A link path that does not decode is left out.
	if ps[0].Path != nil || ps[0].Descriptor != 0 {
		t.Errorf("Param2 %+v", ps[0])
	}
	// No [Params] section: no parameters.
	if ps, err := mustParse(t, "[File]").Params(); ps != nil || err != nil {
		t.Errorf("no section: %v %v", ps, err)
	}
}

func TestParamsErrors(t *testing.T) {
	for _, tc := range []struct{ entry, msg string }{
		{`Param1 = 0, ,, 0x10000, 0xC6, 1;`, "line 2: Param1 descriptor: not a 16-bit number: 0x10000"},
		{`Param1 = 0, ,, 0, 0x100, 1;`, "Param1 data type: not a 8-bit number: 0x100"},
		{`Param1 = 0, ,, 0, , 1;`, "Param1 data type: not a number"},
		{`Param1 = 0, ,, 0, 0xC6, "1";`, "Param1 data size: not a number"},
		{`Param1 = 0, ,, 0, 0xC6, -1;`, "Param1 data size: not a 16-bit number"},
		{`Enum1 = x, "X";`, "Enum1 value 0: "},
		{`Enum1 = 1, "a", "2", "b";`, "Enum1 value 1: not a number"},
		{`Enum1 = 0x1G, "a";`, "Enum1 value 0"},
	} {
		_, err := mustParse(t, "[Params]\n"+tc.entry).Params()
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v, want %q", tc.entry, err, tc.msg)
		}
	}
}

func TestAssemblies(t *testing.T) {
	as, err := sample(t).Assemblies()
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 5 {
		t.Fatalf("%d assemblies", len(as))
	}
	cfg := as[2]
	wantMembers := []AssemblyMember{{16, "Param2"}, {8, "Param3"}, {8, "Param5"}, {32, "Param4"}, {16, ""}}
	if cfg.Number != 151 || cfg.Name != "Configuration" || cfg.Size != 10 || !reflect.DeepEqual(cfg.Members, wantMembers) {
		t.Errorf("Assem151 %+v", cfg)
	}
	if inst, ok := cfg.Instance(); !ok || inst != 151 {
		t.Errorf("Instance %d %v", inst, ok)
	}
	if as[0].Members[0] != (AssemblyMember{Bits: 256}) {
		t.Errorf("Assem100 %+v", as[0].Members)
	}
	if as[3].Size != 0 || as[3].Members != nil {
		t.Errorf("Assem152 %+v", as[3])
	}

	f := mustParse(t, `[Assembly]
	Assem7 = "No path", , , 0x0003, ,, , Param1, 8;
	Assem8 = "x";`)
	as, err = f.Assemblies()
	if err != nil {
		t.Fatal(err)
	}
	if a := as[0]; a.Path != nil || a.Size != 0 || a.Descriptor != 3 || !reflect.DeepEqual(a.Members, []AssemblyMember{{0, "Param1"}}) {
		t.Errorf("Assem7 %+v", a)
	}
	if _, ok := as[1].Instance(); ok {
		t.Error("an assembly without path has an instance")
	}
	if as, err := mustParse(t, "[File]").Assemblies(); as != nil || err != nil {
		t.Errorf("no section: %v %v", as, err)
	}
}

func TestAssembliesErrors(t *testing.T) {
	for _, tc := range []struct{ entry, msg string }{
		{`Assem1 = "a", "20 04 24", 0;`, "line 2: Assem1 path: "},
		{`Assem1 = "a", "20 4", 0;`, `Assem1 path: eds: EPATH octet "4"`},
		{`Assem1 = "a", "20 04 24 01", 0x10000;`, "Assem1 size: not a 16-bit number"},
		{`Assem1 = "a", "20 04 24 01", 1, x;`, "Assem1 descriptor: not a 16-bit number"},
		{`Assem1 = "a", "20 04 24 01", 1, 0, ,, 0x100000000, Param1;`, "Assem1 member size: not a 32-bit number"},
	} {
		_, err := mustParse(t, "[Assembly]\n"+tc.entry).Assemblies()
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v, want %q", tc.entry, err, tc.msg)
		}
	}
}

func TestConnections(t *testing.T) {
	cs, err := sample(t).Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 {
		t.Fatalf("%d connections", len(cs))
	}
	c := cs[0]
	want := Connection{Number: 1, TriggerTransport: 0x04010002, Params: 0x44640405,
		OTRPI: "Param1", OTSize: "32", OTFormat: "Assem150", TORPI: "Param1", TOSize: "32", TOFormat: "Assem100",
		ConfigSize: "10", ConfigFormat: "Assem151", Name: "Exclusive owner", PathText: "20 04 24 97 2C 96 2C 64"}
	wantPath := cip.Path{cip.ClassSegment(cip.ClassAssembly), cip.InstanceSegment(151), cip.ConnectionPointSegment(150), cip.ConnectionPointSegment(100)}
	if c.Path.String() != wantPath.String() {
		t.Errorf("path %v, want %v", c.Path, wantPath)
	}
	c.Path = nil
	if !reflect.DeepEqual(c, want) {
		t.Errorf("%+v\nwant %+v", c, want)
	}
	if c.Class() != 1 || cs[1].Class() != 1 {
		t.Errorf("classes %d %d", c.Class(), cs[1].Class())
	}
	for mask, class := range map[uint32]int{0x01: 0, 0x02: 1, 0x0C: 2, 0x8000: 15, 0x04010000: -1, 0: -1} {
		if got := (Connection{TriggerTransport: mask}).Class(); got != class {
			t.Errorf("Class of %#x: %d, want %d", mask, got, class)
		}
	}
	// A path with references is kept as text.
	cs, err = mustParse(t, "[Connection Manager]\nConnection1 = 1, 2, , , , , , , , , , , \"n\", \"h\", \"20 04 24 [Param1] 2C 01\";").Connections()
	if err != nil || cs[0].Path != nil || cs[0].PathText != "20 04 24 [Param1] 2C 01" || cs[0].Help != "h" || cs[0].Params != 2 {
		t.Errorf("%+v %v", cs, err)
	}
	if cs, err := mustParse(t, "[File]").Connections(); cs != nil || err != nil {
		t.Errorf("no section: %v %v", cs, err)
	}
}

func TestConnectionsErrors(t *testing.T) {
	for _, tc := range []struct{ entry, msg string }{
		{`Connection1 = 0x100000000, 0;`, "line 2: Connection1 field 1: not a 32-bit number"},
		{`Connection1 = 1, x;`, "Connection1 field 2: not a 32-bit number"},
		{`Connection1 = 1;`, "Connection1 field 2: not a number"},
	} {
		_, err := mustParse(t, "[Connection Manager]\n"+tc.entry).Connections()
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v, want %q", tc.entry, err, tc.msg)
		}
	}
}

func TestEPATH(t *testing.T) {
	for _, s := range []string{"20 04 24 64", "20 04 24 97 2C 96 2C 64", "20 F5 24 01", "21 00 01 25 00 01 30 03", ""} {
		p, err := ParseEPATH(s)
		if err != nil {
			t.Errorf("%q: %v", s, err)
			continue
		}
		got, err := FormatEPATH(p)
		if err != nil || got != s {
			t.Errorf("%q: formats as %q %v", s, got, err)
		}
	}
	// Lower case and extra space are accepted.
	if p, err := ParseEPATH("  20 04\t24 0a "); err != nil || p.String() != "@4/10" {
		t.Errorf("%v %v", p, err)
	}
	for _, s := range []string{"2", "204", "zz", "20 04 24", "20 [Param1]"} {
		if p, err := ParseEPATH(s); err == nil {
			t.Errorf("%q parsed: %v", s, p)
		}
	}
	if _, err := FormatEPATH(cip.Path{nil}); err == nil {
		t.Error("a nil segment formatted")
	}
}

func TestFormatRoundTrip(t *testing.T) {
	for _, name := range []string{"otfabric_adapter.eds", "drive.eds"} {
		t.Run(name, func(t *testing.T) {
			f := mustParse(t, readTestdata(t, name))
			out := f.Format()
			g := mustParse(t, out)
			if !sameShape(f, g) {
				t.Fatalf("Parse(Format(f)) differs from f:\n%s", out)
			}
			if again := g.Format(); again != out {
				t.Fatalf("Format is not idempotent:\n%s\n---\n%s", out, again)
			}
		})
	}
}

func TestFormatEdgeCases(t *testing.T) {
	long := strings.Repeat("x", 120)
	f := &File{Sections: []Section{
		{Name: "File", Entries: []Entry{
			{Keyword: "Quotes", Fields: []Field{str(`say "hi"`), str(`back\slash\`), str(`\"`), str("")}},
			{Keyword: "Long", Fields: []Field{str(long), empty, tok("0x10"), set("1, {2}"), empty}},
			{Keyword: "LongSingle", Fields: []Field{str(long)}},
			{Keyword: "None"},
			{Keyword: "Gaps", Fields: []Field{empty, empty}},
		}},
		{Name: "Empty Section"},
		{Name: "Last", Entries: []Entry{{Keyword: "K", Fields: []Field{tok("-1.5e3"), tok("10-25-2026"), tok("12:00:00")}}}},
	}}
	out := f.Format()
	want := "[File]\n" +
		`	Quotes = "say \"hi\"", "back\\slash\\", "\\\"", "";` + "\n" +
		"\tLong =\n\t\t\"" + long + "\",\n\t\t,\n\t\t0x10,\n\t\t{1, {2}},\n\t\t;\n" +
		"\tLongSingle = \"" + long + "\";\n" +
		"\tNone = ;\n" +
		"\tGaps = , ;\n" +
		"\n[Empty Section]\n" +
		"\n[Last]\n\tK = -1.5e3, 10-25-2026, 12:00:00;\n"
	if out != want {
		t.Fatalf("Format:\n%s\nwant:\n%s", out, want)
	}
	g := mustParse(t, out)
	if !sameShape(f, g) {
		t.Fatalf("round trip:\n%#v\n%#v", shape(f), shape(g))
	}
	if g.Format() != out {
		t.Fatal("Format is not idempotent")
	}
	if (&File{}).Format() != "" {
		t.Error("an empty file formats as text")
	}
}
