// SPDX-License-Identifier: MIT

package eds

import (
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
)

func buildSpec() Spec {
	return Spec{
		Identity: cip.Identity{VendorID: 65535, DeviceType: 12, ProductCode: 42,
			Revision: cip.Revision{Major: 3, Minor: 7}, ProductName: "Built adapter"},
		VendorName:  "OT Fabric",
		Description: "A built EDS",
		Date:        time.Date(2026, 10, 25, 13, 14, 15, 0, time.UTC),
		Assemblies: []SpecAssembly{
			{Instance: 100, Name: "Input", Size: 32},
			{Instance: 150, Name: "Output", Size: 16},
			{Instance: 151, Name: "Config", Size: 4},
			{Instance: 199, Name: "Heartbeat", Size: 0},
		},
		Connections: []SpecConnection{
			{Name: "Exclusive owner", Config: 151, Output: 150, Input: 100, OutputSize: 16, InputSize: 32},
			{Name: "Input only", Output: 199, Input: 100, InputSize: 32},
		},
	}
}

func TestBuild(t *testing.T) {
	f, err := Build(buildSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range Validate(f) {
		t.Errorf("%s", is)
	}
	text := f.Format()
	g := mustParse(t, text)
	if !sameShape(f, g) {
		t.Fatalf("Parse(Format(Build)) differs:\n%s", text)
	}
	for _, want := range []string{
		"\tCreateDate = 10-25-2026;\n\tCreateTime = 13:14:15;\n",
		`	DescText = "A built EDS";`,
		`	Assem100 = "Input", "20 04 24 64", 32, 0x0000, , , 256, ;`,
		`	Assem199 = "Heartbeat", "20 04 24 C7", 0, 0x0000, , ;`,
		"\t\t4,\n\t\tAssem151,\n\t\t\"Exclusive owner\",\n\t\t\"\",\n\t\t\"20 04 24 97 2C 96 2C 64\";\n",
		"\t\t,\n\t\t,\n\t\t\"Input only\",\n\t\t\"\",\n\t\t\"20 04 2C C7 2C 64\";\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	d, err := g.Device()
	if err != nil || d.VendorID != 65535 || d.ProductName != "Built adapter" || d.TypeName != cip.DeviceType(12).String() || d.Revision.Minor != 7 {
		t.Errorf("%+v %v", d, err)
	}

	src, err := GenerateGo(g, GenerateOptions{Package: "built"})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := typeCheck(t, src)
	if got := ioConfig(t, file, "ConnectionExclusiveOwner"); got["ConfigInstance"] != "151" || got["OutputInstance"] != "150" ||
		got["InputInstance"] != "100" || got["OutputSize"] != "16" || got["InputSize"] != "32" || got["RPI"] != "10000 * time.Microsecond" {
		t.Errorf("ConnectionExclusiveOwner %v", got)
	}
	if got := ioConfig(t, file, "ConnectionInputOnly"); got["ConfigInstance"] != "" || got["OutputInstance"] != "199" || got["OutputSize"] != "0" {
		t.Errorf("ConnectionInputOnly %v", got)
	}
}

func TestBuildDefaults(t *testing.T) {
	s := buildSpec()
	s.Description, s.VendorName, s.Date = "", "", time.Time{}
	s.Identity.VendorID = 1
	before := time.Now().Add(-time.Second)
	f, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	fs := f.Section("File")
	if e, _ := fs.Entry("DescText"); e.Field(0).Value != "Built adapter" {
		t.Errorf("DescText %v", e)
	}
	e, _ := fs.Entry("CreateDate")
	e2, _ := fs.Entry("CreateTime")
	created, err := time.ParseInLocation("01-02-2006 15:04:05", e.Field(0).Value+" "+e2.Field(0).Value, time.Local)
	if err != nil || created.Before(before.Truncate(time.Second)) || created.After(time.Now()) {
		t.Errorf("created %v %v", created, err)
	}
	if e, _ := f.Section("Device").Entry("VendName"); e.Field(0).Value != cip.VendorName(1) || e.Field(0).Value == "" {
		t.Errorf("VendName %v, want %q", e, cip.VendorName(1))
	}
	for _, is := range Validate(f) {
		t.Errorf("%s", is)
	}
	// No assemblies, no connections: empty sections.
	f, err = Build(Spec{Identity: s.Identity})
	if err != nil {
		t.Fatal(err)
	}
	if a := f.Section("Assembly"); a == nil || len(a.Entries) != 0 {
		t.Errorf("Assembly %v", a)
	}
	if c := f.Section("Connection Manager"); c == nil || len(c.Entries) != 0 {
		t.Errorf("Connection Manager %v", c)
	}
}

func TestBuildErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Spec)
		msg  string
	}{
		{"assembly 0", func(s *Spec) { s.Assemblies[0].Instance = 0 }, "eds: assembly 0 of 32 octets"},
		{"negative size", func(s *Spec) { s.Assemblies[1].Size = -1 }, "eds: assembly 150 of -1 octets"},
		{"unknown output", func(s *Spec) { s.Connections[0].Output = 7 }, `eds: connection "Exclusive owner": no assembly 7`},
		{"unknown input", func(s *Spec) { s.Connections[1].Input = 8 }, `eds: connection "Input only": no assembly 8`},
	} {
		s := buildSpec()
		tc.edit(&s)
		if f, err := Build(s); err == nil || err.Error() != tc.msg {
			t.Errorf("%s: %v %v, want %q", tc.name, f, err, tc.msg)
		}
	}
	// An unknown configuration assembly is left out of the sizes.
	s := buildSpec()
	s.Connections[0].Config = 9
	f, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := f.Connections()
	if cs[0].ConfigSize != "" || cs[0].ConfigFormat != "" || cs[0].PathText != "20 04 24 09 2C 96 2C 64" {
		t.Errorf("%+v", cs[0])
	}
}
