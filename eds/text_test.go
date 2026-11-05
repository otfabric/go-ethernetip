// SPDX-License-Identifier: MIT

package eds

import (
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
)

func textSpec() Spec {
	return Spec{
		Identity:    cip.Identity{VendorID: 1, ProductName: "adapter", Revision: cip.Revision{Major: 1, Minor: 1}},
		VendorName:  "vendor",
		Date:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Assemblies:  []SpecAssembly{{Instance: 100, Name: "in", Size: 4}, {Instance: 150, Name: "out", Size: 4}},
		Connections: []SpecConnection{{Name: "owner", Output: 150, Input: 100, OutputSize: 4, InputSize: 4}},
	}
}

// A text with a control character would give an EDS that does not parse:
// Build refuses it.
func TestBuildRefusesControlCharacters(t *testing.T) {
	for name, set := range map[string]func(*Spec){
		"vendor":      func(s *Spec) { s.VendorName = "a\nb" },
		"description": func(s *Spec) { s.Description = "a\rb" },
		"product":     func(s *Spec) { s.Identity.ProductName = "a\x00b" },
		"assembly":    func(s *Spec) { s.Assemblies[0].Name = "a\tb" },
		"connection":  func(s *Spec) { s.Connections[0].Name = "a\x7Fb" },
	} {
		s := textSpec()
		set(&s)
		if _, err := Build(s); err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Quotes and backslashes are escaped and round-trip.
	s := textSpec()
	s.Identity.ProductName = `say "hi" \ bye`
	f, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseString(f.Format())
	if err != nil {
		t.Fatal(err)
	}
	if d, err := g.Device(); err != nil || d.ProductName != s.Identity.ProductName {
		t.Errorf("round trip: %q %v", d.ProductName, err)
	}
}
