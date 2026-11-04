// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

func TestRevision(t *testing.T) {
	if r, err := revision("255.0"); err != nil || r != (cip.Revision{Major: 255, Minor: 0}) {
		t.Errorf("255.0: %v %v", r, err)
	}
	for _, s := range []string{"256.1", "1.300", "x.1", "1", "-1.2"} {
		if _, err := revision(s); err == nil || !strings.Contains(err.Error(), s) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestWidthFlags(t *testing.T) {
	var a u16Flag
	if err := a.Set("0xFFFF"); err != nil || a != 0xFFFF || a.String() != "65535" {
		t.Errorf("u16 max: %v %v", a, err)
	}
	if err := a.Set("65536"); err == nil {
		t.Error("u16 65536 accepted")
	}
	var b u32Flag
	if err := b.Set("4294967295"); err != nil || b != 0xFFFFFFFF || b.String() != "4294967295" {
		t.Errorf("u32 max: %v %v", b, err)
	}
	if err := b.Set("4294967296"); err == nil {
		t.Error("u32 4294967296 accepted")
	}
}

func TestMemberTypeRange(t *testing.T) {
	byName := templates{}
	if _, info, err := byName.memberType(FixtureMember{Name: "a", Type: "SINT", Count: 0xFFFF}); err != nil || info != 0xFFFF {
		t.Errorf("65535 elements: %d %v", info, err)
	}
	for _, m := range []FixtureMember{
		{Name: "a", Type: "SINT", Count: 0x10000},
		{Name: "b", Type: "BOOL", Bit: 8},
		{Name: "c", Type: "BOOL", Bit: -1},
	} {
		if _, _, err := byName.memberType(m); err == nil || !strings.Contains(err.Error(), "member "+m.Name) {
			t.Errorf("%+v: %v", m, err)
		}
	}
	if _, info, err := byName.memberType(FixtureMember{Name: "d", Type: "BOOL", Bit: 7}); err != nil || info != 7 {
		t.Errorf("bit 7: %d %v", info, err)
	}
}

func TestLoadFixture(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(name, []byte(`{"name":"x","identity":{"revision":"1.2"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := loadFixture(name)
	if err != nil || f.Name != "x" {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := loadFixture(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing fixture loaded")
	}
	// A link out of the fixture's directory is refused.
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFixture(link); err == nil {
		t.Error("a link out of the directory is followed")
	}
}
