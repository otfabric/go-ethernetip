// SPDX-License-Identifier: MIT

package logix

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

type sym = cip.SymbolSegment

var mem = cip.MemberSegment

func TestParseTag(t *testing.T) {
	cases := []struct {
		name string
		path cip.Path
		bit  int
	}{
		{"Tag", cip.Path{sym{Name: "Tag"}}, -1},
		{"_x9", cip.Path{sym{Name: "_x9"}}, -1},
		{"Program:Main.Speed", cip.Path{sym{Name: "Program:Main"}, sym{Name: "Speed"}}, -1},
		{"PROGRAM:Main.A.B", cip.Path{sym{Name: "PROGRAM:Main"}, sym{Name: "A"}, sym{Name: "B"}}, -1},
		{"Arr[3]", cip.Path{sym{Name: "Arr"}, mem(3)}, -1},
		{"Grid[1, 2,3]", cip.Path{sym{Name: "Grid"}, mem(1), mem(2), mem(3)}, -1},
		{"M[2].Sub[0].X", cip.Path{sym{Name: "M"}, mem(2), sym{Name: "Sub"}, mem(0), sym{Name: "X"}}, -1},
		{"Flags.5", cip.Path{sym{Name: "Flags"}}, 5},
		{"A[1].B.63", cip.Path{sym{Name: "A"}, mem(1), sym{Name: "B"}}, 63},
		{"Program:P.T.0", cip.Path{sym{Name: "Program:P"}, sym{Name: "T"}}, 0},
		{"Big[70000]", cip.Path{sym{Name: "Big"}, mem(70000)}, -1},
	}
	for _, c := range cases {
		tp, err := ParseTag(c.name)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(tp.Path, c.path) || tp.Bit != c.bit {
			t.Fatalf("%s: %#v bit %d, want %#v bit %d", c.name, tp.Path, tp.Bit, c.path, c.bit)
		}
	}
}

func TestParseTagErrors(t *testing.T) {
	bad := []string{
		"",
		"Program:Main",
		"Program:.Tag",
		"A..B",
		"A.",
		".A",
		"A.64",
		"A.99999999999999999999",
		"5",
		"1Tag",
		"Bad Name",
		"Tag-1",
		strings.Repeat("a", 41),
		"A[1",
		"A[1]x",
		"A[1,2,3,4]",
		"A[x]",
		"A[]",
		"A[-1]",
		"A[4294967296]",
		"A[1]]",
		"A.5.B",
		"[1]",
	}
	for _, n := range bad {
		if _, err := ParseTag(n); !errors.Is(err, ErrTagName) {
			t.Fatalf("%q: %v", n, err)
		}
	}
	if !validSymbol(strings.Repeat("a", 40)) {
		t.Fatal("40 characters rejected")
	}
	if isDigits("") || !isDigits("012") || isDigits("1a") {
		t.Fatal("isDigits")
	}
}
