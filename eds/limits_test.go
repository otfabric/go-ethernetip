// SPDX-License-Identifier: MIT

package eds

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// wideEntry is an entry of maxFields fields.
var wideEntry = "K = " + strings.Repeat("1,", maxFields-1) + "1;\n"

// TestParseSectionLimit: maxSections sections parse; one more is refused.
func TestParseSectionLimit(t *testing.T) {
	src := strings.Repeat("[S]\n", maxSections)
	if f := mustParse(t, src); len(f.Sections) != maxSections {
		t.Fatalf("%d sections", len(f.Sections))
	}
	_, err := ParseString(src + "[T]\n")
	var se *SyntaxError
	if !errors.Is(err, ErrSyntax) || !errors.As(err, &se) || !strings.Contains(se.Msg, "more than 16384 sections") || se.Line != maxSections+1 {
		t.Fatalf("%v", err)
	}
}

// TestParseFileFieldLimit: maxFileFields fields in the file parse; one
// more is refused.
func TestParseFileFieldLimit(t *testing.T) {
	src := "[A]\n" + strings.Repeat(wideEntry, maxFileFields/maxFields)
	f := mustParse(t, src)
	n := 0
	for _, e := range f.Sections[0].Entries {
		n += len(e.Fields)
	}
	if n != maxFileFields {
		t.Fatalf("%d fields", n)
	}
	_, err := ParseString(src + "K = 1;\n")
	var se *SyntaxError
	if !errors.Is(err, ErrSyntax) || !errors.As(err, &se) || !strings.Contains(se.Msg, "more than 1048576 fields in the file") {
		t.Fatalf("%v", err)
	}
}

// TestLimitsAboveRealFiles: the files in testdata stay far below the
// limits (a hundredth of each, at most).
func TestLimitsAboveRealFiles(t *testing.T) {
	for _, name := range []string{"otfabric_adapter.eds", "drive.eds"} {
		src := readTestdata(t, name)
		f := mustParse(t, src)
		entries, fields, widest := 0, 0, 0
		for _, s := range f.Sections {
			entries += len(s.Entries)
			for _, e := range s.Entries {
				fields += len(e.Fields)
				widest = max(widest, len(e.Fields))
			}
		}
		t.Logf("%s: %d octets, %d sections, %d entries, %d fields, at most %d in an entry", name, len(src), len(f.Sections), entries, fields, widest)
		if len(src) > MaxFileSize/100 || len(f.Sections) > maxSections/100 || entries > maxEntries/100 || fields > maxFileFields/100 || widest > maxFields/100 {
			t.Errorf("%s is within a hundredth of a limit", name)
		}
	}
}

// parseBudget is what one Parse may allocate, for any file at or just
// past the limits: the file is read and copied (three to six times
// MaxFileSize with the growth of the read buffer, six with the race
// detector), and at most maxSections sections, maxEntries entries and
// maxFileFields fields are held, four times over for the growth of their
// slices. On a 64-bit platform it is 243 MiB.
const parseBudget = uint64(6*MaxFileSize +
	4*(maxSections*unsafe.Sizeof(Section{})+maxEntries*unsafe.Sizeof(Entry{})+maxFileFields*unsafe.Sizeof(Field{})))

// TestParseAllocationBudget: files at the limits, accepted or refused,
// allocate within parseBudget.
func TestParseAllocationBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("parses files of up to 16 MiB")
	}
	fill := func(head, unit string) string {
		return head + strings.Repeat(unit, (MaxFileSize-len(head))/len(unit))
	}
	for _, tc := range []struct {
		name string
		src  string
		ok   bool
	}{
		{"maxFileFields fields in wide entries", "[A]\n" + strings.Repeat(wideEntry, maxFileFields/maxFields), true},
		{"maxEntries entries of 4 fields", "[A]\n" + strings.Repeat("K=1,1,1,1;\n", maxEntries), true},
		{"maxEntries empty entries", "[A]\n" + strings.Repeat("K=;\n", maxEntries), true},
		{"maxSections sections", strings.Repeat("[S]\n", maxSections), true},
		{"MaxFileSize octets of wide entries", fill("[A]\n", wideEntry), false},
		{"MaxFileSize octets of short entries", fill("[A]\n", "K=1;\n"), false},
		{"MaxFileSize octets of sections", fill("", "[S]\n"), false},
		{"MaxFileSize octets of one-field sections", fill("", "[S]\nK=1;\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			a := testenv.PerCall(t, 1, func() { _, err = ParseString(tc.src) })
			t.Logf("%d octets, %d MiB allocated per call, budget %d MiB (%v)", len(tc.src), a.Octets>>20, parseBudget>>20, err)
			if a.Octets > parseBudget {
				t.Fatalf("%d MiB allocated for a file of %d octets, budget %d MiB", a.Octets>>20, len(tc.src), parseBudget>>20)
			}
			if (err == nil) != tc.ok {
				t.Fatalf("Parse = %v", err)
			}
		})
	}
}
