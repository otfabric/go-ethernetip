// SPDX-License-Identifier: MIT

package eds

import (
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func tok(v string) Field { return Field{Kind: FieldToken, Value: v} }
func str(v string) Field { return Field{Kind: FieldString, Value: v} }
func set(v string) Field { return Field{Kind: FieldDataset, Value: v} }

var empty = Field{Kind: FieldEmpty}

func TestParseSectionsAndEntries(t *testing.T) {
	src := `$ a comment before the first section
[File]   $ comment after a section
	DescText = "first" $ comment between strings
		"second"
		"third";
	Quoted = "say \"hi\" \\ there";
	CreateDate = 10-25-2026;
	CreateTime = 12:00:00;
	Hex = 0xC8, 0X1f;
	Negative = -40, -0.5, 1e3;
[ Device Classification ]
	Class1 = EtherNetIP;
	Empty = ;
	Gaps = 1,,3, ;
	Multi =
		1,  $ one
		2,
		3;
	Set = {1, {2, 3}, "x"}, { };
	Words = a token with spaces , x;
`
	f := mustParse(t, src)
	want := []Section{
		{Name: "File", Entries: []Entry{
			{Keyword: "DescText", Fields: []Field{str("firstsecondthird")}},
			{Keyword: "Quoted", Fields: []Field{str(`say "hi" \ there`)}},
			{Keyword: "CreateDate", Fields: []Field{tok("10-25-2026")}},
			{Keyword: "CreateTime", Fields: []Field{tok("12:00:00")}},
			{Keyword: "Hex", Fields: []Field{tok("0xC8"), tok("0X1f")}},
			{Keyword: "Negative", Fields: []Field{tok("-40"), tok("-0.5"), tok("1e3")}},
		}},
		{Name: "Device Classification", Entries: []Entry{
			{Keyword: "Class1", Fields: []Field{tok("EtherNetIP")}},
			{Keyword: "Empty"},
			{Keyword: "Gaps", Fields: []Field{tok("1"), empty, tok("3"), empty}},
			{Keyword: "Multi", Fields: []Field{tok("1"), tok("2"), tok("3")}},
			{Keyword: "Set", Fields: []Field{set(`1, {2, 3}, "x"`), set("")}},
			{Keyword: "Words", Fields: []Field{tok("a token with spaces"), tok("x")}},
		}},
	}
	if got := shape(f); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
	// Lines of sections and entries.
	lines := map[string]int{"DescText": 3, "Quoted": 6, "Negative": 10, "Class1": 12, "Multi": 15, "Words": 20}
	for _, s := range f.Sections {
		for _, e := range s.Entries {
			if l, ok := lines[e.Keyword]; ok && e.Line != l {
				t.Errorf("%s on line %d, want %d", e.Keyword, e.Line, l)
			}
		}
	}
	if f.Sections[0].Line != 2 || f.Sections[1].Line != 11 {
		t.Errorf("section lines %d, %d", f.Sections[0].Line, f.Sections[1].Line)
	}
}

func TestParseEmpty(t *testing.T) {
	for _, src := range []string{"", "  \n\t$ only a comment\n", "\uFEFF"} {
		f := mustParse(t, src)
		if len(f.Sections) != 0 {
			t.Errorf("%q: %d sections", src, len(f.Sections))
		}
	}
}

func TestParseBOM(t *testing.T) {
	f := mustParse(t, "\uFEFF[File]\r\n\tDescText = \"x\";\r\n")
	if len(f.Sections) != 1 || f.Sections[0].Name != "File" || f.Sections[0].Entries[0].Field(0).Value != "x" {
		t.Fatalf("%#v", f)
	}
	// A byte order mark is only skipped at the start: in a token its octets
	// are kept, U+FFFD (EF BF BD) among them.
	f = mustParse(t, "[A]\nK = \uFFFDx, \uFEFF;\n")
	if got := f.Sections[0].Entries[0].Fields; got[0].Value != "\uFFFDx" || got[1].Value != "\uFEFF" {
		t.Fatalf("fields %q", got)
	}
	if _, err := ParseString("[A]\n\uFEFFK = 1;"); err == nil {
		t.Fatal("a byte order mark before a keyword parsed")
	}
}

func TestParseDatasets(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("{", n) + "1" + strings.Repeat("}", n) }
	f := mustParse(t, "[A]\nK = "+deep(16)+";\nL = {a,\n b};\nM = 2;")
	e := f.Sections[0].Entries
	if e[0].Field(0).Value != deep(15) || e[1].Field(0).Value != "a,\n b" {
		t.Fatalf("datasets %q %q", e[0].Field(0).Value, e[1].Field(0).Value)
	}
	if e[2].Line != 5 {
		t.Errorf("a dataset across lines: next entry on line %d, want 5", e[2].Line)
	}
	_, err := ParseString("[A]\nK = " + deep(17) + ";")
	if err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Fatalf("17 levels: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		line      int
		msg       string
	}{
		{"entry before section", "$c\nK = 1;", 2, "entry before the first section"},
		{"unterminated string", "[A]\nK = \"abc;\nL = 1;", 2, "unterminated string"},
		{"unterminated string at EOF", "[A]\nK = \"abc\\\"", 2, "unterminated string"},
		{"unterminated adjacent string", "[A]\nK = \"a\"\n \"b", 3, "unterminated string"},
		{"unterminated section", "[A]\n[B\nK = 1;", 2, "unterminated section name"},
		{"unterminated section at EOF", "[A", 1, "unterminated section name"},
		{"empty section name", "[A]\n[ \t]", 2, "empty section name"},
		{"missing =", "[A]\n\nK 1;", 3, "expected = after K"},
		{"missing ;", "[A]\nK = 1, 2", 2, "entry K not terminated by ;"},
		{"missing ; after string", "[A]\nK = \"x\"\n", 3, "entry K not terminated by ;"},
		{"no keyword", "[A]\n= 1;", 2, `expected a keyword, found '='`},
		{"bad keyword char", "[A]\nK* = 1;", 2, `expected = after K`},
		{"string then token", "[A]\nK = 1 \"x\";", 2, `unexpected '"' in entry K`},
		{"string then dataset", "[A]\nK = \"x\" {1};", 2, `unexpected '{' in entry K`},
		{"bracket in field", "[A]\nK = [1];", 2, `unexpected '['`},
		{"unterminated dataset", "[A]\nK = {1,\n2;\n", 4, "unterminated dataset"},
		{"too many fields", "[A]\nK = " + strings.Repeat("1,", maxFields) + "1;", 2, "more than 4096 fields"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseString(tc.src)
			if err == nil {
				t.Fatal("no error")
			}
			if !errors.Is(err, ErrSyntax) {
				t.Errorf("%v does not match ErrSyntax", err)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("%T is not a *SyntaxError", err)
			}
			if se.Line != tc.line || !strings.Contains(se.Msg, tc.msg) {
				t.Errorf("line %d %q, want line %d %q", se.Line, se.Msg, tc.line, tc.msg)
			}
			if want := "eds: line " + strconv.Itoa(tc.line) + ": "; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("Error() = %q, want prefix %q", err.Error(), want)
			}
		})
	}
	if errors.Is(errors.New("other"), ErrSyntax) || (&SyntaxError{}).Is(io.EOF) {
		t.Error("SyntaxError matches other errors")
	}
}

func TestParseFieldLimit(t *testing.T) {
	f := mustParse(t, "[A]\nK = "+strings.Repeat("1,", maxFields-1)+"1;")
	if n := len(f.Sections[0].Entries[0].Fields); n != maxFields {
		t.Fatalf("%d fields", n)
	}
}

func TestParseEntryLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("parses 2^18 entries")
	}
	src := "[A]\n" + strings.Repeat("K=;\n", maxEntries)
	f := mustParse(t, src)
	if n := len(f.Sections[0].Entries); n != maxEntries {
		t.Fatalf("%d entries", n)
	}
	_, err := ParseString(src + "[B]\nK=;\n")
	var se *SyntaxError
	if !errors.As(err, &se) || !strings.Contains(se.Msg, "more than 262144 entries") || se.Line != maxEntries+3 {
		t.Fatalf("%v", err)
	}
}

// spaces is a reader of n spaces after a prefix that allocates nothing per
// read.
type spaces struct {
	prefix string
	n      int64
}

func (r *spaces) Read(b []byte) (int, error) {
	if r.prefix != "" {
		k := copy(b, r.prefix)
		r.prefix = r.prefix[k:]
		return k, nil
	}
	if r.n <= 0 {
		return 0, io.EOF
	}
	k := len(b)
	if int64(k) > r.n {
		k = int(r.n)
	}
	for i := range b[:k] {
		b[i] = ' '
	}
	r.n -= int64(k)
	return k, nil
}

func TestParseMaxFileSize(t *testing.T) {
	const head = "[A]\nK = 1;\n"
	f, err := Parse(&spaces{prefix: head, n: MaxFileSize - int64(len(head))})
	if err != nil || len(f.Sections) != 1 {
		t.Fatalf("a file of MaxFileSize octets: %v", err)
	}
	_, err = Parse(&spaces{prefix: head, n: MaxFileSize - int64(len(head)) + 1})
	if !errors.Is(err, ErrSyntax) || !strings.Contains(err.Error(), "larger than 16 MiB") {
		t.Fatalf("a file of MaxFileSize+1 octets: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestParseReadError(t *testing.T) {
	_, err := Parse(failingReader{})
	if err == nil || err.Error() != "disk on fire" || errors.Is(err, ErrSyntax) {
		t.Fatalf("%v", err)
	}
}

func TestFieldString(t *testing.T) {
	for _, tc := range []struct {
		f    Field
		want string
	}{
		{empty, ""},
		{tok("0xC8"), "0xC8"},
		{str(`a "b" c:\d`), `"a \"b\" c:\\d"`},
		{set("1, 2"), "{1, 2}"},
	} {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("%#v: %s, want %s", tc.f, got, tc.want)
		}
	}
}

func TestLookups(t *testing.T) {
	f := mustParse(t, "[File]\nDescText = \"x\";\n[device]\nVendCode = 1, 2;")
	s := f.Section("DEVICE")
	if s == nil || s.Name != "device" {
		t.Fatalf("Section is not case-insensitive: %v", s)
	}
	if f.Section("Params") != nil {
		t.Error("a missing section was found")
	}
	e, ok := s.Entry("vendcode")
	if !ok || e.Field(1).Value != "2" {
		t.Fatalf("Entry is not case-insensitive: %v %v", e, ok)
	}
	if _, ok := s.Entry("ProdCode"); ok {
		t.Error("a missing entry was found")
	}
	if e.Field(-1) != (Field{}) || e.Field(2) != (Field{}) {
		t.Error("Field out of range is not empty")
	}
}
