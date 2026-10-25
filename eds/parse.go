// SPDX-License-Identifier: MIT

// Package eds reads, validates, writes and generates Electronic Data
// Sheets: the text files (.eds) in which a device vendor describes an
// EtherNet/IP device's identity, parameters, assemblies and I/O
// connections.
//
// [Parse] reads a file into its sections and entries without interpreting
// them, so that vendor-specific sections survive a round trip through
// [File.Format]. The typed views ([File.Device], [File.Params],
// [File.Assemblies], [File.Connections]) interpret the public sections;
// [Validate] checks a file against the rules of the format; [GenerateGo]
// turns a file into Go constants, types and scanner configurations.
//
// The grammar follows the publicly documented EDS format as the eds_pie
// project (MIT) and vendor EDS files use it; the ODVA specification of EDS
// (CIP Volume 1, chapter 7) is not available to this project.
package eds

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// ErrSyntax reports text that is not an EDS file.
var ErrSyntax = errors.New("eds: syntax error")

// Limits that bound what Parse accepts from an untrusted file.
const (
	MaxFileSize = 16 << 20 // octets
	maxFields   = 4096     // fields of one entry
	maxEntries  = 1 << 18  // entries of the file
)

// FieldKind is how a field was written.
type FieldKind uint8

// Field kinds.
const (
	// FieldEmpty is a field left empty between two commas.
	FieldEmpty FieldKind = iota
	// FieldString is a quoted string; adjacent strings are joined.
	FieldString
	// FieldToken is an unquoted token: a number, a keyword, a date, a
	// time, a reference such as Param3.
	FieldToken
	// FieldDataset is a braced list, written {a, b, c}.
	FieldDataset
)

// Field is one field of an entry.
type Field struct {
	Kind FieldKind
	// Value is the text: the content of a string without its quotes, the
	// token, or the content of a dataset without its braces.
	Value string
}

// String returns the field as it is written in a file.
func (f Field) String() string {
	switch f.Kind {
	case FieldString:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(f.Value) + `"`
	case FieldDataset:
		return "{" + f.Value + "}"
	default:
		return f.Value
	}
}

// Entry is a keyword and its fields: Keyword = f1, f2, ...;
type Entry struct {
	Keyword string
	Fields  []Field
	// Line is the line the entry starts on.
	Line int
}

// Field returns field i, or an empty field when the entry has fewer.
func (e Entry) Field(i int) Field {
	if i < 0 || i >= len(e.Fields) {
		return Field{}
	}
	return e.Fields[i]
}

// Section is a section of a file: [Name] and its entries.
type Section struct {
	Name    string
	Entries []Entry
	Line    int
}

// Entry returns the first entry with keyword kw (case-insensitive).
func (s *Section) Entry(kw string) (Entry, bool) {
	for _, e := range s.Entries {
		if strings.EqualFold(e.Keyword, kw) {
			return e, true
		}
	}
	return Entry{}, false
}

// File is a parsed EDS file.
type File struct {
	Sections []Section
}

// Section returns the section named name (case-insensitive), or nil.
func (f *File) Section(name string) *Section {
	for i := range f.Sections {
		if strings.EqualFold(f.Sections[i].Name, name) {
			return &f.Sections[i]
		}
	}
	return nil
}

// SyntaxError is an [ErrSyntax] with its position.
type SyntaxError struct {
	Line int
	Msg  string
}

// Error returns for example "eds: line 12: unterminated string".
func (e *SyntaxError) Error() string { return fmt.Sprintf("eds: line %d: %s", e.Line, e.Msg) }

// Is makes a SyntaxError match ErrSyntax.
func (e *SyntaxError) Is(target error) bool { return target == ErrSyntax }

// ParseString parses the text of an EDS file.
func ParseString(s string) (*File, error) { return Parse(strings.NewReader(s)) }

// Parse reads an EDS file. Comments ($ to the end of the line) are
// dropped. It reads at most MaxFileSize octets.
func Parse(r io.Reader) (*File, error) {
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(r), MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, &SyntaxError{Line: 0, Msg: "file larger than 16 MiB"}
	}
	// A UTF-8 byte order mark may start the file.
	p := &parser{src: strings.TrimPrefix(string(data), "\uFEFF"), line: 1}
	return p.file()
}

type parser struct {
	src  string
	pos  int
	line int
}

func (p *parser) errf(format string, a ...any) error {
	return &SyntaxError{Line: p.line, Msg: fmt.Sprintf(format, a...)}
}

func (p *parser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

// skip skips white space and comments.
func (p *parser) skip() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.line++
			p.pos++
		case c == '$':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) file() (*File, error) {
	f := &File{}
	var cur *Section
	n := 0
	for {
		p.skip()
		if p.pos >= len(p.src) {
			return f, nil
		}
		if p.peek() == '[' {
			start := p.line
			p.pos++
			end := strings.IndexAny(p.src[p.pos:], "]\n")
			if end < 0 || p.src[p.pos+end] != ']' {
				return nil, p.errf("unterminated section name")
			}
			name := strings.TrimSpace(p.src[p.pos : p.pos+end])
			p.pos += end + 1
			if name == "" {
				return nil, p.errf("empty section name")
			}
			f.Sections = append(f.Sections, Section{Name: name, Line: start})
			cur = &f.Sections[len(f.Sections)-1]
			continue
		}
		if cur == nil {
			return nil, p.errf("entry before the first section")
		}
		e, err := p.entry()
		if err != nil {
			return nil, err
		}
		if n++; n > maxEntries {
			return nil, p.errf("more than %d entries", maxEntries)
		}
		cur.Entries = append(cur.Entries, e)
	}
}

func isKeywordChar(c byte) bool {
	return c == '_' || c == '-' || c == '.' || c == '/' || c < 0x80 && (unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)))
}

func (p *parser) entry() (Entry, error) {
	e := Entry{Line: p.line}
	start := p.pos
	for p.pos < len(p.src) && isKeywordChar(p.src[p.pos]) {
		p.pos++
	}
	e.Keyword = p.src[start:p.pos]
	if e.Keyword == "" {
		return e, p.errf("expected a keyword, found %q", p.peek())
	}
	p.skip()
	if p.peek() != '=' {
		return e, p.errf("expected = after %s", e.Keyword)
	}
	p.pos++
	for {
		fd, err := p.field()
		if err != nil {
			return e, err
		}
		if len(e.Fields) >= maxFields {
			return e, p.errf("entry %s has more than %d fields", e.Keyword, maxFields)
		}
		e.Fields = append(e.Fields, fd)
		p.skip()
		switch p.peek() {
		case ',':
			p.pos++
		case ';':
			p.pos++
			// "Keyword = ;" has no field.
			if len(e.Fields) == 1 && e.Fields[0].Kind == FieldEmpty {
				e.Fields = nil
			}
			return e, nil
		case 0:
			return e, p.errf("entry %s not terminated by ;", e.Keyword)
		default:
			return e, p.errf("unexpected %q in entry %s", p.peek(), e.Keyword)
		}
	}
}

func (p *parser) field() (Field, error) {
	p.skip()
	switch c := p.peek(); {
	case c == '"':
		var sb strings.Builder
		for p.peek() == '"' {
			p.pos++
			for {
				if p.pos >= len(p.src) || p.src[p.pos] == '\n' {
					return Field{}, p.errf("unterminated string")
				}
				ch := p.src[p.pos]
				if ch == '\\' && p.pos+1 < len(p.src) && (p.src[p.pos+1] == '"' || p.src[p.pos+1] == '\\') {
					sb.WriteByte(p.src[p.pos+1])
					p.pos += 2
					continue
				}
				p.pos++
				if ch == '"' {
					break
				}
				sb.WriteByte(ch)
			}
			p.skip()
		}
		return Field{Kind: FieldString, Value: sb.String()}, nil
	case c == '{':
		depth := 0
		start := p.pos
		for p.pos < len(p.src) {
			switch p.src[p.pos] {
			case '{':
				depth++
			case '}':
				depth--
			case '\n':
				p.line++
			}
			p.pos++
			if depth == 0 {
				return Field{Kind: FieldDataset, Value: strings.TrimSpace(p.src[start+1 : p.pos-1])}, nil
			}
			if depth > 16 {
				return Field{}, p.errf("datasets nested too deep")
			}
		}
		return Field{}, p.errf("unterminated dataset")
	case c == ',' || c == ';':
		return Field{Kind: FieldEmpty}, nil
	default:
		start := p.pos
		for p.pos < len(p.src) {
			ch := p.src[p.pos]
			if ch == ',' || ch == ';' || ch == '\n' || ch == '$' || ch == '"' || ch == '{' || ch == '[' {
				break
			}
			p.pos++
		}
		v := strings.TrimSpace(p.src[start:p.pos])
		if v == "" {
			return Field{}, p.errf("unexpected %q", p.peek())
		}
		return Field{Kind: FieldToken, Value: v}, nil
	}
}
