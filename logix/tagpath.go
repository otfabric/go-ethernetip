// SPDX-License-Identifier: MIT

package logix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/otfabric/go-ethernetip/cip"
)

// ErrTagName reports a tag name that does not parse.
var ErrTagName = fmt.Errorf("logix: invalid tag name")

// TagPath is a parsed tag name: its symbolic path and, when the name ends
// in a bit number ("Counts.5"), that bit.
type TagPath struct {
	Path cip.Path
	// Bit is the bit number of a name that ends in one, -1 otherwise.
	Bit int
}

// ParseTag parses a Logix tag name into its symbolic path:
//
//	Tag                 a controller-scoped tag
//	Program:Main.Tag    a program-scoped tag
//	Tag[3]  Tag[1,2]    array elements (up to three dimensions)
//	Tag.Member[2].Sub   structure members
//	Tag.5               bit 5 of an integer
//
// Each name becomes an ANSI extended symbol segment, each index a member
// segment.
func ParseTag(name string) (TagPath, error) {
	tp := TagPath{Bit: -1}
	if name == "" {
		return tp, fmt.Errorf("%w: empty", ErrTagName)
	}
	rest := name
	if strings.HasPrefix(strings.ToLower(rest), "program:") {
		i := strings.IndexByte(rest, '.')
		if i < 0 || i == len("program:") {
			return tp, fmt.Errorf("%w: %q: program without a tag", ErrTagName, name)
		}
		tp.Path = append(tp.Path, cip.SymbolSegment{Name: rest[:i]})
		rest = rest[i+1:]
	}
	parts := strings.Split(rest, ".")
	for pi, part := range parts {
		if part == "" {
			return tp, fmt.Errorf("%w: %q: empty member", ErrTagName, name)
		}
		if pi > 0 && pi == len(parts)-1 && isDigits(part) {
			b, _ := strconv.Atoi(part)
			if b > 63 {
				return tp, fmt.Errorf("%w: %q: bit %d", ErrTagName, name, b)
			}
			tp.Bit = b
			break
		}
		sym, idx, ok := strings.Cut(part, "[")
		if !validSymbol(sym) {
			return tp, fmt.Errorf("%w: %q: symbol %q", ErrTagName, name, sym)
		}
		tp.Path = append(tp.Path, cip.SymbolSegment{Name: sym})
		if !ok {
			continue
		}
		if !strings.HasSuffix(idx, "]") {
			return tp, fmt.Errorf("%w: %q: unclosed index", ErrTagName, name)
		}
		dims := strings.Split(strings.TrimSuffix(idx, "]"), ",")
		if len(dims) > 3 {
			return tp, fmt.Errorf("%w: %q: more than three dimensions", ErrTagName, name)
		}
		for _, d := range dims {
			v, err := strconv.ParseUint(strings.TrimSpace(d), 10, 32)
			if err != nil {
				return tp, fmt.Errorf("%w: %q: index %q", ErrTagName, name, d)
			}
			tp.Path = append(tp.Path, cip.MemberSegment(uint32(v)))
		}
	}
	return tp, nil
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// validSymbol accepts Logix names: letters, digits and underscores, not
// starting with a digit, at most 40 characters; a leading colon form such
// as "Program:X" is handled by ParseTag.
func validSymbol(s string) bool {
	if s == "" || len(s) > 40 || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, c := range s {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
