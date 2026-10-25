// SPDX-License-Identifier: MIT

package eds

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
)

// Severity is the weight of an [Issue].
type Severity uint8

// Severities.
const (
	// Warning: the file is usable but deviates from the format or from
	// common practice.
	Warning Severity = iota + 1
	// Error: a tool cannot rely on the file.
	Error
)

// String returns "warning" or "error".
func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Issue is a finding of [Validate].
type Issue struct {
	Severity Severity
	Line     int
	Section  string
	Message  string
}

// String returns for example "error: line 4 [Device]: VendCode missing".
func (i Issue) String() string {
	return fmt.Sprintf("%s: line %d [%s]: %s", i.Severity, i.Line, i.Section, i.Message)
}

var (
	reDate = regexp.MustCompile(`^(\d{2})-(\d{2})-(\d{4})$`)
	reTime = regexp.MustCompile(`^(\d{2}):(\d{2}):(\d{2})$`)
	reRef  = regexp.MustCompile(`^(?i)(Param|Assem|Enum|Connection|ProxyAssem)(\d+)$`)
)

// Validate checks a file and returns its issues, errors first. A file with
// no Error issue can be used by the typed views and the generator.
//
// It checks: [File] and [Device] come first, with their required entries;
// dates, times and revisions are well formed; numbers are numbers; data
// types of parameters are elementary types whose size matches; minimum,
// maximum and default are ordered; ParamN and AssemN references resolve;
// EPATHs decode; assembly members fill their size; keywords are not
// repeated within a section.
func Validate(f *File) []Issue {
	v := &validator{f: f}
	v.order()
	v.file()
	v.device()
	v.duplicates()
	v.params()
	v.assemblies()
	v.connections()
	out := append(v.errs, v.warns...)
	return out
}

type validator struct {
	f     *File
	errs  []Issue
	warns []Issue
}

func (v *validator) add(sev Severity, line int, sec, format string, a ...any) {
	is := Issue{Severity: sev, Line: line, Section: sec, Message: fmt.Sprintf(format, a...)}
	if sev == Error {
		v.errs = append(v.errs, is)
	} else {
		v.warns = append(v.warns, is)
	}
}

func (v *validator) order() {
	if len(v.f.Sections) == 0 {
		v.add(Error, 0, "", "no sections")
		return
	}
	if !strings.EqualFold(v.f.Sections[0].Name, "File") {
		v.add(Error, v.f.Sections[0].Line, v.f.Sections[0].Name, "the first section must be [File]")
	}
	if len(v.f.Sections) < 2 || !strings.EqualFold(v.f.Sections[1].Name, "Device") {
		v.add(Warning, 0, "", "the second section should be [Device]")
	}
}

func (v *validator) require(s *Section, kws ...string) {
	for _, kw := range kws {
		if _, ok := s.Entry(kw); !ok {
			v.add(Error, s.Line, s.Name, "%s missing", kw)
		}
	}
}

func (v *validator) file() {
	s := v.f.Section("File")
	if s == nil {
		v.add(Error, 0, "File", "no [File] section")
		return
	}
	v.require(s, "DescText", "CreateDate", "CreateTime", "Revision")
	for _, kw := range []string{"CreateDate", "ModDate"} {
		if e, ok := s.Entry(kw); ok && !validDate(e.Field(0).Value) {
			v.add(Error, e.Line, s.Name, "%s %q is not a date (mm-dd-yyyy)", kw, e.Field(0).Value)
		}
	}
	for _, kw := range []string{"CreateTime", "ModTime"} {
		if e, ok := s.Entry(kw); ok && !validTime(e.Field(0).Value) {
			v.add(Error, e.Line, s.Name, "%s %q is not a time (hh:mm:ss)", kw, e.Field(0).Value)
		}
	}
	if e, ok := s.Entry("Revision"); ok {
		major, minor, found := strings.Cut(e.Field(0).Value, ".")
		_, e1 := strconv.ParseUint(major, 10, 8)
		_, e2 := strconv.ParseUint(minor, 10, 8)
		if !found || e1 != nil || e2 != nil {
			v.add(Error, e.Line, s.Name, "Revision %q is not major.minor", e.Field(0).Value)
		}
	}
}

func validDate(s string) bool {
	m := reDate.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	_, err := time.Parse("01-02-2006", s)
	return err == nil
}

func validTime(s string) bool {
	if !reTime.MatchString(s) {
		return false
	}
	_, err := time.Parse("15:04:05", s)
	return err == nil
}

func (v *validator) device() {
	s := v.f.Section("Device")
	if s == nil {
		v.add(Error, 0, "Device", "no [Device] section")
		return
	}
	v.require(s, "VendCode", "ProdType", "ProdCode", "MajRev", "MinRev", "ProdName")
	for kw, bits := range map[string]int{"VendCode": 16, "ProdType": 16, "ProdCode": 16, "MajRev": 8, "MinRev": 8} {
		if e, ok := s.Entry(kw); ok {
			if _, err := parseUint(e.Field(0), bits); err != nil {
				v.add(Error, e.Line, s.Name, "%s: %v", kw, err)
			}
		}
	}
	if e, ok := s.Entry("ProdName"); ok && len(e.Field(0).Value) > 32 {
		v.add(Warning, e.Line, s.Name, "ProdName longer than 32 characters")
	}
	if dc := v.f.Section("Device Classification"); dc == nil {
		v.add(Warning, 0, "Device Classification", "no [Device Classification] section (EtherNetIP)")
	} else {
		found := false
		for _, e := range dc.Entries {
			if strings.EqualFold(e.Field(0).Value, "EtherNetIP") {
				found = true
			}
		}
		if !found {
			v.add(Warning, dc.Line, dc.Name, "no class EtherNetIP")
		}
	}
}

func (v *validator) duplicates() {
	for _, s := range v.f.Sections {
		seen := map[string]int{}
		for _, e := range s.Entries {
			k := strings.ToLower(e.Keyword)
			if l, ok := seen[k]; ok {
				v.add(Error, e.Line, s.Name, "%s repeats the entry of line %d", e.Keyword, l)
			}
			seen[k] = e.Line
		}
	}
}

// exists reports whether a reference such as Param3 names an entry.
func (v *validator) exists(ref string) bool {
	m := reRef.FindStringSubmatch(ref)
	if m == nil {
		return false
	}
	sec := map[string]string{"param": "Params", "enum": "Params", "assem": "Assembly", "proxyassem": "Assembly", "connection": "Connection Manager"}[strings.ToLower(m[1])]
	s := v.f.Section(sec)
	if s == nil {
		return false
	}
	_, ok := s.Entry(ref)
	return ok
}

func (v *validator) params() {
	s := v.f.Section("Params")
	if s == nil {
		return
	}
	ps, err := v.f.Params()
	if err != nil {
		v.add(Error, s.Line, s.Name, "%v", err)
		return
	}
	lines := map[int]int{}
	for _, ne := range numbered(s, "Param") {
		lines[ne.n] = ne.e.Line
	}
	for _, p := range ps {
		line := lines[p.Number]
		if !p.Type.Known() {
			v.add(Error, line, s.Name, "Param%d: data type 0x%02X is not an elementary type", p.Number, uint8(p.Type))
			continue
		}
		if n := p.Type.Size(); n > 0 && p.Size != n {
			v.add(Error, line, s.Name, "Param%d: data size %d, %s has %d", p.Number, p.Size, p.Type, n)
		}
		if p.Name == "" {
			v.add(Warning, line, s.Name, "Param%d has no name", p.Number)
		}
		if !p.Type.IsInteger() && !p.Type.IsFloat() {
			continue
		}
		lim := map[string]float64{}
		for k, val := range map[string]string{"minimum": p.Min, "maximum": p.Max, "default": p.Default} {
			if strings.TrimSpace(val) == "" {
				continue
			}
			x, err := limitValue(val, p.Type)
			if err != nil {
				v.add(Error, line, s.Name, "Param%d: %s %q is not a number", p.Number, k, val)
				continue
			}
			lim[k] = x
		}
		mn, okMin := lim["minimum"]
		mx, okMax := lim["maximum"]
		df, okDef := lim["default"]
		if okMin && okMax && mn > mx {
			v.add(Error, line, s.Name, "Param%d: minimum above maximum", p.Number)
		}
		if okDef && (okMin && df < mn || okMax && df > mx) {
			v.add(Error, line, s.Name, "Param%d: default outside minimum and maximum", p.Number)
		}
	}
}

func number(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		u, err := strconv.ParseUint(s[2:], 16, 64)
		return float64(u), err
	}
	return strconv.ParseFloat(s, 64)
}

// limitValue returns the value of a minimum, maximum or default of a
// parameter of type t. A hex number of a signed type is its two's
// complement, as GenerateGo reads it: 0xFFFF of an INT is -1.
func limitValue(s string, t cip.DataType) (float64, error) {
	x, err := number(s)
	if err != nil || !t.IsSigned() || base(strings.TrimSpace(s)) != 16 {
		return x, err
	}
	bits := 8 * t.Size()
	u, _ := strconv.ParseUint(strings.TrimSpace(s)[2:], 16, 64)
	if bits < 64 && u >= 1<<bits {
		return x, nil
	}
	return float64(int64(u<<(64-bits)) >> (64 - bits)), nil
}

func (v *validator) assemblies() {
	s := v.f.Section("Assembly")
	if s == nil {
		return
	}
	as, err := v.f.Assemblies()
	if err != nil {
		v.add(Error, s.Line, s.Name, "%v", err)
		return
	}
	for _, a := range as {
		e, _ := s.Entry("Assem" + strconv.Itoa(a.Number))
		bits := 0
		for _, m := range a.Members {
			bits += m.Bits
			if m.Ref != "" && !v.exists(m.Ref) {
				v.add(Error, e.Line, s.Name, "Assem%d: member %s does not exist", a.Number, m.Ref)
			}
		}
		if a.Size > 0 && len(a.Members) > 0 && bits != 8*a.Size {
			v.add(Error, e.Line, s.Name, "Assem%d: members of %d bits for %d octets", a.Number, bits, a.Size)
		}
		if raw := e.Field(1).Value; strings.TrimSpace(raw) != "" && a.Path == nil {
			v.add(Error, e.Line, s.Name, "Assem%d: path %q", a.Number, raw)
		}
	}
}

func (v *validator) connections() {
	s := v.f.Section("Connection Manager")
	if s == nil {
		return
	}
	cs, err := v.f.Connections()
	if err != nil {
		v.add(Error, s.Line, s.Name, "%v", err)
		return
	}
	for _, c := range cs {
		e, _ := s.Entry("Connection" + strconv.Itoa(c.Number))
		for _, ref := range []string{c.OTRPI, c.OTSize, c.OTFormat, c.TORPI, c.TOSize, c.TOFormat, c.ConfigSize, c.ConfigFormat} {
			if reRef.MatchString(ref) && !v.exists(ref) {
				v.add(Error, e.Line, s.Name, "Connection%d: %s does not exist", c.Number, ref)
			}
		}
		if c.Path == nil && !strings.Contains(c.PathText, "[") {
			v.add(Error, e.Line, s.Name, "Connection%d: path %q", c.Number, c.PathText)
		}
		if c.Class() < 0 {
			v.add(Warning, e.Line, s.Name, "Connection%d: no transport class", c.Number)
		}
	}
}
