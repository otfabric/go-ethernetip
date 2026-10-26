// SPDX-License-Identifier: MIT

package eds

import (
	"fmt"
	"go/ast"
	"go/importer"
	goparser "go/parser"
	"go/token"
	"go/types"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func mustParse(t testing.TB, s string) *File {
	t.Helper()
	f, err := ParseString(s)
	if err != nil {
		t.Fatalf("ParseString: %v\n%s", err, s)
	}
	return f
}

func readTestdata(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// shape returns the sections of f without line numbers, for structural
// comparison.
func shape(f *File) []Section {
	out := make([]Section, len(f.Sections))
	for i, s := range f.Sections {
		out[i] = Section{Name: s.Name}
		for _, e := range s.Entries {
			e.Line = 0
			out[i].Entries = append(out[i].Entries, e)
		}
	}
	return out
}

func sameShape(a, b *File) bool { return reflect.DeepEqual(shape(a), shape(b)) }

// The importer that type-checks generated code: it reads the packages of
// this module and the standard library from source, once per test binary.
var (
	typeFset     = token.NewFileSet()
	typeImporter types.Importer
	typeMu       sync.Mutex
)

// typeCheck parses and type-checks generated source as a package of its
// own and returns its syntax and scope.
func typeCheck(t testing.TB, src []byte) (*ast.File, *types.Scope) {
	t.Helper()
	typeMu.Lock()
	defer typeMu.Unlock()
	if typeImporter == nil {
		typeImporter = importer.ForCompiler(typeFset, "source", nil)
	}
	file, err := goparser.ParseFile(typeFset, "gen.go", src, goparser.ParseComments)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\n%s", err, withLines(src))
	}
	conf := types.Config{Importer: typeImporter}
	pkg, err := conf.Check(file.Name.Name, typeFset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatalf("generated code does not type-check: %v\n%s", err, withLines(src))
	}
	return file, pkg.Scope()
}

// withLines numbers the lines of src for a failure message.
func withLines(src []byte) string {
	var sb strings.Builder
	for i, l := range strings.Split(string(src), "\n") {
		fmt.Fprintf(&sb, "%4d  %s\n", i+1, l)
	}
	return sb.String()
}
