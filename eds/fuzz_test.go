// SPDX-License-Identifier: MIT

package eds

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob("testdata/*.eds")
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(b))
	}
	for _, s := range []string{
		"",
		"\uFEFF[File]\nK = 1;",
		"[A]\nK = \"a\" \"b\", , {1, {2}}, 0x10, -4;",
		"[A]\nK = \"\\\\\", \"\\\"\";",
		"[A]\nK = ;\nL = , ;",
		valid,
		valid + "[Params]\n" + param("1", "0xC3", "2", `"n"`, "0xFF9C, 0x64, 0xFFFF") + "\tEnum1 = 0, \"a\", 0, \"b\";\n",
		valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24 01\", 2, 0, ,, 8, Param1, 8, ;\n",
		valid + "[Connection Manager]\n\tConnection1 = 1, 0, 1e30, Assem1, , , , , , , , , \"c\", \"\", \"20 04 2C 01 2C 02\";\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		file, err := ParseString(s)
		if err != nil {
			return
		}
		out := file.Format()
		again, err := ParseString(out)
		if err != nil {
			t.Fatalf("Format output does not parse: %v\n%q", err, out)
		}
		if !sameShape(file, again) {
			t.Fatalf("Parse(Format(f)) differs from f\n%q", out)
		}
		if out2 := again.Format(); out2 != out {
			t.Fatalf("Format is not stable:\n%q\n%q", out, out2)
		}
		Validate(file)
		_, _ = file.Device()
		_, _ = file.Params()
		_, _ = file.Assemblies()
		if cs, err := file.Connections(); err == nil {
			for _, c := range cs {
				c.Class()
			}
		}
		_, _ = GenerateGo(file, GenerateOptions{})
	})
}
