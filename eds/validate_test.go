// SPDX-License-Identifier: MIT

package eds

import (
	"strings"
	"testing"
)

const (
	validFile = `[File]
	DescText = "d";
	CreateDate = 10-25-2026;
	CreateTime = 12:00:00;
	Revision = 1.0;
`
	validDevice = `[Device]
	VendCode = 1;
	ProdType = 12;
	ProdCode = 2;
	MajRev = 1;
	MinRev = 0;
	ProdName = "p";
`
	validClass = `[Device Classification]
	Class1 = EtherNetIP;
`
	valid = validFile + validDevice + validClass
)

// param returns a ParamN entry of type t and size n with min, max, default.
func param(num, t, n, name, lim string) string {
	return "\tParam" + num + " = 0, ,, 0x0000, " + t + ", " + n + ", " + name + ", \"\", \"\", " + lim + ", ,,,, ,,,, ;\n"
}

func TestValidateClean(t *testing.T) {
	for _, src := range []string{
		valid,
		readTestdata(t, "otfabric_adapter.eds"),
		readTestdata(t, "drive.eds"),
		valid + "[Params]\n" + param("1", "0xC3", "2", `"Signed hex"`, "0xFF9C, 0x0064, 0xFFFF") +
			param("2", "0xC4", "4", `"Full range"`, "0x80000000, 0x7FFFFFFF, 0") +
			param("3", "0xC3", "2", `"Too wide stays unsigned"`, "0, 0x10000, 0x10000") +
			param("4", "0xC5", "8", `"LINT"`, "0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF") +
			param("5", "0xD0", "0", `"String"`, `"a", "z", x`) +
			param("6", "0xCA", "4", `"Float"`, "-1.5, 1e3, ") +
			"[Connection Manager]\n\tConnection1 = 1, 0, ,,, ,,, ,,,, \"c\", \"\", \"20 04 24 [Param1] 2C 01\";\n",
	} {
		for _, is := range Validate(mustParse(t, src)) {
			if is.Severity == Error || src == valid {
				t.Errorf("%s\nin\n%s", is, src)
			}
		}
	}
}

// TestValidateRule checks each rule with a file that breaks only it.
func TestValidateRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string // Issue.String of the expected issue
	}{
		{"no sections", "", "error: line 0 []: no sections"},
		{"first not File", validDevice + validFile + validClass, "error: line 1 [Device]: the first section must be [File]"},
		{"second not Device", validFile + validClass + validDevice, "warning: line 0 []: the second section should be [Device]"},
		{"only File", validFile, "error: line 0 [Device]: no [Device] section"},
		{"no File", "[Other]\n" + validDevice, "error: line 0 [File]: no [File] section"},
		{"missing DescText", strings.Replace(valid, "DescText", "Desc", 1), "error: line 1 [File]: DescText missing"},
		{"missing CreateTime", strings.Replace(valid, "CreateTime", "Time", 1), "error: line 1 [File]: CreateTime missing"},
		{"bad date", strings.Replace(valid, "10-25-2026", "13-01-2026", 1), `error: line 3 [File]: CreateDate "13-01-2026" is not a date (mm-dd-yyyy)`},
		{"ISO date", strings.Replace(valid, "10-25-2026", "2026-10-25", 1), `CreateDate "2026-10-25" is not a date`},
		{"bad ModDate", strings.Replace(valid, "Revision", "ModDate = 02-30-2026;\n\tRevision", 1), `ModDate "02-30-2026" is not a date`},
		{"bad time", strings.Replace(valid, "12:00:00", "24:00:00", 1), `error: line 4 [File]: CreateTime "24:00:00" is not a time (hh:mm:ss)`},
		{"short time", strings.Replace(valid, "12:00:00", "12:00", 1), `CreateTime "12:00" is not a time`},
		{"bad ModTime", strings.Replace(valid, "Revision", "ModTime = \"x\";\n\tRevision", 1), `ModTime "x" is not a time`},
		{"revision without minor", strings.Replace(valid, "1.0", "1", 1), `error: line 5 [File]: Revision "1" is not major.minor`},
		{"revision not numbers", strings.Replace(valid, "1.0", "a.b", 1), `Revision "a.b" is not major.minor`},
		{"revision too large", strings.Replace(valid, "1.0", "1.256", 1), `Revision "1.256" is not major.minor`},
		{"missing VendCode", strings.Replace(valid, "VendCode", "Vend", 1), "error: line 6 [Device]: VendCode missing"},
		{"missing ProdName", strings.Replace(valid, "ProdName", "Name", 1), "error: line 6 [Device]: ProdName missing"},
		{"VendCode too large", strings.Replace(valid, "VendCode = 1", "VendCode = 65536", 1), "error: line 7 [Device]: VendCode: not a 16-bit number: 65536"},
		{"MinRev not a number", strings.Replace(valid, "MinRev = 0", "MinRev = x", 1), "MinRev: not a 8-bit number: x"},
		{"long ProdName", strings.Replace(valid, `"p"`, `"`+strings.Repeat("p", 33)+`"`, 1), "warning: line 12 [Device]: ProdName longer than 32 characters"},
		{"no Device Classification", validFile + validDevice, "warning: line 0 [Device Classification]: no [Device Classification] section (EtherNetIP)"},
		{"no EtherNetIP class", validFile + validDevice + "[Device Classification]\n\tClass1 = DeviceNet;\n", "warning: line 13 [Device Classification]: no class EtherNetIP"},
		{"duplicate keyword", valid + "[Port]\n\tPort1 = 1;\n\tport1 = 2;\n", "error: line 17 [Port]: port1 repeats the entry of line 16"},
		{"bad Params", valid + "[Params]\n\tParam1 = 0, ,, 0, x, 1;\n", "error: line 15 [Params]: eds: line 16: Param1 data type: not a 8-bit number: x"},
		{"unknown data type", valid + "[Params]\n" + param("1", "0xFF", "1", `"n"`, ",,"), "error: line 16 [Params]: Param1: data type 0xFF is not an elementary type"},
		{"size mismatch", valid + "[Params]\n" + param("1", "0xC4", "2", `"n"`, ",,"), "error: line 16 [Params]: Param1: data size 2, DINT has 4"},
		{"no name", valid + "[Params]\n" + param("1", "0xC6", "1", `""`, ",,"), "warning: line 16 [Params]: Param1 has no name"},
		{"min not a number", valid + "[Params]\n" + param("1", "0xC6", "1", `"n"`, "low, 1, 0"), `error: line 16 [Params]: Param1: minimum "low" is not a number`},
		{"max not a number", valid + "[Params]\n" + param("1", "0xCA", "4", `"n"`, `0, one, 0`), `Param1: maximum "one" is not a number`},
		{"default not a number", valid + "[Params]\n" + param("1", "0xC6", "1", `"n"`, "0, 1, 0xZZ"), `Param1: default "0xZZ" is not a number`},
		{"min above max", valid + "[Params]\n" + param("1", "0xC6", "1", `"n"`, "10, 1, "), "error: line 16 [Params]: Param1: minimum above maximum"},
		{"signed hex min above max", valid + "[Params]\n" + param("1", "0xC2", "1", `"n"`, "0x01, 0xFF, "), "Param1: minimum above maximum"},
		{"default below min", valid + "[Params]\n" + param("1", "0xC6", "1", `"n"`, "10, 20, 5"), "error: line 16 [Params]: Param1: default outside minimum and maximum"},
		{"default above max", valid + "[Params]\n" + param("1", "0xC6", "1", `"n"`, ", 20, 0x15"), "Param1: default outside minimum and maximum"},
		{"bad Assembly", valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24\", 1;\n", "error: line 15 [Assembly]: eds: line 16: Assem1 path: "},
		{"missing member", valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24 01\", 1, 0, ,, 8, Param1;\n", "error: line 16 [Assembly]: Assem1: member Param1 does not exist"},
		{"member not a reference", valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24 01\", 1, 0, ,, 8, Speed;\n", "Assem1: member Speed does not exist"},
		{"member of missing section", valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24 01\", 2, 0, ,, 8, Param1, 8, Assem1;\n", "Assem1: member Param1 does not exist"},
		{"member bits", valid + "[Assembly]\n\tAssem1 = \"a\", \"20 04 24 01\", 2, 0, ,, 8, , 4, ;\n", "error: line 16 [Assembly]: Assem1: members of 12 bits for 2 octets"},
		{"bad Connection Manager", valid + "[Connection Manager]\n\tConnection1 = x, 0;\n", "error: line 15 [Connection Manager]: eds: line 16: Connection1 field 1: not a 32-bit number: x"},
		{"missing RPI param", valid + "[Connection Manager]\n\tConnection1 = 2, 0, Param9, 0, , , , , , , , , \"c\", \"\", \"20 04 24 01\";\n", "error: line 16 [Connection Manager]: Connection1: Param9 does not exist"},
		{"missing format assembly", valid + "[Params]\n" + param("1", "0xC8", "4", `"RPI"`, ",,") + "[Connection Manager]\n\tConnection1 = 2, 0, Param1, 0, Assem2, , , , , , Connection3, ProxyAssem4, \"c\", \"\", \"20 04 24 01\";\n", "Connection1: Assem2 does not exist"},
		{"missing config connection", valid + "[Connection Manager]\n\tConnection1 = 2, 0, , , , , , , , , Connection3, ProxyAssem4, \"c\", \"\", \"20 04 24 01\";\n", "Connection1: Connection3 does not exist"},
		{"missing proxy assembly", valid + "[Assembly]\n[Connection Manager]\n\tConnection1 = 2, 0, , , , , , , , , , ProxyAssem4, \"c\", \"\", \"20 04 24 01\";\n", "Connection1: ProxyAssem4 does not exist"},
		{"bad connection path", valid + "[Connection Manager]\n\tConnection1 = 2, 0, , , , , , , , , , , \"c\", \"\", \"20 04 2\";\n", `error: line 16 [Connection Manager]: Connection1: path "20 04 2"`},
		{"no connection path", valid + "[Connection Manager]\n\tConnection1 = 2, 0;\n", `Connection1: path ""`},
		{"no transport class", valid + "[Connection Manager]\n\tConnection1 = 0x04010000, 0, , , , , , , , , , , \"c\", \"\", \"20 04 24 01\";\n", "warning: line 16 [Connection Manager]: Connection1: no transport class"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := Validate(mustParse(t, tc.src))
			var all []string
			found := false
			for _, is := range issues {
				all = append(all, is.String())
				if strings.Contains(is.String(), tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no issue %q in\n%s", tc.want, strings.Join(all, "\n"))
			}
		})
	}
}

func TestValidateReferences(t *testing.T) {
	src := valid + `[Params]
` + param("1", "0xC8", "4", `"RPI"`, ",,") + `	Enum1 = 1, "one";
[Assembly]
	Assem1 = "a", "20 04 24 01", 4, 0, ,, 32, Param1;
	Assem2 = "b", "20 04 24 02", 6, 0, ,, 32, Assem1, 16, ;
	ProxyAssem3 = "p", "20 04 24 03", 0;
[Connection Manager]
	Connection1 = 2, 0, Param1, Assem1, Assem1, Param1, 6, Assem2, , , Enum1, ProxyAssem3, "c", "", "20 04 24 01 2C 01 2C 02";
	Connection2 = 1, 0, 5000, 4, Connection1, , , , , , , , "d", "", "20 04 2C 01 2C 02";
`
	for _, is := range Validate(mustParse(t, src)) {
		t.Errorf("%s", is)
	}
}

func TestValidateOrder(t *testing.T) {
	// Errors come first, warnings after them, each in the order found.
	src := validFile + strings.Replace(validDevice, `"p"`, `"`+strings.Repeat("p", 40)+`"`, 1) +
		"[Port]\n\tA = 1;\n\tA = 2;\n"
	issues := Validate(mustParse(t, src))
	var sev []Severity
	for _, is := range issues {
		sev = append(sev, is.Severity)
	}
	want := []Severity{Error, Warning, Warning}
	if len(sev) != len(want) {
		t.Fatalf("%v", issues)
	}
	for i := range want {
		if sev[i] != want[i] {
			t.Fatalf("%v", issues)
		}
	}
}

func TestSeverityAndIssueString(t *testing.T) {
	if Error.String() != "error" || Warning.String() != "warning" || Severity(0).String() != "warning" {
		t.Errorf("%s %s %s", Error, Warning, Severity(0))
	}
	is := Issue{Severity: Error, Line: 4, Section: "Device", Message: "VendCode missing"}
	if got := is.String(); got != "error: line 4 [Device]: VendCode missing" {
		t.Errorf("%s", got)
	}
}
