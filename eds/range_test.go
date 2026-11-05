// SPDX-License-Identifier: MIT

package eds

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
)

// TestDeviceRange checks that every identity keyword takes the largest
// value of its field and rejects the next one, naming the keyword and
// the line, instead of truncating it to a wrong identity.
func TestDeviceRange(t *testing.T) {
	base := map[string]string{"VendCode": "1", "ProdType": "2", "ProdCode": "3", "MajRev": "1", "MinRev": "0"}
	order := []string{"VendCode", "ProdType", "ProdCode", "MajRev", "MinRev"}
	src := func(kw, v string) string {
		var sb strings.Builder
		sb.WriteString("[Device]\n")
		for _, k := range order {
			x := base[k]
			if k == kw {
				x = v
			}
			fmt.Fprintf(&sb, "%s=%s;\n", k, x)
		}
		return sb.String()
	}
	for _, tc := range []struct {
		kw        string
		bits      int
		max, over string
		line      int
	}{
		{"VendCode", 16, "65535", "65536", 2},
		{"ProdType", 16, "0xFFFF", "0x10000", 3},
		{"ProdCode", 16, "65535", "70000", 4},
		{"MajRev", 8, "255", "300", 5},
		{"MinRev", 8, "0xFF", "256", 6},
		{"MinRev", 8, "255", "18446744073709551616", 6},
	} {
		d, err := mustParse(t, src(tc.kw, tc.max)).Device()
		if err != nil {
			t.Fatalf("%s=%s: %v", tc.kw, tc.max, err)
		}
		want := uint64(1)<<tc.bits - 1
		got := map[string]uint64{"VendCode": uint64(d.VendorID), "ProdType": uint64(d.DeviceType),
			"ProdCode": uint64(d.ProductCode), "MajRev": uint64(d.Revision.Major), "MinRev": uint64(d.Revision.Minor)}[tc.kw]
		if got != want {
			t.Errorf("%s=%s: %d, want %d", tc.kw, tc.max, got, want)
		}
		_, err = mustParse(t, src(tc.kw, tc.over)).Device()
		msg := fmt.Sprintf("eds: line %d: [Device] %s: not a %d-bit number: %s", tc.line, tc.kw, tc.bits, tc.over)
		if err == nil || err.Error() != msg {
			t.Errorf("%s=%s: %v, want %q", tc.kw, tc.over, err, msg)
		}
		// Validate reports the same entry as an error.
		found := false
		for _, is := range Validate(mustParse(t, src(tc.kw, tc.over))) {
			found = found || (is.Severity == Error && is.Line == tc.line && strings.Contains(is.Message, tc.kw))
		}
		if !found {
			t.Errorf("%s=%s: Validate does not report it", tc.kw, tc.over)
		}
	}
}

func TestParamRange(t *testing.T) {
	for _, tc := range []struct{ entry, msg string }{
		{`Param1 = 0, ,, 0xFFFF, 0xFF, 65535;`, ""},
		{`Param1 = 0, ,, 0, 0xC6, 65536;`, "line 2: Param1 data size: not a 16-bit number: 65536"},
		{`Param1 = 0, ,, 0, 0xC6, 0xFFFFFFFFFFFFFFFF;`, "Param1 data size: not a 16-bit number"},
		{`Param1 = 0, ,, 0, 256, 1;`, "Param1 data type: not a 8-bit number: 256"},
		{`Param1 = 0, ,, 65536, 0xC6, 1;`, "Param1 descriptor: not a 16-bit number: 65536"},
	} {
		ps, err := mustParse(t, "[Params]\n"+tc.entry).Params()
		if tc.msg == "" {
			if err != nil || len(ps) != 1 || ps[0].Size != 65535 || ps[0].Descriptor != 0xFFFF || ps[0].Type != 0xFF {
				t.Errorf("%s: %+v %v", tc.entry, ps, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v, want %q", tc.entry, err, tc.msg)
		}
	}
}

func TestAssemblyRange(t *testing.T) {
	maxBits := fmt.Sprint(8 * MaxAssemblySize)
	as, err := mustParse(t, `[Assembly]
Assem1 = "a", "20 04 24 01", 65535, 0xFFFF, ,, `+maxBits+`, ;`).Assemblies()
	if err != nil || len(as) != 1 || as[0].Size != MaxAssemblySize || as[0].Descriptor != 0xFFFF || as[0].Members[0].Bits != 8*MaxAssemblySize {
		t.Fatalf("%+v %v", as, err)
	}
	for _, tc := range []struct{ entry, msg string }{
		{`Assem1 = "a", "20 04 24 01", 65536;`, "line 2: Assem1 size: not a 16-bit number: 65536"},
		{`Assem1 = "a", "20 04 24 01", 1, 65536;`, "Assem1 descriptor: not a 16-bit number: 65536"},
		{`Assem1 = "a", "20 04 24 01", 0, 0, ,, ` + fmt.Sprint(8*MaxAssemblySize+1) + `, ;`,
			fmt.Sprintf("line 2: Assem1 member size: %d is above %d", 8*MaxAssemblySize+1, 8*MaxAssemblySize)},
		{`Assem1 = "a", "20 04 24 01", 0, 0, ,, 0xFFFFFFFF, ;`, "Assem1 member size: 0xFFFFFFFF is above"},
		{`Assem1 = "a", "20 04 24 01", 0, 0, ,, 0x100000000, ;`, "Assem1 member size: not a 32-bit number: 0x100000000"},
	} {
		_, err := mustParse(t, "[Assembly]\n"+tc.entry).Assemblies()
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v, want %q", tc.entry, err, tc.msg)
		}
	}
}

func TestConnectionRange(t *testing.T) {
	cs, err := mustParse(t, "[Connection Manager]\nConnection1 = 0xFFFFFFFF, 4294967295;").Connections()
	if err != nil || len(cs) != 1 || cs[0].TriggerTransport != math.MaxUint32 || cs[0].Params != math.MaxUint32 {
		t.Fatalf("%+v %v", cs, err)
	}
	_, err = mustParse(t, "[Connection Manager]\nConnection1 = 1, 4294967296;").Connections()
	if want := "line 2: Connection1 field 2: not a 32-bit number: 4294967296"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v, want %q", err, want)
	}
}

func TestSignExtend(t *testing.T) {
	for _, tc := range []struct {
		u    uint64
		bits int
		want int64
	}{
		{0xFF, 8, -1},
		{0x7F, 8, 127},
		{0x80, 8, -128},
		{0x1FF, 8, -1},
		{0xFFFF, 16, -1},
		{0x8000, 16, -32768},
		{0x7FFFFFFF, 32, math.MaxInt32},
		{0x80000000, 32, math.MinInt32},
		{math.MaxUint64, 64, -1},
		{1 << 63, 64, math.MinInt64},
		{math.MaxInt64, 64, math.MaxInt64},
		{0, 64, 0},
		{1, 1, -1},
	} {
		if got := signExtend(tc.u, tc.bits); got != tc.want {
			t.Errorf("signExtend(%#x, %d) = %d, want %d", tc.u, tc.bits, got, tc.want)
		}
	}
}

// TestGenerateLargeLayout checks that members adding up to more than the
// largest assembly get no struct, whose Encode would allocate it.
func TestGenerateLargeLayout(t *testing.T) {
	maxBits := fmt.Sprint(8 * MaxAssemblySize)
	src := valid + "[Assembly]\n\tAssem1 = \"Big\", \"20 04 24 01\", 0, 0, ,, " + maxBits + ", , 8, ;\n"
	out := generate(t, src)
	if !bytes.Contains(out, []byte("no struct is generated")) || bytes.Contains(out, []byte("Encode()")) {
		t.Errorf("a layout beyond %d octets has a struct:\n%s", MaxAssemblySize, out)
	}
}
