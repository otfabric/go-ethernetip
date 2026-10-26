//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// The adapter fixture: what go-ethernetip serves to the reference
// originators.
const (
	adapterVendor  = 65535
	adapterProduct = 42
	adapterName    = "OT Fabric interop adapter"
	adapterNameHex = "194f542046616272696320696e7465726f702061646170746572"
)

// TestEIPScannerToGoAdapter runs EIPScanner against go-ethernetip's target.
func TestEIPScannerToGoAdapter(t *testing.T) {
	node := startNode(t, image("eipscanner"), "adapter")
	img, host := image("eipscanner"), node.ip
	const dir, name = "ref->go", "eipscanner"

	t.Run("ListIdentityUDP", func(t *testing.T) {
		record(t, "ListIdentity (UDP)", dir, name, "")
		r := client(t, img, "list-identity", "--host", host)
		id := r.obj("identity")
		if !r.ok() || id.num("vendorId") != adapterVendor || id.num("productCode") != adapterProduct || id.str("productName") != adapterName ||
			id.str("socketAddress") != host+":44818" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("GetAttributeSingle", func(t *testing.T) {
		record(t, "Get_Attribute_Single (16-bit logical segments)", dir, name, "EIPScanner packs 16-bit class/instance/attribute segments")
		r := client(t, img, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7")
		if !r.ok() || r.num("status") != 0 || r.str("data") != adapterNameHex {
			t.Fatalf("%v", r)
		}
	})
	t.Run("GetAttributesAll", func(t *testing.T) {
		record(t, "Get_Attributes_All (Identity)", dir, name, "")
		r := client(t, img, "get-attributes-all", "--host", host, "--class", "1", "--instance", "1")
		if !r.ok() || !strings.HasPrefix(r.str("data"), "ffff0c002a000307") || !strings.HasSuffix(r.str("data"), adapterNameHex) {
			t.Fatalf("%v", r)
		}
	})
	t.Run("SetAttributeEcho", func(t *testing.T) {
		record(t, "Set_Attribute_Single (assembly)", dir, name, "")
		data := strings.Repeat("e7", 32)
		if r := client(t, img, "set-attribute", "--host", host, "--class", "4", "--instance", "150", "--attribute", "3", "--data", data); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "get-attribute", "--host", host, "--class", "4", "--instance", "100", "--attribute", "3"); r.str("data") != data {
			t.Fatalf("%v", r)
		}
	})
	t.Run("MultipleService", func(t *testing.T) {
		record(t, "Multiple Service Packet", dir, name, "built by the adapter with EIPScanner's MessageRouterRequest")
		r := client(t, img, "multiple-get", "--host", host, "--path", "@1/1/1", "--path", "@1/1/99", "--path", "@4/100/4")
		reps, _ := r["replies"].([]any)
		if !r.ok() || r.num("status") != 0x1E || len(reps) != 3 {
			t.Fatalf("%v", r)
		}
		want := []struct {
			st   float64
			data string
		}{{0, "ffff"}, {0x14, ""}, {0, "2000"}}
		for i, w := range want {
			rp := result(reps[i].(map[string]any))
			if rp.num("status") != w.st || rp.str("data") != w.data {
				t.Fatalf("reply %d: %v", i, rp)
			}
		}
	})
	t.Run("Class1ExclusiveOwner", func(t *testing.T) {
		record(t, "Class 1 I/O, exclusive owner, point-to-point", dir, name, "")
		out := strings.Repeat("9d", 32)
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1500", "--output-data", out)
		checkIO(t, r, out)
	})
	t.Run("Class1Large", func(t *testing.T) {
		record(t, "Large_Forward_Open", dir, name, "")
		out := strings.Repeat("d9", 32)
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "20", "--duration-ms", "1000", "--output-data", out, "--large")
		checkIO(t, r, out)
	})
	t.Run("Class1InputOnly", func(t *testing.T) {
		record(t, "Class 1 I/O, input only (heartbeat O->T)", dir, name, "")
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "152", "--input", "100",
			"--output-size", "0", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1000")
		if !r.ok() || r.obj("forwardOpen").num("status") != 0 || r.num("received") < 10 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1WrongSize", func(t *testing.T) {
		record(t, "Forward_Open refusal (connection size)", dir, name, "EIPScanner logs the refusal; the adapter reports refused")
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "31", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100")
		if refused, _ := r.obj("forwardOpen")["refused"].(bool); !r.ok() || !refused {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1ConfigData", func(t *testing.T) {
		record(t, "Class 1 I/O, configuration data", dir, name, "a data segment at the end of EIPScanner's connection path")
		cfg := "a1a2a3a4a5a6a7a8a9aa"
		out := strings.Repeat("4e", 32)
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1000", "--output-data", out, "--config-data", cfg)
		checkIO(t, r, out)
		if r := client(t, img, "get-attribute", "--host", host, "--class", "4", "--instance", "151", "--attribute", "3"); r.str("data") != cfg {
			t.Fatalf("configuration assembly after the Forward_Open: %v", r)
		}
	})
	t.Run("Class1ConfigDataWrongSize", func(t *testing.T) {
		record(t, "Forward_Open refusal (configuration size)", dir, name, "EIPScanner logs the refusal; the adapter reports refused")
		r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100", "--config-data", "0102")
		if refused, _ := r.obj("forwardOpen")["refused"].(bool); !r.ok() || !refused {
			t.Fatalf("%v", r)
		}
	})
	notApplicable("Class 1 I/O, listen-only (multicast, next to its owner)", dir, name, "EIPScanner does not join multicast groups")
	notApplicable("Class 3 connected explicit messaging", dir, name, "EIPScanner has no SendUnitData sender")
	notApplicable("Class 1 I/O, T->O multicast", dir, name, "EIPScanner does not join multicast groups")
	notApplicable("Logix tag services", dir, name, "EIPScanner has no symbolic segments")
}

// TestPycomm3ToGoAdapter runs pycomm3's generic CIP driver against
// go-ethernetip's target.
func TestPycomm3ToGoAdapter(t *testing.T) {
	node := startNode(t, image("pycomm3"), "adapter")
	img, host := image("pycomm3"), node.ip
	const dir, name = "ref->go", "pycomm3"

	identity := func(t *testing.T, r result) {
		t.Helper()
		id := r.obj("identity")
		if !r.ok() || id.num("productCode") != adapterProduct || id.str("productName") != adapterName || id.str("revision") != "3.7" ||
			id.num("serialNumber") != 305419896 {
			t.Fatalf("%v", r)
		}
	}
	t.Run("ListIdentityTCP", func(t *testing.T) {
		record(t, "ListIdentity (TCP)", dir, name, "")
		identity(t, client(t, img, "list-identity", "--host", host))
	})
	t.Run("ListIdentityUDP", func(t *testing.T) {
		record(t, "ListIdentity (UDP)", dir, name, "pycomm3 discover() to the adapter's address")
		identity(t, client(t, img, "discover", "--host", host))
	})
	for _, connected := range []bool{false, true} {
		suffix, feature, extra := "Unconnected", "Get_Attribute_Single", []string{}
		if connected {
			suffix, feature, extra = "Connected", "Class 3 connected explicit messaging (Large_Forward_Open)", []string{"--connected"}
		}
		t.Run("GetAttribute"+suffix, func(t *testing.T) {
			record(t, feature, dir, name, "")
			r := client(t, img, "get-attribute", append([]string{"--host", host, "--class", "1", "--instance", "1", "--attribute", "7"}, extra...)...)
			if !r.ok() || r.num("status") != 0 || r.str("data") != adapterNameHex {
				t.Fatalf("%v", r)
			}
		})
	}
	t.Run("SetAttributeEcho", func(t *testing.T) {
		record(t, "Set_Attribute_Single (assembly)", dir, name, "")
		data := strings.Repeat("71", 32)
		if r := client(t, img, "set-attribute", "--host", host, "--class", "4", "--instance", "150", "--attribute", "3", "--data", data); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "get-attributes-all", "--host", host, "--class", "4", "--instance", "100", "--connected"); r.str("data") != data {
			t.Fatalf("%v", r)
		}
	})
	t.Run("AttributeNotSupported", func(t *testing.T) {
		record(t, "Error responses (unknown class, attribute)", dir, name, "")
		if r := client(t, img, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "99"); r.num("status") != 0x14 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "get-attribute", "--host", host, "--class", "0x99", "--instance", "1", "--attribute", "1"); r.num("status") != 0x05 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("UnconnectedSendModuleInfo", func(t *testing.T) {
		record(t, "Unconnected_Send routing (backplane slot 0)", dir, name, "pycomm3 get_module_info(0)")
		r := client(t, img, "identity", "--host", host)
		m := r.obj("module")
		if !r.ok() || m.str("product_name") != adapterName || m.num("product_code") != adapterProduct {
			t.Fatalf("%v", r)
		}
	})
	notApplicable("Class 1 I/O, exclusive owner, point-to-point", dir, name, "pycomm3 has no implicit messaging")
}

// TestPycomm3ToGoLogix runs pycomm3's LogixDriver against go-ethernetip's
// Logix emulation (logix.TagServer) serving the logix fixture.
func TestPycomm3ToGoLogix(t *testing.T) {
	node := startNode(t, image("pycomm3"), "logix")
	img, host := image("pycomm3"), node.ip
	const dir, name = "ref->go", "pycomm3"

	t.Run("TagList", func(t *testing.T) {
		record(t, "Logix tag list (0x55) and LogixDriver open", dir, name, "pycomm3 uploads the tag list on open: Unconnected_Send, Large_Forward_Open, program name, 0x55 with continuation")
		r := client(t, img, "tag-list", "--host", host)
		tags, _ := r["tags"].([]any)
		if !r.ok() || len(tags) != 10 || r.str("programName") != "logix" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("ReadAtomic", func(t *testing.T) {
		record(t, "Logix Read Tag (atomic types)", dir, name, "")
		r := client(t, img, "read-tags", "--host", host, "--tags", "Counter,Temperature,Small,Word,Big,Ratio,Running")
		res, _ := r["results"].([]any)
		want := []any{42.0, 21.5, -7.0, 1234.0, 1099511627776.0, 0.125, true}
		if !r.ok() || len(res) != len(want) {
			t.Fatalf("%v", r)
		}
		for i, w := range want {
			rr := result(res[i].(map[string]any))
			vals, _ := rr["values"].([]any)
			if rr["errorText"] != nil || len(vals) != 1 || vals[0] != w {
				t.Fatalf("tag %d: %v, want %v", i, rr, w)
			}
		}
	})
	t.Run("ReadFragmented", func(t *testing.T) {
		record(t, "Logix Read Tag Fragmented (1200 octets)", dir, name, "")
		r := client(t, img, "read-tag", "--host", host, "--tag", "Samples", "--count", "300")
		vals, _ := r["values"].([]any)
		if !r.ok() || r.num("status") != 0 || len(vals) != 300 || vals[0] != -1000.0 || vals[299] != float64(299*7-1000) {
			t.Fatalf("%v", r)
		}
	})
	t.Run("WriteReadBack", func(t *testing.T) {
		record(t, "Logix Write Tag", dir, name, "pycomm3 1.2.16 repeats the request in the message; the emulation ignores the extra octets, as Logix does")
		if r := client(t, img, "write-tag", "--host", host, "--tag", "Counter", "--type", "DINT", "--values", "77"); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "read-tag", "--host", host, "--tag", "Counter"); fmt.Sprint(r["values"]) != "[77]" {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "write-tag", "--host", host, "--tag", "Speeds", "--type", "INT", "--values", "5,6,7"); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "read-tag", "--host", host, "--tag", "Speeds", "--count", "4"); fmt.Sprint(r["values"]) != "[5 6 7 9]" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("WriteFragmented", func(t *testing.T) {
		record(t, "Logix Write Tag Fragmented (1200 octets)", dir, name, "pycomm3 splits a write larger than its connection size into Write Tag Fragmented (0x53)")
		vals := make([]string, 300)
		for i := range vals {
			vals[i] = fmt.Sprint(i*11 - 1500)
		}
		if r := client(t, img, "write-tag", "--host", host, "--tag", "Samples", "--type", "DINT", "--values", strings.Join(vals, ",")); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		r := client(t, img, "read-tag", "--host", host, "--tag", "Samples", "--count", "300")
		got, _ := r["values"].([]any)
		if len(got) != 300 || got[0] != -1500.0 || got[299] != float64(299*11-1500) {
			t.Fatalf("%v", r)
		}
	})
}

// TestPycomm3ToGoStructures runs pycomm3's LogixDriver against the Logix
// emulation serving the logix-structures fixture: bit writes, structures
// (template upload) and STRING.
func TestPycomm3ToGoStructures(t *testing.T) {
	node := startNode(t, image("pycomm3"), "logix-structures")
	img, host := image("pycomm3"), node.ip
	const dir, name = "ref->go", "pycomm3"
	read := func(t *testing.T, tag string, count int) []any {
		t.Helper()
		r := client(t, img, "read-tag", "--host", host, "--tag", tag, "--count", fmt.Sprint(count))
		vals, _ := r["values"].([]any)
		if !r.ok() || r.num("status") != 0 {
			t.Fatalf("read %s: %v", tag, r)
		}
		return vals
	}
	write := func(t *testing.T, tag, typ, values string) {
		t.Helper()
		if r := client(t, img, "write-tag", "--host", host, "--tag", tag, "--type", typ, "--values", values); !r.ok() || r.num("status") != 0 {
			t.Fatalf("write %s: %v", tag, r)
		}
	}
	t.Run("TagList", func(t *testing.T) {
		record(t, "Logix tag list with structure and STRING tags", dir, name, "pycomm3 uploads the Motor template (Get_Attribute_List and Read Template on class 0x6C) on open")
		r := client(t, img, "tag-list", "--host", host)
		types := map[string]string{}
		tags, _ := r["tags"].([]any)
		for _, x := range tags {
			tg := result(x.(map[string]any))
			types[tg.str("name")] = tg.str("type")
		}
		if !r.ok() || types["Pump"] != "Motor" || types["Fans"] != "Motor" || types["Message"] != "STRING" || types["Flags"] != "DINT" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("BitWrite", func(t *testing.T) {
		record(t, "Logix bit write (Read Modify Write Tag)", dir, name, "pycomm3 writes Flags.N with service 0x4E")
		write(t, "Flags.3", "BOOL", "true")
		write(t, "Flags.0", "BOOL", "1")
		if v := read(t, "Flags", 1); fmt.Sprint(v) != "[9]" {
			t.Fatalf("Flags = %v", v)
		}
		write(t, "Flags.3", "BOOL", "false")
		write(t, "Flags.31", "BOOL", "true")
		if v := read(t, "Flags", 1); fmt.Sprint(v) != fmt.Sprint([]any{float64(int32(-2147483647))}) {
			t.Fatalf("Flags = %v", v)
		}
	})
	t.Run("BoolArrayBitWrite", func(t *testing.T) {
		record(t, "Logix BOOL array element write", dir, name, "pycomm3 writes Bits[N] with Read Modify Write on the DWORD holding it")
		write(t, "Bits[37]", "BOOL", "true")
		if v := read(t, "Bits[37]", 1); fmt.Sprint(v) != "[true]" {
			t.Fatalf("Bits[37] = %v", v)
		}
		if v := read(t, "Bits[36]", 1); fmt.Sprint(v) != "[false]" {
			t.Fatalf("Bits[36] = %v", v)
		}
	})
	t.Run("StructRead", func(t *testing.T) {
		record(t, "Logix structure read (UDT)", dir, name, "BOOL members in a hidden host SINT, an INT array and a nested STRING")
		v := read(t, "Pump", 1)
		want := "[map[Current:2.5 Enabled:true Faulted:false Label:pump Setpoints:[10 20 30 40] Speed:1500]]"
		if fmt.Sprint(v) != want {
			t.Fatalf("Pump = %v, want %s", v, want)
		}
		v = read(t, "Fans", 2)
		if len(v) != 2 || fmt.Sprint(v[1]) != "map[Current:1.25 Enabled:true Faulted:false Label:fan-b Setpoints:[5 6 7 8] Speed:900]" {
			t.Fatalf("Fans = %v", v)
		}
		if v := read(t, "Fans[0].Label", 1); fmt.Sprint(v) != "[fan-a]" {
			t.Fatalf("Fans[0].Label = %v", v)
		}
	})
	t.Run("StructWrite", func(t *testing.T) {
		record(t, "Logix structure write (UDT)", dir, name, "a whole structure, then one member")
		write(t, "Pump", "JSON", `{"Enabled": false, "Faulted": true, "Speed": -5, "Current": 0.5, "Setpoints": [4, 3, 2, 1], "Label": "renamed"}`)
		want := "[map[Current:0.5 Enabled:false Faulted:true Label:renamed Setpoints:[4 3 2 1] Speed:-5]]"
		if v := read(t, "Pump", 1); fmt.Sprint(v) != want {
			t.Fatalf("Pump = %v, want %s", v, want)
		}
		write(t, "Pump.Speed", "DINT", "1800")
		if v := read(t, "Pump.Speed", 1); fmt.Sprint(v) != "[1800]" {
			t.Fatalf("Pump.Speed = %v", v)
		}
		write(t, "Pump.Enabled", "BOOL", "true")
		if v := read(t, "Pump.Enabled", 1); fmt.Sprint(v) != "[true]" {
			t.Fatalf("Pump.Enabled = %v", v)
		}
	})
	t.Run("String", func(t *testing.T) {
		record(t, "Logix STRING read and write", dir, name, "")
		if v := read(t, "Message", 1); fmt.Sprint(v) != "[hello]" {
			t.Fatalf("Message = %v", v)
		}
		if v := read(t, "Names", 3); fmt.Sprint(v) != "[alpha beta gamma]" {
			t.Fatalf("Names = %v", v)
		}
		write(t, "Message", "STRING", "written by pycomm3")
		if v := read(t, "Message", 1); fmt.Sprint(v) != "[written by pycomm3]" {
			t.Fatalf("Message = %v", v)
		}
		write(t, "Names[1]", "STRING", "BETA")
		if v := read(t, "Names", 3); fmt.Sprint(v) != "[alpha BETA gamma]" {
			t.Fatalf("Names = %v", v)
		}
	})
}

// TestCpppoToGo runs cpppo's client against go-ethernetip's target and
// Logix emulation.
func TestCpppoToGo(t *testing.T) {
	adapter := startNode(t, image("cpppo"), "adapter")
	lgx := startNode(t, image("cpppo"), "logix")
	img := image("cpppo")
	const dir, name = "ref->go", "cpppo"

	for _, tr := range []string{"tcp", "udp"} {
		t.Run("ListIdentity"+strings.ToUpper(tr), func(t *testing.T) {
			record(t, "ListIdentity ("+strings.ToUpper(tr)+")", dir, name, "")
			r := client(t, img, "list-identity", "--host", adapter.ip, "--transport", tr)
			id := r.obj("identity")
			if !r.ok() || id.num("vendorId") != adapterVendor || id.str("productName") != adapterName || id.str("socketAddress") != adapter.ip+":44818" {
				t.Fatalf("%v", r)
			}
		})
	}
	t.Run("Attributes", func(t *testing.T) {
		record(t, "Get_Attribute_Single", dir, name, "")
		r := client(t, img, "get-attribute", "--host", adapter.ip, "--class", "1", "--instance", "1", "--attribute", "7")
		if !r.ok() || r.str("data") != adapterNameHex {
			t.Fatalf("%v", r)
		}
	})
	t.Run("SetAttributeEcho", func(t *testing.T) {
		record(t, "Set_Attribute_Single (assembly)", dir, name, "")
		data := strings.Repeat("2b", 32)
		if r := client(t, img, "set-attribute", "--host", adapter.ip, "--class", "4", "--instance", "150", "--attribute", "3", "--data", data); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "get-attributes-all", "--host", adapter.ip, "--class", "4", "--instance", "100"); r.str("data") != data {
			t.Fatalf("%v", r)
		}
	})
	t.Run("MultipleService", func(t *testing.T) {
		record(t, "Multiple Service Packet", dir, name, "")
		r := client(t, img, "multiple-get", "--host", adapter.ip, "--path", "@1/1/1", "--path", "@1/1/7")
		reps, _ := r["replies"].([]any)
		if !r.ok() || len(reps) != 2 || result(reps[1].(map[string]any)).str("data") != adapterNameHex {
			t.Fatalf("%v", r)
		}
	})
	t.Run("LogixReadWrite", func(t *testing.T) {
		record(t, "Logix Read Tag (atomic types)", dir, name, "through Unconnected_Send to slot 0")
		r := client(t, img, "read-tags", "--host", lgx.ip, "--tags", "Counter,Temperature,Small")
		if !r.ok() || fmt.Sprint(r["results"]) != "[map[status:0 tag:Counter values:[42]] map[status:0 tag:Temperature values:[21.5]] map[status:0 tag:Small values:[-7]]]" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("LogixFragmented", func(t *testing.T) {
		record(t, "Logix Read Tag Fragmented (1200 octets)", dir, name, "Read Tag Fragmented with byte offsets, continued by the adapter while the target answers 0x06")
		r := client(t, img, "read-tag", "--host", lgx.ip, "--tag", "Samples", "--count", "300", "--type", "DINT")
		vals, _ := r["values"].([]any)
		if !r.ok() || len(vals) != 300 || vals[299] != float64(299*7-1000) {
			t.Fatalf("%v", r)
		}
	})
	t.Run("LogixWrite", func(t *testing.T) {
		record(t, "Logix Write Tag", dir, name, "")
		if r := client(t, img, "write-tag", "--host", lgx.ip, "--tag", "Speeds", "--type", "INT", "--values", "5,6,7"); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := client(t, img, "read-tag", "--host", lgx.ip, "--tag", "Speeds", "--count", "4"); fmt.Sprint(r["values"]) != "[5 6 7 9]" {
			t.Fatalf("%v", r)
		}
	})
	notApplicable("Class 1 I/O, exclusive owner, point-to-point", dir, name, "cpppo has no implicit messaging")
}

// TestGoClientCpppo runs go-ethernetip's originator against cpppo's
// simulator serving the logix fixture.
func TestGoClientCpppo(t *testing.T) {
	ref := startServer(t, image("cpppo"), nil, "server")
	host := ref.ip
	const dir, name = "go->ref", "cpppo"
	t.Run("ListIdentity", func(t *testing.T) {
		record(t, "ListIdentity (TCP)", dir, name, "")
		r := nodeClient(t, "list-identity", "--host", host)
		if id := r.obj("identity"); !r.ok() || id.str("productName") != "1756-L61/B LOGIX5561" || id.str("revision") != "20.11" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("ListIdentityUDP", func(t *testing.T) {
		record(t, "ListIdentity (UDP)", dir, name, "")
		if r := nodeClient(t, "list-identity", "--host", host, "--transport", "udp"); !r.ok() || r.obj("identity").num("vendorId") != 1 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("GetAttribute", func(t *testing.T) {
		record(t, "Get_Attribute_Single", dir, name, "")
		r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7")
		if !r.ok() || r.str("data") != "14313735362d4c36312f42204c4f47495835353631" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("MultipleService", func(t *testing.T) {
		record(t, "Multiple Service Packet", dir, name, "")
		r := nodeClient(t, "multiple-get", "--host", host, "--path", "@1/1/1", "--path", "@1/1/7")
		reps, _ := r["replies"].([]any)
		if !r.ok() || len(reps) != 2 || result(reps[0].(map[string]any)).str("data") != "0100" {
			t.Fatalf("%v", r)
		}
	})
	values := map[string]any{"Counter": 42.0, "Temperature": 21.5, "Small": -7.0, "Word": 1234.0, "Big": 1099511627776.0, "Ratio": 0.125}
	for _, mode := range []string{"routed", "connected"} {
		args := []string{"--route", "1/0"}
		feature := "Logix Read Tag (atomic types)"
		if mode == "connected" {
			args = []string{"--connected"}
			feature = "Class 3 connected explicit messaging"
		}
		t.Run("ReadTags-"+mode, func(t *testing.T) {
			record(t, feature, dir, name, mode)
			for tag, want := range values {
				r := nodeClient(t, "read-tag", append([]string{"--host", host, "--tag", tag}, args...)...)
				vals, _ := r["values"].([]any)
				if !r.ok() || r.num("status") != 0 || len(vals) != 1 || vals[0] != want {
					t.Fatalf("%s: %v", tag, r)
				}
			}
		})
		t.Run("Fragmented-"+mode, func(t *testing.T) {
			record(t, "Logix Read Tag Fragmented (1200 octets)", dir, name, mode)
			r := nodeClient(t, "read-tag", append([]string{"--host", host, "--tag", "Samples", "--count", "300"}, args...)...)
			vals, _ := r["values"].([]any)
			if !r.ok() || len(vals) != 300 || vals[299] != float64(299*7-1000) {
				t.Fatalf("%v", r)
			}
		})
	}
	t.Run("WriteReadBack", func(t *testing.T) {
		record(t, "Logix Write Tag", dir, name, "")
		if r := nodeClient(t, "write-tag", "--host", host, "--tag", "Temperature", "--type", "REAL", "--values", "-3.25", "--route", "1/0"); r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		r := nodeClient(t, "read-tag", "--host", host, "--tag", "Temperature", "--connected")
		if vals, _ := r["values"].([]any); len(vals) != 1 || math.Abs(vals[0].(float64)+3.25) > 1e-9 {
			t.Fatalf("%v", r)
		}
	})
	notApplicable("Logix bit write (Read Modify Write Tag)", dir, name, "cpppo 5.2.5 rejects service 0x4E: it answers SendRRData with encapsulation status 0x0008")
	notApplicable("Class 1 I/O, exclusive owner, point-to-point", dir, name, "cpppo has no implicit messaging")
	notApplicable("Logix tag list (0x55) and LogixDriver open", dir, name, "cpppo has no Symbol object tag list")
	notApplicable("Logix structure read (UDT)", dir, name, "cpppo's simulator has no structure templates")
}
