//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"strings"
	"testing"
)

// The opener-sample fixture: what OpENer's sample application serves.
const (
	openerVendor  = 1
	openerProduct = 65001
	openerName    = "OpENer PC"
)

// TestGoScannerOpENer runs go-ethernetip's originator against OpENer.
func TestGoScannerOpENer(t *testing.T) {
	ref := startServer(t, image("opener"), nil, "server")
	host := ref.ip
	const dir, name = "go->ref", "opener"

	t.Run("ListIdentityTCP", func(t *testing.T) {
		record(t, "ListIdentity (TCP)", dir, name, "")
		r := nodeClient(t, "list-identity", "--host", host)
		id := r.obj("identity")
		if !r.ok() || id.num("vendorId") != openerVendor || id.num("productCode") != openerProduct || id.str("productName") != openerName ||
			id.str("socketAddress") != host+":44818" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("ListIdentityUDP", func(t *testing.T) {
		record(t, "ListIdentity (UDP)", dir, name, "")
		r := nodeClient(t, "list-identity", "--host", host, "--transport", "udp")
		if !r.ok() || r.obj("identity").str("productName") != openerName {
			t.Fatalf("%v", r)
		}
	})
	t.Run("ListServices", func(t *testing.T) {
		record(t, "ListServices", dir, name, "")
		r := nodeClient(t, "list-services", "--host", host)
		svcs, _ := r["services"].([]any)
		if !r.ok() || len(svcs) != 1 || result(svcs[0].(map[string]any)).str("name") != "Communications" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("GetAttributeSingle", func(t *testing.T) {
		record(t, "Get_Attribute_Single", dir, name, "")
		r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7")
		if !r.ok() || r.num("status") != 0 || r.str("data") != "094f70454e6572205043" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("GetAttributesAllIdentity", func(t *testing.T) {
		record(t, "Get_Attributes_All (Identity)", dir, name, "")
		r := nodeClient(t, "get-attributes-all", "--host", host, "--class", "1", "--instance", "1")
		// vendor 1, type 12, product 65001, revision 2.3, ..., serial 123456789
		if !r.ok() || !strings.HasPrefix(r.str("data"), "01000c00e9fd0203") || !strings.Contains(r.str("data"), "15cd5b07") {
			t.Fatalf("%v", r)
		}
	})
	t.Run("SetAttributeAssemblyEcho", func(t *testing.T) {
		record(t, "Set_Attribute_Single (assembly)", dir, name, "")
		data := strings.Repeat("5a", 32)
		if r := nodeClient(t, "set-attribute", "--host", host, "--class", "4", "--instance", "150", "--attribute", "3", "--data", data); !r.ok() || r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := nodeClient(t, "get-attribute", "--host", host, "--class", "4", "--instance", "100", "--attribute", "3"); r.str("data") != data {
			t.Fatalf("input after writing the output: %v", r)
		}
	})
	t.Run("ErrorStatuses", func(t *testing.T) {
		record(t, "Error responses (unknown class, attribute)", dir, name, "OpENer answers 0x05 for an unknown class or instance, 0x14 for an attribute")
		if r := nodeClient(t, "get-attribute", "--host", host, "--class", "0x99", "--instance", "1", "--attribute", "1"); r.num("status") != 0x05 {
			t.Fatalf("unknown class: %v", r)
		}
		if r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "99"); r.num("status") != 0x14 {
			t.Fatalf("unknown attribute: %v", r)
		}
	})
	t.Run("Class3", func(t *testing.T) {
		record(t, "Class 3 connected explicit messaging", dir, name, "")
		r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7", "--connected")
		if !r.ok() || r.str("data") != "094f70454e6572205043" {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1ExclusiveOwner", func(t *testing.T) {
		record(t, "Class 1 I/O, exclusive owner, point-to-point", dir, name, "output 150 echoed to input 100 by the sample application")
		out := strings.Repeat("c3", 32)
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1500", "--output-data", out)
		checkIO(t, r, out)
	})
	t.Run("Class1LargeForwardOpen", func(t *testing.T) {
		record(t, "Large_Forward_Open", dir, name, "")
		out := strings.Repeat("3c", 32)
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "20", "--duration-ms", "1000", "--output-data", out, "--large")
		checkIO(t, r, out)
	})
	t.Run("Class1InputOnly", func(t *testing.T) {
		record(t, "Class 1 I/O, input only (heartbeat O->T)", dir, name, "")
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "152", "--input", "100",
			"--output-size", "0", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1000")
		if fo := r.obj("forwardOpen"); !r.ok() || fo.num("status") != 0 || r.num("received") < 10 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1Multicast", func(t *testing.T) {
		record(t, "Class 1 I/O, T->O multicast", dir, name, "")
		out := strings.Repeat("a1", 32)
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1500", "--output-data", out, "--multicast")
		checkIO(t, r, out)
	})
	t.Run("Class1WrongSize", func(t *testing.T) {
		record(t, "Forward_Open refusal (connection size)", dir, name, "")
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "31", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100")
		fo := r.obj("forwardOpen")
		ext, _ := fo["extendedStatus"].([]any)
		if fo.num("status") != 1 || len(ext) == 0 || ext[0].(float64) != 0x0127 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1ConfigData", func(t *testing.T) {
		record(t, "Class 1 I/O, configuration data", dir, name, "a data segment of 10 octets for configuration assembly 151")
		cfg := "0102030405060708090a"
		out := strings.Repeat("c4", 32)
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1000", "--output-data", out, "--config-data", cfg)
		checkIO(t, r, out)
		if r := nodeClient(t, "get-attribute", "--host", host, "--class", "4", "--instance", "151", "--attribute", "3"); r.str("data") != cfg {
			t.Fatalf("configuration assembly after the Forward_Open: %v", r)
		}
	})
	t.Run("Class1ConfigDataWrongSize", func(t *testing.T) {
		record(t, "Forward_Open refusal (configuration size)", dir, name, "OpENer answers 0x0129 (invalid configuration application path) where go-ethernetip's target answers 0x0126 (invalid configuration size)")
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100", "--config-data", "0102")
		fo := r.obj("forwardOpen")
		ext, _ := fo["extendedStatus"].([]any)
		if fo.num("status") != 1 || len(ext) == 0 || ext[0].(float64) != 0x0129 {
			t.Fatalf("%v", r)
		}
	})
	t.Run("Class1ListenOnly", func(t *testing.T) {
		record(t, "Class 1 I/O, listen-only (multicast, next to its owner)", dir, name, "listen-only connection point 153 opened while the exclusive owner's multicast production runs; both consume it on one endpoint")
		out := strings.Repeat("b2", 32)
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
			"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1500", "--output-data", out,
			"--multicast", "--listen-only", "153")
		checkIO(t, r, out)
		lo := r.obj("listenOnly")
		lfo, fo := lo.obj("forwardOpen"), r.obj("forwardOpen")
		if lfo.num("status") != 0 || lfo.num("toConnectionId") != fo.num("toConnectionId") || lfo.str("multicastGroup") != fo.str("multicastGroup") {
			t.Fatalf("listen-only Forward_Open: %v", r)
		}
		if lo.num("received") < 10 || lo.str("lastInput") != out {
			t.Fatalf("listen-only data: %v", lo)
		}
	})
	t.Run("Class1ListenOnlyWithoutOwner", func(t *testing.T) {
		record(t, "Forward_Open refusal (listen-only without owner)", dir, name, "")
		r := nodeClient(t, "io", "--host", host, "--config", "151", "--output", "153", "--input", "100",
			"--output-size", "0", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100", "--multicast")
		fo := r.obj("forwardOpen")
		ext, _ := fo["extendedStatus"].([]any)
		if fo.num("status") != 1 || len(ext) == 0 || ext[0].(float64) != 0x0119 {
			t.Fatalf("%v", r)
		}
	})
	notApplicable("Multiple Service Packet", dir, name, "OpENer answers 0x08: not implemented")
	notApplicable("Unconnected_Send routing", dir, name, "OpENer answers 0x08: not implemented")
	notApplicable("Logix tag services", dir, name, "not a Logix controller")
}

// checkIO checks an io result: the connection opened, data flowed both
// ways, the echoed output came back and Forward_Close succeeded.
func checkIO(t *testing.T, r result, out string) {
	t.Helper()
	fo := r.obj("forwardOpen")
	if !r.ok() || fo.num("status") != 0 {
		t.Fatalf("Forward_Open: %v", r)
	}
	if r.num("sent") < 10 || r.num("received") < 10 {
		t.Fatalf("too little traffic: %v", r)
	}
	if r.str("lastInput") != out {
		t.Fatalf("last input %s, want the echoed output %s", r.str("lastInput"), out)
	}
	if to, _ := r["timedOut"].(bool); to {
		t.Fatalf("timed out: %v", r)
	}
	if fc := r.obj("forwardClose"); fc.num("status") != 0 || fc["error"] != nil {
		t.Fatalf("Forward_Close: %v", r)
	}
}
