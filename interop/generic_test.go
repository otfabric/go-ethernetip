//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

// The references tested by capability: every case a reference declares
// the operations and features for runs; the others are recorded N/A with
// the missing declaration as the reason. OpENer, EIPScanner, pycomm3 and
// cpppo keep their own tests (opener_test.go, references_test.go), which
// also check their documented quirks.
var (
	genericClients = []string{"libplctag", "gologix", "pylogix", "etherip", "eiprs", "nodeeip", "eeip"}
	genericServers = []string{"libplctag", "gologix"}
)

// knownLimits are cases a reference declares the features for but cannot
// do, for reasons of its own (its adapter's documented quirks): recorded
// N/A with the reason, not run.
var knownLimits = map[string]map[string]string{
	"etherip": {
		"Logix Read Tag (64-bit types)": "reference limitation: etherip knows no LINT or LREAL (its type lookup fails)",
	},
	"libplctag": {
		"Logix BOOL array element write": "reference limitation: libplctag sends Bits[37] as element 37 of the DWORD array; its own form is Bits[1].5",
	},
	"nodeeip": {
		"Logix BOOL array element write": "reference limitation: node-ethernet-ip sends Bits[37] as element 37 of the DWORD array",
	},
}

// explicitArgs are added to a reference's attribute requests, with the
// reason recorded in the matrix notes.
var explicitArgs = map[string]struct {
	args []string
	note string
}{
	"libplctag": {[]string{"--connected"}, "over Class 3: libplctag 2.7.2 builds unconnected requests without their route path"},
}

// caps is a capability document (print-capabilities).
type caps struct {
	Adapter string `json:"adapter"`
	Roles   struct {
		Server bool `json:"server"`
		Client bool `json:"client"`
	} `json:"roles"`
	Fixtures         []string        `json:"fixtures"`
	ClientOperations []string        `json:"clientOperations"`
	ClientFeatures   map[string]bool `json:"clientFeatures"`
	ServerFeatures   map[string]bool `json:"serverFeatures"`

	extra []string // explicitArgs of the reference
}

// attr returns the arguments of an attribute request, with the
// reference's explicitArgs.
func (c *caps) attr(args ...string) []string { return append(args, c.extra...) }

var (
	capsMu    sync.Mutex
	capsCache = map[string]*caps{}
)

func capabilities(t *testing.T, img string) *caps {
	t.Helper()
	capsMu.Lock()
	defer capsMu.Unlock()
	if c := capsCache[img]; c != nil {
		return c
	}
	out, err := dockerOut("run", "--rm", img, "print-capabilities")
	if err != nil {
		t.Fatal(err)
	}
	c := &caps{}
	if err := json.Unmarshal(lastLine([]byte(out)), c); err != nil {
		t.Fatalf("%s print-capabilities: %v: %s", img, err, out)
	}
	capsCache[img] = c
	return c
}

// missing returns why c cannot run a case that needs ops and the client
// features feats, or "".
func (c *caps) missing(ops, feats []string) string {
	for _, o := range ops {
		found := false
		for _, x := range c.ClientOperations {
			found = found || x == o
		}
		if !found {
			return fmt.Sprintf("the adapter has no %s operation", o)
		}
	}
	for _, f := range feats {
		if !c.ClientFeatures[f] {
			return fmt.Sprintf("the adapter declares no client feature %s", f)
		}
	}
	return ""
}

// same compares a value of a result document with what is expected,
// with BOOL as true/false or 1/0 and numbers within float rounding.
func same(got, want any) bool {
	switch w := want.(type) {
	case bool:
		switch g := got.(type) {
		case bool:
			return g == w
		case float64:
			return (g != 0) == w
		}
		return false
	case float64:
		switch g := got.(type) {
		case float64:
			return g == w || math.Abs(g-w) <= 1e-6*math.Max(1, math.Abs(w))
		case bool:
			return (w != 0) == g
		}
		return false
	case string:
		g, ok := got.(string)
		return ok && strings.TrimRight(g, "\x00") == w
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !same(g[i], w[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range w {
			if !same(g[k], v) {
				return false
			}
		}
		return true
	}
	return fmt.Sprint(got) == fmt.Sprint(want)
}

// values returns the values of a read-tag document.
func values(r result) []any {
	v, _ := r["values"].([]any)
	return v
}

// genericCase is one capability-driven case.
type genericCase struct {
	feature string
	fixture string // the node fixture it runs against
	ops     []string
	feats   []string
	run     func(t *testing.T, img, host string, c *caps)
	attr    bool // an attribute request: explicitArgs apply
}

// TestReferenceClientsToGo runs every generic reference client against
// go-ethernetip's target serving the adapter, logix and logix-structures
// fixtures.
func TestReferenceClientsToGo(t *testing.T) {
	for _, name := range genericClients {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			img := image(name)
			c := capabilities(t, img)
			if !c.Roles.Client {
				return
			}
			note := ""
			if ea, ok := explicitArgs[name]; ok {
				c.extra, note = ea.args, ea.note
			}
			// The nodes live as long as this reference's test (not the
			// case that first needs one: its cleanup would stop them).
			rt := t
			nodes := map[string]*container{}
			host := func(t *testing.T, fixture string) string {
				t.Helper()
				if nodes[fixture] == nil {
					nodes[fixture] = startNode(rt, img, fixture)
				}
				return nodes[fixture].ip
			}
			const dir = "ref->go"
			for _, tc := range clientCases() {
				if why := c.missing(tc.ops, tc.feats); why != "" {
					notApplicable(tc.feature, dir, name, why)
					continue
				}
				if why := knownLimits[name][tc.feature]; why != "" {
					notApplicable(tc.feature, dir, name, why)
					continue
				}
				t.Run(strings.ReplaceAll(tc.feature, " ", "_"), func(t *testing.T) {
					n := ""
					if tc.attr {
						n = note
					}
					record(t, tc.feature, dir, name, n)
					tc.run(t, img, host(t, tc.fixture), c)
				})
			}
		})
	}
}

func clientCases() []genericCase {
	ioCase := func(feature string, feats []string, extra ...string) genericCase {
		return genericCase{feature, "adapter", []string{"io"}, append([]string{"class1"}, feats...), func(t *testing.T, img, host string, c *caps) {
			out := strings.Repeat("6b", 32)
			args := append([]string{"--host", host, "--config", "151", "--output", "150", "--input", "100",
				"--output-size", "32", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1500", "--output-data", out}, extra...)
			checkIO(t, client(t, img, "io", args...), out)
		}, false}
	}
	return []genericCase{
		{"ListIdentity (TCP)", "adapter", []string{"list-identity"}, []string{"listIdentityTcp"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "list-identity", "--host", host, "--transport", "tcp")
			if id := r.obj("identity"); !r.ok() || id.str("productName") != adapterName || id.num("productCode") != adapterProduct {
				t.Fatalf("%v", r)
			}
		}, false},
		{"ListIdentity (UDP)", "adapter", []string{"list-identity"}, []string{"listIdentityUdp"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "list-identity", "--host", host, "--transport", "udp")
			if id := r.obj("identity"); !r.ok() || id.str("productName") != adapterName {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Get_Attribute_Single", "adapter", []string{"get-attribute"}, []string{"getAttributeSingle"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "get-attribute", c.attr("--host", host, "--class", "1", "--instance", "1", "--attribute", "7")...)
			if !r.ok() || r.num("status") != 0 || r.str("data") != adapterNameHex {
				t.Fatalf("%v", r)
			}
		}, true},
		{"Get_Attributes_All (Identity)", "adapter", []string{"get-attributes-all"}, []string{"getAttributesAll"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "get-attributes-all", c.attr("--host", host, "--class", "1", "--instance", "1")...)
			if !r.ok() || !strings.HasPrefix(r.str("data"), "ffff0c002a000307") || !strings.HasSuffix(r.str("data"), adapterNameHex) {
				t.Fatalf("%v", r)
			}
		}, true},
		{"Set_Attribute_Single (assembly)", "adapter", []string{"set-attribute", "get-attribute"}, []string{"setAttributeSingle", "getAttributeSingle"}, func(t *testing.T, img, host string, c *caps) {
			data := strings.Repeat("3e", 32)
			if r := client(t, img, "set-attribute", c.attr("--host", host, "--class", "4", "--instance", "150", "--attribute", "3", "--data", data)...); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "get-attribute", c.attr("--host", host, "--class", "4", "--instance", "100", "--attribute", "3")...); r.str("data") != data {
				t.Fatalf("input after writing the output: %v", r)
			}
		}, true},
		{"Error responses (unknown class, attribute)", "adapter", []string{"get-attribute"}, []string{"getAttributeSingle"}, func(t *testing.T, img, host string, c *caps) {
			if r := client(t, img, "get-attribute", c.attr("--host", host, "--class", "1", "--instance", "1", "--attribute", "99")...); !r.ok() || r.num("status") != 0x14 {
				t.Fatalf("unknown attribute: %v", r)
			}
			if r := client(t, img, "get-attribute", c.attr("--host", host, "--class", "0x99", "--instance", "1", "--attribute", "1")...); !r.ok() || r.num("status") != 0x05 {
				t.Fatalf("unknown class: %v", r)
			}
		}, true},
		{"Multiple Service Packet", "adapter", []string{"multiple-get"}, []string{"multipleService"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "multiple-get", "--host", host, "--path", "@1/1/1", "--path", "@1/1/99", "--path", "@4/100/4")
			reps, _ := r["replies"].([]any)
			if !r.ok() || len(reps) != 3 {
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
		}, false},
		{"Class 3 connected explicit messaging", "adapter", []string{"get-attribute"}, []string{"class3"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7", "--connected")
			if !r.ok() || r.num("status") != 0 || r.str("data") != adapterNameHex {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Identity object (identity operation)", "adapter", []string{"identity"}, nil, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "identity", "--host", host)
			name := r.obj("identity").str("productName")
			for _, k := range []string{"product_name", "name"} {
				if name == "" {
					name = r.obj("module").str(k)
				}
			}
			if !r.ok() || name != adapterName {
				t.Fatalf("%v", r)
			}
		}, false},
		ioCase("Class 1 I/O, exclusive owner, point-to-point", nil),
		ioCase("Large_Forward_Open", []string{"largeForwardOpen"}, "--large"),
		ioCase("Class 1 I/O, T->O multicast", []string{"multicast"}, "--multicast"),
		ioCase("Class 1 I/O, configuration data", []string{"configData"}, "--config-data", "0a0b0c0d0e0f10111213"),
		{"Class 1 I/O, input only (heartbeat O->T)", "adapter", []string{"io"}, []string{"class1", "inputOnly"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "io", "--host", host, "--config", "151", "--output", "152", "--input", "100",
				"--output-size", "0", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "1000")
			if !r.ok() || r.obj("forwardOpen").num("status") != 0 || r.num("received") < 10 {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Forward_Open refusal (connection size)", "adapter", []string{"io"}, []string{"class1"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "io", "--host", host, "--config", "151", "--output", "150", "--input", "100",
				"--output-size", "31", "--input-size", "32", "--rpi-ms", "10", "--duration-ms", "100")
			fo := r.obj("forwardOpen")
			refused, _ := fo["refused"].(bool)
			if !r.ok() || (fo.num("status") == 0 && !refused) {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix tag list (0x55)", "logix", []string{"tag-list"}, []string{"tagList"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "tag-list", "--host", host)
			tags, _ := r["tags"].([]any)
			if !r.ok() || len(tags) != 10 {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix Read Tag (atomic types)", "logix", []string{"read-tag"}, []string{"logixTags"}, func(t *testing.T, img, host string, c *caps) {
			want := map[string]any{"Counter": 42.0, "Temperature": 21.5, "Small": -7.0, "Word": 1234.0, "Running": true}
			for tag, w := range want {
				r := client(t, img, "read-tag", "--host", host, "--tag", tag)
				if v := values(r); !r.ok() || len(v) != 1 || !same(v[0], w) {
					t.Fatalf("%s: %v, want %v", tag, r, w)
				}
			}
		}, false},
		{"Logix Read Tag (64-bit types)", "logix", []string{"read-tag"}, []string{"logixTags"}, func(t *testing.T, img, host string, c *caps) {
			for tag, w := range map[string]any{"Big": 1099511627776.0, "Ratio": 0.125} {
				r := client(t, img, "read-tag", "--host", host, "--tag", tag)
				if v := values(r); !r.ok() || len(v) != 1 || !same(v[0], w) {
					t.Fatalf("%s: %v, want %v", tag, r, w)
				}
			}
		}, false},
		{"Logix multiple tags in one request (read-tags)", "logix", []string{"read-tags"}, []string{"logixTags"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "read-tags", "--host", host, "--tags", "Counter,Temperature,Small")
			res, _ := r["results"].([]any)
			want := []any{42.0, 21.5, -7.0}
			if !r.ok() || len(res) != len(want) {
				t.Fatalf("%v", r)
			}
			for i, w := range want {
				if v := values(result(res[i].(map[string]any))); len(v) != 1 || !same(v[0], w) {
					t.Fatalf("tag %d: %v, want %v", i, res[i], w)
				}
			}
		}, false},
		{"Logix Read Tag Fragmented (1200 octets)", "logix", []string{"read-tag"}, []string{"readTagFragmented"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "read-tag", "--host", host, "--tag", "Samples", "--count", "300")
			v := values(r)
			if !r.ok() || len(v) != 300 || !same(v[0], -1000.0) || !same(v[299], float64(299*7-1000)) {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix Write Tag", "logix", []string{"write-tag", "read-tag"}, []string{"logixTags"}, func(t *testing.T, img, host string, c *caps) {
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Counter", "--type", "DINT", "--values", "77"); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Counter"); !same(values(r), []any{77.0}) {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Speeds", "--type", "INT", "--values", "5,6,7"); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Speeds", "--count", "4"); !same(values(r), []any{5.0, 6.0, 7.0, 9.0}) {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix Write Tag Fragmented (1200 octets)", "logix", []string{"write-tag", "read-tag"}, []string{"writeTagFragmented"}, func(t *testing.T, img, host string, c *caps) {
			vals := make([]string, 300)
			for i := range vals {
				vals[i] = fmt.Sprint(i*13 - 2000)
			}
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Samples", "--type", "DINT", "--values", strings.Join(vals, ",")); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			r := client(t, img, "read-tag", "--host", host, "--tag", "Samples", "--count", "300")
			if v := values(r); len(v) != 300 || !same(v[0], -2000.0) || !same(v[299], float64(299*13-2000)) {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix tag list with structure and STRING tags", "logix-structures", []string{"tag-list"}, []string{"tagList", "templates"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "tag-list", "--host", host)
			tags, _ := r["tags"].([]any)
			names := map[string]bool{}
			for _, x := range tags {
				names[result(x.(map[string]any)).str("name")] = true
			}
			if !r.ok() || !names["Pump"] || !names["Message"] || !names["Bits"] {
				t.Fatalf("%v", r)
			}
		}, false},
		{"Logix bit write (Read Modify Write Tag)", "logix-structures", []string{"write-tag", "read-tag"}, []string{"readModifyWrite"}, func(t *testing.T, img, host string, c *caps) {
			for _, b := range []string{"3", "0"} {
				if r := client(t, img, "write-tag", "--host", host, "--tag", "Flags."+b, "--type", "BOOL", "--values", "true"); !r.ok() || r.num("status") != 0 {
					t.Fatalf("Flags.%s: %v", b, r)
				}
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Flags"); !same(values(r), []any{9.0}) {
				t.Fatalf("Flags: %v", r)
			}
		}, false},
		{"Logix BOOL array element write", "logix-structures", []string{"write-tag", "read-tag"}, []string{"readModifyWrite"}, func(t *testing.T, img, host string, c *caps) {
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Bits[37]", "--type", "BOOL", "--values", "true"); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Bits[37]"); !same(values(r), []any{true}) {
				t.Fatalf("Bits[37]: %v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Bits[36]"); !same(values(r), []any{false}) {
				t.Fatalf("Bits[36]: %v", r)
			}
		}, false},
		{"Logix structure read (UDT)", "logix-structures", []string{"read-tag"}, []string{"templates"}, func(t *testing.T, img, host string, c *caps) {
			r := client(t, img, "read-tag", "--host", host, "--tag", "Pump")
			want := map[string]any{"Enabled": true, "Faulted": false, "Speed": 1500.0, "Current": 2.5,
				"Setpoints": []any{10.0, 20.0, 30.0, 40.0}, "Label": "pump"}
			if v := values(r); !r.ok() || len(v) != 1 || !same(v[0], want) {
				t.Fatalf("Pump: %v", r)
			}
		}, false},
		{"Logix structure write (UDT)", "logix-structures", []string{"write-tag", "read-tag"}, []string{"templates"}, func(t *testing.T, img, host string, c *caps) {
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Pump.Speed", "--type", "DINT", "--values", "1800"); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Pump.Speed"); !same(values(r), []any{1800.0}) {
				t.Fatalf("Pump.Speed: %v", r)
			}
		}, false},
		{"Logix STRING read and write", "logix-structures", []string{"write-tag", "read-tag"}, []string{"templates"}, func(t *testing.T, img, host string, c *caps) {
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Message"); !same(values(r), []any{"hello"}) {
				t.Fatalf("Message: %v", r)
			}
			if r := client(t, img, "write-tag", "--host", host, "--tag", "Message", "--type", "STRING", "--values", "written"); !r.ok() || r.num("status") != 0 {
				t.Fatalf("%v", r)
			}
			if r := client(t, img, "read-tag", "--host", host, "--tag", "Message"); !same(values(r), []any{"written"}) {
				t.Fatalf("Message: %v", r)
			}
		}, false},
	}
}

// fixtureDoc is the part of a fixture the server cases need.
type fixtureDoc struct {
	Identity struct {
		ProductName string `json:"productName"`
	} `json:"identity"`
	Tags []struct {
		Name   string    `json:"name"`
		Type   string    `json:"type"`
		Count  int       `json:"count"`
		Values []float64 `json:"values"`
	} `json:"tags"`
}

// TestGoClientToReferenceServers runs go-ethernetip's originator against
// every generic reference server, for each fixture it serves.
func TestGoClientToReferenceServers(t *testing.T) {
	for _, name := range genericServers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			img := image(name)
			c := capabilities(t, img)
			if !c.Roles.Server {
				return
			}
			const dir = "go->ref"
			for _, fixture := range c.Fixtures {
				t.Run(fixture, func(t *testing.T) {
					out, err := dockerOut("run", "--rm", img, "print-fixture", fixture)
					if err != nil {
						t.Fatal(err)
					}
					var fx fixtureDoc
					if err := json.Unmarshal([]byte(out), &fx); err != nil {
						t.Fatal(err)
					}
					host := startServer(t, img, nil, "server", "--fixture", "/fixtures/"+fixture+"/fixture.json").ip
					serverCases(t, name, dir, host, c, fx)
				})
			}
		})
	}
}

func serverCases(t *testing.T, name, dir, host string, c *caps, fx fixtureDoc) {
	feat := func(f string) bool { return c.ServerFeatures[f] }
	step := func(feature, need string, fn func(t *testing.T)) {
		if need != "" && !feat(need) {
			notApplicable(feature, dir, name, "the server declares no "+need)
			return
		}
		t.Run(strings.ReplaceAll(feature, " ", "_"), func(t *testing.T) {
			record(t, feature, dir, name, "")
			fn(t)
		})
	}
	nameHex := fmt.Sprintf("%02x", len(fx.Identity.ProductName)) + fmt.Sprintf("%x", fx.Identity.ProductName)
	step("ListIdentity (TCP)", "listIdentityTcp", func(t *testing.T) {
		r := nodeClient(t, "list-identity", "--host", host)
		if !r.ok() || r.obj("identity").str("productName") != fx.Identity.ProductName {
			t.Fatalf("%v", r)
		}
	})
	step("ListIdentity (UDP)", "listIdentityUdp", func(t *testing.T) {
		r := nodeClient(t, "list-identity", "--host", host, "--transport", "udp")
		if !r.ok() || r.obj("identity").str("productName") != fx.Identity.ProductName {
			t.Fatalf("%v", r)
		}
	})
	step("Get_Attribute_Single", "getAttributeSingle", func(t *testing.T) {
		r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7")
		if !r.ok() || r.num("status") != 0 || r.str("data") != nameHex {
			t.Fatalf("%v", r)
		}
	})
	step("Get_Attributes_All (Identity)", "getAttributesAll", func(t *testing.T) {
		r := nodeClient(t, "get-attributes-all", "--host", host, "--class", "1", "--instance", "1")
		if !r.ok() || r.num("status") != 0 || !strings.Contains(r.str("data"), nameHex) {
			t.Fatalf("%v", r)
		}
	})
	stepIf := func(feature string, needs []string, fn func(t *testing.T)) {
		for _, n := range needs {
			if !feat(n) {
				notApplicable(feature, dir, name, "the server declares no "+n)
				return
			}
		}
		step(feature, "", fn)
	}
	stepIf("Multiple Service Packet", []string{"multipleService", "getAttributeSingle"}, func(t *testing.T) {
		r := nodeClient(t, "multiple-get", "--host", host, "--path", "@1/1/1", "--path", "@1/1/7")
		reps, _ := r["replies"].([]any)
		if !r.ok() || len(reps) != 2 || result(reps[1].(map[string]any)).str("data") != nameHex {
			t.Fatalf("%v", r)
		}
	})
	stepIf("Class 3 connected explicit messaging", []string{"class3", "getAttributeSingle"}, func(t *testing.T) {
		r := nodeClient(t, "get-attribute", "--host", host, "--class", "1", "--instance", "1", "--attribute", "7", "--connected")
		if !r.ok() || r.num("status") != 0 || r.str("data") != nameHex {
			t.Fatalf("%v", r)
		}
	})
	if len(fx.Tags) == 0 {
		return
	}
	// Logix: every scalar of the fixture, routed to slot 0 and connected.
	for _, mode := range []string{"routed", "connected"} {
		args := []string{"--route", "1/0"}
		feature := "Logix Read Tag (atomic types)"
		need := "logixTags"
		if mode == "connected" {
			// Through slot 0 as well: a Logix target wants the backplane
			// port in the Forward_Open path (libplctag's ab_server does).
			args = []string{"--connected", "--route", "1/0"}
			feature, need = "Logix Read Tag over Class 3", "class3"
		}
		step(feature, need, func(t *testing.T) {
			n := 0
			for _, tg := range fx.Tags {
				if tg.Count > 1 || len(tg.Values) != 1 || !feat("logixTags") {
					continue
				}
				r := nodeClient(t, "read-tag", append([]string{"--host", host, "--tag", tg.Name}, args...)...)
				want := any(tg.Values[0])
				if tg.Type == "BOOL" {
					want = tg.Values[0] != 0
				}
				if v := values(r); !r.ok() || r.num("status") != 0 || len(v) != 1 || !same(v[0], want) {
					t.Fatalf("%s: %v, want %v", tg.Name, r, want)
				}
				n++
			}
			if n == 0 {
				t.Skip("the fixture has no scalar tag")
			}
		})
	}
	step("Logix Write Tag", "logixTags", func(t *testing.T) {
		if r := nodeClient(t, "write-tag", "--host", host, "--tag", "Counter", "--type", "DINT", "--values", "-5", "--route", "1/0"); !r.ok() || r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := nodeClient(t, "read-tag", "--host", host, "--tag", "Counter", "--route", "1/0"); !same(values(r), []any{-5.0}) {
			t.Fatalf("%v", r)
		}
	})
	step("Logix Read Tag Fragmented (1200 octets)", "readTagFragmented", func(t *testing.T) {
		r := nodeClient(t, "read-tag", "--host", host, "--tag", "Samples", "--count", "300", "--connected", "--route", "1/0")
		if v := values(r); !r.ok() || len(v) != 300 || !same(v[299], float64(299*7-1000)) {
			t.Fatalf("%v", r)
		}
	})
	step("Logix bit write (Read Modify Write Tag)", "readModifyWrite", func(t *testing.T) {
		if r := nodeClient(t, "write-bit", "--host", host, "--tag", "Flags.4", "--type", "DINT", "--values", "1", "--route", "1/0"); !r.ok() || r.num("status") != 0 {
			t.Fatalf("%v", r)
		}
		if r := nodeClient(t, "read-tag", "--host", host, "--tag", "Flags", "--route", "1/0"); !same(values(r), []any{16.0}) {
			t.Fatalf("%v", r)
		}
	})
	step("Logix tag list (0x55)", "tagList", func(t *testing.T) {
		r := nodeClient(t, "tag-list", "--host", host)
		tags, _ := r["tags"].([]any)
		if !r.ok() || len(tags) < len(fx.Tags) {
			t.Fatalf("%v", r)
		}
	})
}
