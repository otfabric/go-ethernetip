//go:build interop

// SPDX-License-Identifier: MIT

// Package interop tests go-ethernetip against the reference implementations
// of otfabric/ethernetip-interop: OpENer, cpppo, EIPScanner and pycomm3, as
// container images that follow its container contract.
//
// go-ethernetip itself runs in a container too (internal/cmd/interopnode,
// built here for Linux), on the same Docker network as the references:
// I/O connections need the originator and the target to reach each other
// without NAT. Both directions are tested: the library's originator against
// the reference targets, and the reference originators against the
// library's target.
package interop

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The reference images this version is qualified against:
// otfabric/ethernetip-interop v0.8.2 (OpENer fb90c99, cpppo 5.2.5,
// EIPScanner 12c89a5, pycomm3 1.2.16, libplctag 2.7.2, gologix 0.44.0-beta,
// pylogix 1.1.7, etherip ce0688a, eip-rs 16e2236, node-ethernet-ip 2.0.0,
// EEIP.NET 58b91a0, go-ethernet-ip (loki-os) 535f797, cB-Sigma enip 0.2.1),
// pinned by multi-arch index digest so
// that a run is reproducible. Override per image to try another build, for
// example the images "make images" builds in ethernetip-interop:
//
//	ETHERNETIP_INTEROP_<ADAPTER>_IMAGE (OPENER, CPPPO, EIPSCANNER, PYCOMM3,
//	LIBPLCTAG, GOLOGIX, PYLOGIX, ETHERIP, EIPRS, NODEEIP, EEIP, LOKIEIP,
//	CBSIGMA)
//
// or ETHERNETIP_INTEROP_VERSION=dev (a tag) for all of them.
//
// ETHERNETIP_INTEROP_ADAPTERS restricts the run to a comma-separated subset.
//
// otfabric is go-ethernetip itself, as published by otfabric/ethernetip-interop
// (ethernetip-interop-otfabric). It is not a reference: it runs, as a client and
// a server of the generic tests, only when ETHERNETIP_INTEROP_OTFABRIC_IMAGE
// names an image, and what it shows is compatibility between releases of this
// library, not independent verification.
const interopRelease = "v0.8.2"

const otfabric = "otfabric"

// selected reports whether ETHERNETIP_INTEROP_ADAPTERS selects an adapter:
// every reference when it is empty; otfabric only when its image is set.
func selected(name string) bool {
	if name == otfabric && os.Getenv("ETHERNETIP_INTEROP_OTFABRIC_IMAGE") == "" {
		return false
	}
	only := os.Getenv("ETHERNETIP_INTEROP_ADAPTERS")
	if only == "" {
		return true
	}
	for _, want := range strings.Split(only, ",") {
		if strings.TrimSpace(want) == name {
			return true
		}
	}
	return false
}

// requireAdapter skips a test of one reference that is not selected.
func requireAdapter(t *testing.T, name string) {
	t.Helper()
	if !selected(name) {
		t.Skipf("%s is not selected (ETHERNETIP_INTEROP_ADAPTERS)", name)
	}
}

// generic returns the selected adapters of a generic list, with otfabric
// when its image is set.
func generic(names []string) []string {
	var out []string
	for _, n := range append(append([]string{}, names...), otfabric) {
		if selected(n) {
			out = append(out, n)
		}
	}
	return out
}

// checkSelection fails a run whose ETHERNETIP_INTEROP_ADAPTERS selects
// nothing, or otfabric without its image.
func checkSelection() error {
	only := os.Getenv("ETHERNETIP_INTEROP_ADAPTERS")
	if only == "" {
		return nil
	}
	known := append(append([]string{"opener", "cpppo", "eipscanner", "pycomm3"}, genericClients...), otfabric)
	for _, want := range strings.Split(only, ",") {
		want = strings.TrimSpace(want)
		if want == otfabric && os.Getenv("ETHERNETIP_INTEROP_OTFABRIC_IMAGE") == "" {
			return fmt.Errorf("ETHERNETIP_INTEROP_ADAPTERS selects otfabric, which has no image: set ETHERNETIP_INTEROP_OTFABRIC_IMAGE")
		}
		found := false
		for _, k := range known {
			found = found || k == want
		}
		if !found {
			return fmt.Errorf("ETHERNETIP_INTEROP_ADAPTERS: unknown adapter %q", want)
		}
	}
	return nil
}

var pinned = map[string]string{
	"opener":     "sha256:344cfbd1ffad656b940c9ca5431184ac2bfe0d7a58f21a9c958c90685c88d820",
	"eipscanner": "sha256:33038cc8215ff8b8f7aecca8bc31773a9b158f572a0c6df9b672ada7ab5078d9",
	"cpppo":      "sha256:00b81c31cc3f390cf0f889d64c56dfaf15091d9ea81730170c61b121a0360a12",
	"pycomm3":    "sha256:c189df3ea45a1dab2d250034c14fa130c4f27ccf606bd38b780e8a98a3f2eb2b",
	"libplctag":  "sha256:40e51962e9169fd72e539cd4ccb44c807894e894c5168060f441d3744724eb0f",
	"gologix":    "sha256:f01985cbbfbf57962662d701a21bc0f06e77082c5f3b7f6b1b26cc0891b9d9a9",
	"pylogix":    "sha256:61779bdb0d9fabc8d1b0d90539ed98cde294d49ea63245dcc600387a40fe45ef",
	"etherip":    "sha256:ec21f437e91229951db573a22994d03d828da5596c40cfee98dc228e536e5380",
	"eiprs":      "sha256:b918f31d016f42070a471b1e793c349c076ae8de72d3f261ba44d9ea8f466989",
	"nodeeip":    "sha256:a4c886bb5b7abdb9012a0b80e2db01fe6c58872b428111c02fc853b4da749a14",
	"eeip":       "sha256:2b84a58b84090b05bb729974b94b96e2c2ca035d28017ccc3005a2fd5a4f5608",
	"lokieip":    "sha256:3f84aa98951568d34b08ace947826244f17097f835b9ac747a48ea11ea6fd5cd",
	"cbsigma":    "sha256:553531bbef54950aae7f215451636c18f1413919400a2886e7320be2ea4d5f19",
}

func image(name string) string {
	if v := os.Getenv("ETHERNETIP_INTEROP_" + strings.ToUpper(name) + "_IMAGE"); v != "" {
		return v
	}
	repo := "ghcr.io/otfabric/ethernetip-interop-" + name
	if v := os.Getenv("ETHERNETIP_INTEROP_VERSION"); v != "" {
		return repo + ":" + v
	}
	if pinned[name] == "" {
		return repo + ":" + interopRelease
	}
	return repo + "@" + pinned[name]
}

var (
	network  string
	nodeDir  string
	nodeBase = "debian:trixie-slim"
)

func TestMain(m *testing.M) {
	code, err := setup(m)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "interop:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func setup(m *testing.M) (int, error) {
	if err := checkSelection(); err != nil {
		return 0, err
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return 0, fmt.Errorf("docker is required: %w", err)
	}
	arch, err := dockerOut("info", "--format", "{{.Architecture}}")
	if err != nil {
		return 0, err
	}
	goarch := map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "amd64": "amd64"}[strings.TrimSpace(arch)]
	if goarch == "" {
		return 0, fmt.Errorf("docker architecture %q", arch)
	}
	nodeDir, err = os.MkdirTemp("", "ethernetip-interop-node-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(nodeDir) }()
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(self))
	build := exec.Command("go", "build", "-o", filepath.Join(nodeDir, "interopnode"), "./internal/cmd/interopnode")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch, "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("build interopnode: %v\n%s", err, out)
	}
	network = fmt.Sprintf("ethernetip-interop-%d", time.Now().UnixNano())
	if _, err := dockerOut("network", "create", "--label", "ethernetip-interop.run=1", network); err != nil {
		return 0, err
	}
	defer func() { _, _ = dockerOut("network", "rm", network) }()
	code := m.Run()
	stopAll()
	writeMatrix()
	return code, nil
}

func dockerOut(args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// container is a running server container.
type container struct {
	name string
	ip   string
}

var (
	runningMu sync.Mutex
	running   = map[string]bool{}
)

func stopAll() {
	runningMu.Lock()
	defer runningMu.Unlock()
	for n := range running {
		_, _ = dockerOut("stop", "-t", "5", n)
	}
}

// startServer starts a server container and waits for its "ready" event.
// extra are docker run options before the image; args the command.
func startServer(t *testing.T, img string, extra []string, args ...string) *container {
	t.Helper()
	name := fmt.Sprintf("eip-%s-%d", strings.NewReplacer("/", "-", ":", "-", ".", "-", "@", "-").Replace(filepath.Base(img)), time.Now().UnixNano())
	run := append([]string{"run", "-d", "--rm", "--name", name, "--network", network, "--label", "ethernetip-interop.run=1"}, extra...)
	run = append(append(run, img), args...)
	if _, err := dockerOut(run...); err != nil {
		t.Fatal(err)
	}
	runningMu.Lock()
	running[name] = true
	runningMu.Unlock()
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := dockerOut("logs", name)
			t.Logf("logs of %s:\n%s", name, logs)
		}
		_, _ = dockerOut("stop", "-t", "5", name)
		runningMu.Lock()
		delete(running, name)
		runningMu.Unlock()
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		cmd := exec.Command("docker", "logs", name)
		out, _ := cmd.Output()
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			var ev map[string]any
			if json.Unmarshal(sc.Bytes(), &ev) == nil && ev["event"] == "ready" {
				ip, err := dockerOut("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
				if err != nil {
					t.Fatal(err)
				}
				return &container{name: name, ip: strings.TrimSpace(ip)}
			}
		}
		if time.Now().After(deadline) {
			logs, _ := dockerOut("logs", name)
			t.Fatalf("%s not ready after 60 s:\n%s", img, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// startNode starts go-ethernetip's adapter serving a fixture of image.
func startNode(t *testing.T, fixtureImage, fixture string) *container {
	t.Helper()
	dir := t.TempDir()
	fx, err := dockerOut("run", "--rm", fixtureImage, "print-fixture", fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, fixture), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fixture, "fixture.json"), []byte(fx), 0o644); err != nil {
		t.Fatal(err)
	}
	return startServer(t, nodeBase, []string{"-v", nodeDir + ":/node:ro", "-v", dir + ":/fixtures:ro"},
		"/node/interopnode", "server", "--fixture", "/fixtures/"+fixture+"/fixture.json", "--ready-file", "")
}

// result is a client result document.
type result map[string]any

func (r result) ok() bool { b, _ := r["ok"].(bool); return b }

func (r result) num(k string) float64 {
	f, _ := r[k].(float64)
	return f
}

func (r result) str(k string) string {
	s, _ := r[k].(string)
	return s
}

func (r result) obj(k string) result {
	m, _ := r[k].(map[string]any)
	return result(m)
}

// client runs one client operation of an image; args after the operation.
func client(t *testing.T, img, op string, args ...string) result {
	t.Helper()
	return runClient(t, []string{img, "client", op}, args)
}

// nodeClient runs one client operation of go-ethernetip's node.
func nodeClient(t *testing.T, op string, args ...string) result {
	t.Helper()
	return runClient(t, []string{"-v", nodeDir + ":/node:ro", nodeBase, "/node/interopnode", "client", op}, args)
}

func runClient(t *testing.T, head, args []string) result {
	t.Helper()
	cmdArgs := append([]string{"run", "--rm", "--network", network, "--label", "ethernetip-interop.run=1"}, head...)
	cmdArgs = append(cmdArgs, args...)
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var r result
	if jerr := json.Unmarshal(lastLine(out.Bytes()), &r); jerr != nil {
		t.Fatalf("%s: no result document (exit %v): %s\nstderr: %s", strings.Join(cmdArgs, " "), err, out.String(), errb.String())
	}
	if !r.ok() {
		t.Logf("%s: %s\nstderr: %s", strings.Join(args, " "), out.String(), tail(errb.String(), 2000))
	}
	return r
}

func lastLine(b []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	return lines[len(lines)-1]
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// The matrix of results: feature, role, reference, outcome.
type row struct {
	Feature   string `json:"feature"`
	Direction string `json:"direction"` // "go->ref" (go-ethernetip originator) or "ref->go"
	Reference string `json:"reference"`
	Status    string `json:"status"` // pass, fail, n/a
	Test      string `json:"test"`
	Note      string `json:"note,omitempty"`
}

var (
	matrixMu sync.Mutex
	matrix   []row
)

// record adds a row; status follows the test's outcome unless it is n/a.
func record(t *testing.T, feature, direction, reference, note string) {
	t.Helper()
	t.Cleanup(func() {
		st := "pass"
		if t.Failed() {
			st = "fail"
		}
		if t.Skipped() {
			st = "skipped"
		}
		matrixMu.Lock()
		matrix = append(matrix, row{feature, direction, reference, st, t.Name(), note})
		matrixMu.Unlock()
	})
}

// notApplicable records a feature the reference does not have.
func notApplicable(feature, direction, reference, why string) {
	matrixMu.Lock()
	matrix = append(matrix, row{feature, direction, reference, "n/a", "", why})
	matrixMu.Unlock()
}

// writeMatrix writes interop/results/matrix.json when
// ETHERNETIP_INTEROP_WRITE_MATRIX is set.
func writeMatrix() {
	if os.Getenv("ETHERNETIP_INTEROP_WRITE_MATRIX") == "" {
		return
	}
	matrixMu.Lock()
	defer matrixMu.Unlock()
	sort.SliceStable(matrix, func(i, j int) bool {
		a, b := matrix[i], matrix[j]
		if a.Reference != b.Reference {
			return a.Reference < b.Reference
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		return a.Feature < b.Feature
	})
	versions := map[string]string{}
	for _, n := range append([]string{"opener", "cpppo", "eipscanner", "pycomm3"}, generic(genericClients)...) {
		if !selected(n) {
			continue
		}
		v, _ := dockerOut("run", "--rm", image(n), "version")
		versions[n] = strings.TrimSpace(v)
	}
	doc := map[string]any{"interopRelease": interopRelease, "generated": time.Now().UTC().Format(time.RFC3339),
		"images": versions, "rows": matrix}
	b, _ := json.MarshalIndent(doc, "", "  ")
	_, self, _, _ := runtime.Caller(0)
	_ = os.WriteFile(filepath.Join(filepath.Dir(self), "results", "matrix.json"), append(b, '\n'), 0o644)
}
