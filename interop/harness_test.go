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
// otfabric/ethernetip-interop v0.4.0 (OpENer d8820ef, cpppo 5.2.5,
// EIPScanner 12c89a5, pycomm3 1.2.16, libplctag 2.7.2, gologix 0.44.0-beta,
// pylogix 1.1.6, etherip ce0688a, eip-rs 16e2236, node-ethernet-ip 2.0.0,
// EEIP.NET 58b91a0, go-ethernet-ip (loki-os) 535f797), pinned by multi-arch index digest so
// that a run is reproducible. Override per image to try another build, for
// example the images "make images" builds in ethernetip-interop:
//
//	ETHERNETIP_INTEROP_<ADAPTER>_IMAGE (OPENER, CPPPO, EIPSCANNER, PYCOMM3,
//	LIBPLCTAG, GOLOGIX, PYLOGIX, ETHERIP, EIPRS, NODEEIP, EEIP, LOKIEIP)
//
// or ETHERNETIP_INTEROP_VERSION=dev (a tag) for all of them.
const interopRelease = "v0.4.0"

var pinned = map[string]string{
	"opener":     "sha256:553ba14c06afed0fcb943df0d2e018962ffacfa005202d170fdde1c45e004cc0",
	"eipscanner": "sha256:90b2dcc334f28f4a089d745fc3ba2e4be57074784bbf19ce8fbac7320041a48c",
	"cpppo":      "sha256:7a6a21379273c50723f0460f79a1d5bd5c55172b12482fee8e4918c585367fff",
	"pycomm3":    "sha256:ab0f4c94371ee015fe6a8334ce97365c2a1ee5a58801d50575a6ea9dfce13c19",
	"libplctag":  "sha256:9545f3769f9a208ad23287e524ae867bb9028006c5d95ba353c61632b59c9bb5",
	"gologix":    "sha256:247df02e99413196e1e05f9d03b072c605b67bd319d00b12fdb8f91ae7b45d6f",
	"pylogix":    "sha256:9f18bed8b840147a06189e46e70ef36c1ff1de2bca3ee1c03cbaf981fb6fc01f",
	"etherip":    "sha256:0ec23abe6438033478c22f428a10970d69bcf180c9d4f7ce61f7a98b9837667b",
	"eiprs":      "sha256:47da222e9c8189be948f3a0a69c6aaa2415384c1806c8ff89152ce76ee8d29fa",
	"nodeeip":    "sha256:1e94e470e526730e699850a2b5f738b6ef3e45541134ed925ad1a140a1eb621c",
	"eeip":       "sha256:b539af2d94988ee5fede9f8c8e750d11a4bde90cffce3af536948a415dfd7a4e",
	"lokieip":    "sha256:c9dd85e74e4846494d1f8aa37989f1b078c8f984ef3dfd64b1c192c816b9b38b",
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
	for _, n := range append([]string{"opener", "cpppo", "eipscanner", "pycomm3"}, genericClients...) {
		v, _ := dockerOut("run", "--rm", image(n), "version")
		versions[n] = strings.TrimSpace(v)
	}
	doc := map[string]any{"interopRelease": interopRelease, "generated": time.Now().UTC().Format(time.RFC3339),
		"images": versions, "rows": matrix}
	b, _ := json.MarshalIndent(doc, "", "  ")
	_, self, _, _ := runtime.Caller(0)
	_ = os.WriteFile(filepath.Join(filepath.Dir(self), "results", "matrix.json"), append(b, '\n'), 0o644)
}
