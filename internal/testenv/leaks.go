// SPDX-License-Identifier: MIT

package testenv

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// module is the import path prefix of the code whose goroutines are
// checked.
const module = "github.com/otfabric/go-ethernetip/"

// LeakWait is how long the leak checks wait for goroutines to end.
const LeakWait = 10 * time.Second

// runner is the part of *testing.M that RunLeakChecked uses.
type runner interface{ Run() int }

var _ runner = (*testing.M)(nil)

// RunLeakChecked runs the tests of m and then checks that every goroutine
// they started has ended: a goroutine that did not exist before the tests
// and runs code of this module is a leak. It waits up to LeakWait for them
// to end, prints the stacks of those left, and returns the exit code for
// os.Exit. Call it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(testenv.RunLeakChecked(m)) }
func RunLeakChecked(m runner) int { return runLeakChecked(m, LeakWait, os.Stderr) }

// runLeakChecked is RunLeakChecked with the wait and the output given.
func runLeakChecked(m runner, wait time.Duration, out io.Writer) int {
	before := goroutineIDs(stacks())
	code := m.Run()
	if code != 0 {
		return code
	}
	if left := waitGone(before, "", wait); len(left) > 0 {
		_, _ = fmt.Fprintf(out, "leak: %d goroutine(s) left after the tests\n%s\n", len(left), strings.Join(left, "\n\n"))
		return 1
	}
	return 0
}

// reporterF is the part of testing.TB that NoGoroutine uses.
type reporterF interface {
	Helper()
	Fatalf(format string, args ...any)
}

// NoGoroutine fails t unless, within LeakWait, no goroutine of this module
// other than the caller's has a stack that contains frame (a function name
// such as "implicit.(*Connection).run").
func NoGoroutine(t reporterF, frame string) { noGoroutine(t, frame, LeakWait) }

// noGoroutine is NoGoroutine with the wait given.
func noGoroutine(t reporterF, frame string, wait time.Duration) {
	t.Helper()
	if left := waitGone(nil, frame, wait); len(left) > 0 {
		t.Fatalf("%d goroutine(s) in %s left:\n%s", len(left), frame, strings.Join(left, "\n\n"))
	}
}

// waitGone polls until no goroutine is left that is not in before, runs
// code of this module and, when frame is set, has frame in its stack; it
// returns the stacks of those left after d.
func waitGone(before map[string]bool, frame string, d time.Duration) []string {
	deadline := time.Now().Add(d)
	for {
		left := leftOver(stacks(), before, frame)
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stacks returns the stacks of every goroutine but the caller's.
func stacks() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	all := strings.Split(string(buf), "\n\n")
	// The first is the caller's.
	return all[1:]
}

// goroutineIDs returns the IDs of the goroutines of stacks.
func goroutineIDs(stacks []string) map[string]bool {
	ids := make(map[string]bool, len(stacks))
	for _, s := range stacks {
		ids[goroutineID(s)] = true
	}
	return ids
}

// goroutineID returns the ID of a stack, "goroutine 7 [running]:...": "7".
func goroutineID(stack string) string {
	f := strings.Fields(stack)
	if len(f) < 2 || f[0] != "goroutine" {
		return ""
	}
	return f[1]
}

// leftOver returns the stacks that are not in before, run code of this
// module other than the test framework's, and contain frame.
func leftOver(stacks []string, before map[string]bool, frame string) []string {
	var out []string
	for _, s := range stacks {
		if before[goroutineID(s)] || !strings.Contains(s, module) || strings.Contains(s, "testing.(*M).") {
			continue
		}
		if frame != "" && !strings.Contains(s, frame) {
			continue
		}
		out = append(out, s)
	}
	return out
}
