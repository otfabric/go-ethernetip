// SPDX-License-Identifier: MIT

package e2e

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain checks, after all the tests, that no goroutine and no file
// descriptor (socket) is left behind: every client, scanner, server and
// connection the tests opened must have released what it started.
func TestMain(m *testing.M) {
	goroutines := runtime.NumGoroutine()
	fds := openFDs()
	code := m.Run()
	if code == 0 {
		if err := checkLeaks(goroutines, fds); err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func checkLeaks(goroutines, fds int) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		g, f := runtime.NumGoroutine(), openFDs()
		if g <= goroutines+2 && (fds < 0 || f <= fds+2) {
			return nil
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			return fmt.Errorf("leak: %d goroutines (started with %d), %d descriptors (started with %d)\n%s",
				g, goroutines, f, fds, filterStacks(string(buf[:n])))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// openFDs returns the number of open file descriptors of the process, or
// -1 where /dev/fd is not available.
func openFDs() int {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// filterStacks keeps the goroutines that run code of this module.
func filterStacks(all string) string {
	var out []string
	for _, g := range strings.Split(all, "\n\n") {
		if strings.Contains(g, "otfabric/go-ethernetip/") && !strings.Contains(g, "TestMain") {
			out = append(out, g)
		}
	}
	return strings.Join(out, "\n\n")
}
