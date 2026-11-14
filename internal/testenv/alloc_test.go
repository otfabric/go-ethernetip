// SPDX-License-Identifier: MIT

package testenv

import (
	"strings"
	"testing"
	"time"
)

var sink []byte

func TestPerCall(t *testing.T) {
	a := PerCall(t, 100, func() { sink = make([]byte, 1<<20) })
	if a.Octets < 1<<20 || a.Octets > 2<<20 || a.Allocs != 1 {
		t.Errorf("1 MiB allocation measured as %v", a)
	}
	sink = nil
	if a := PerCall(t, 100, func() {}); a.Octets != 0 || a.Allocs != 0 {
		t.Errorf("no allocation measured as %v", a)
	}
	if s := (Allocation{Allocs: 2, Octets: 64}).String(); s != "64 octets in 2 allocations per call" {
		t.Errorf("String = %q", s)
	}
	// Runs below 1 measure one call.
	if a := PerCall(t, 0, func() { sink = make([]byte, 4096) }); a.Octets != 4096 {
		t.Errorf("one call measured as %v", a)
	}
	sink = nil
}

// TestPerCallOtherGoroutine: a goroutine of the module that runs during
// the measurement fails it.
func TestPerCallOtherGoroutine(t *testing.T) {
	var r fatalRec
	stop := make(chan struct{})
	park(stop)
	calls := 0
	perCall(&r, 10, func() { calls++ }, 50*time.Millisecond)
	close(stop)
	if !strings.Contains(r.msg, "running during an allocation measurement") || calls != 0 {
		t.Fatalf("goroutine not reported (%q), %d calls", r.msg, calls)
	}
}

func TestRunning(t *testing.T) {
	stacks := []string{
		"goroutine 1 [chan receive]:\ntesting.(*T).Run(0xc000)\n" + module + "encap_test.TestCPF()",
		"goroutine 2 [chan receive]:\ntesting.(*T).Parallel(0xc000)\n" + module + "eds.TestParse()",
		"goroutine 3 [IO wait]:\n" + module + "implicit.(*Connection).run()",
		"goroutine 4 [select]:\nnet/http.(*persistConn).readLoop()",
	}
	if got := running(stacks); len(got) != 1 || !strings.HasPrefix(got[0], "goroutine 3 ") {
		t.Errorf("running = %q", got)
	}
}
