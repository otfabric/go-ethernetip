// SPDX-License-Identifier: MIT

package testenv

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Allocation is what one call of a function allocates, on average.
type Allocation struct {
	// Allocs is the number of allocations per call, truncated as
	// testing.AllocsPerRun reports it.
	Allocs float64
	// Octets is the number of octets allocated per call
	// (runtime.MemStats.TotalAlloc).
	Octets uint64
}

func (a Allocation) String() string {
	return fmt.Sprintf("%d octets in %v allocations per call", a.Octets, a.Allocs)
}

// ErrorOctets is what an error value and its message may allocate: the
// part of an allocation budget that is not data the code must hold.
const ErrorOctets = 1 << 10

// PerCall measures what f allocates per call the way testing.AllocsPerRun
// does, in octets as well as allocations: with GOMAXPROCS at 1, after one
// call that is not counted (one-time initialisation), as the average over
// runs calls. It first waits up to LeakWait until no other goroutine of
// this module runs, and fails t if one is left: what it allocates would be
// counted. The average keeps what the runtime and the test framework
// allocate during the measurement from deciding the result; a budget for
// Octets is derived from what the code under test must hold.
func PerCall(t reporterF, runs int, f func()) Allocation {
	t.Helper()
	return perCall(t, runs, f, LeakWait)
}

// perCall is PerCall with the wait given.
func perCall(t reporterF, runs int, f func(), wait time.Duration) Allocation {
	t.Helper()
	if left := waitIdle(wait); len(left) > 0 {
		t.Fatalf("%d goroutine(s) of the module running during an allocation measurement:\n%s", len(left), strings.Join(left, "\n\n"))
		return Allocation{}
	}
	if runs < 1 {
		runs = 1
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	f()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	n := uint64(runs)
	return Allocation{
		Allocs: float64((after.Mallocs - before.Mallocs) / n),
		Octets: (after.TotalAlloc - before.TotalAlloc) / n,
	}
}

// waitIdle polls until no goroutine of this module runs but the caller's
// and the tests that wait for it; it returns the stacks of those left
// after d.
func waitIdle(d time.Duration) []string {
	deadline := time.Now().Add(d)
	for {
		left := running(stacks())
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// running returns the stacks that run code of this module, except those of
// tests waiting for a subtest or for their turn to run in parallel.
func running(stacks []string) []string {
	var out []string
	for _, s := range leftOver(stacks, nil, "") {
		if strings.Contains(s, "testing.(*T).Run(") || strings.Contains(s, "testing.(*T).Parallel(") {
			continue
		}
		out = append(out, s)
	}
	return out
}
