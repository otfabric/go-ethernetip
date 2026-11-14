// SPDX-License-Identifier: MIT

package testenv

import "runtime"

// Allocated returns the octets the process allocates while f runs: the
// measure of the allocation-budget tests.
func Allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
