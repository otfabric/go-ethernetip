// SPDX-License-Identifier: MIT

// Package callback is how the library calls the application's code: a
// handler, a callback or a metrics hook that does not return normally is
// stopped at the library's boundary, logged at Error level with its stack,
// and reported to the library's caller, which then goes on as documented
// for that call. The process keeps running.
package callback

import (
	"fmt"
	"runtime/debug"

	"github.com/otfabric/go-ethernetip/internal/logx"
)

// Do calls f, the application's code named name ("OnData",
// "Object.ServeCIP", ...), and reports whether it returned normally. When it
// did not, the failure is logged to log with what it ended with and its
// stack, and Do returns false.
func Do(log *logx.Logger, name string, f func()) (ok bool) {
	defer func() {
		if !ok {
			Failed(log, name, recover())
		}
	}()
	f()
	return true
}

// Failed logs the application's code named name that did not return
// normally; v is what it ended with.
func Failed(log *logx.Logger, name string, v any) {
	log.Error("application code did not return normally", "callback", name, "value", fmt.Sprint(v), "stack", string(debug.Stack()))
}
