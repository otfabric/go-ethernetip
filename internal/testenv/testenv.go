// SPDX-License-Identifier: MIT

// Package testenv decides what a test does when the machine lacks something
// it needs.
package testenv

import (
	"fmt"
	"os"
	"testing"
)

// RequireMulticast is the environment variable that turns a missing multicast
// path into a failure. CI sets it where multicast works, so that the multicast
// tests cannot silently stop running there.
const RequireMulticast = "ETHERNETIP_REQUIRE_MULTICAST"

// reporter is the part of testing.TB that Multicast uses.
type reporter interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

var _ reporter = testing.TB(nil)

// Multicast ends a test that needs multicast, which this machine does not
// deliver: a skip, or a failure when RequireMulticast is set.
func Multicast(t reporter, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv(RequireMulticast) != "" {
		t.Fatalf("%s is set: %s", RequireMulticast, msg)
		return
	}
	t.Skipf("%s", msg)
}
