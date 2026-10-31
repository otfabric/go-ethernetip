// SPDX-License-Identifier: MIT

package testenv

import (
	"strings"
	"testing"
)

type recorder struct{ fatal, skip string }

func (r *recorder) Helper()                        {}
func (r *recorder) Fatalf(format string, _ ...any) { r.fatal = format }
func (r *recorder) Skipf(_ string, args ...any)    { r.skip = args[0].(string) }

func TestMulticastSkipsByDefault(t *testing.T) {
	t.Setenv("ETHERNETIP_REQUIRE_MULTICAST", "")
	var r recorder
	Multicast(&r, "no route: %v", 1)
	if r.fatal != "" || !strings.Contains(r.skip, "no route: 1") {
		t.Fatalf("%+v", r)
	}
}

func TestMulticastFailsWhenRequired(t *testing.T) {
	t.Setenv("ETHERNETIP_REQUIRE_MULTICAST", "1")
	var r recorder
	Multicast(&r, "no route")
	if r.fatal == "" || r.skip != "" {
		t.Fatalf("%+v", r)
	}
}
