// SPDX-License-Identifier: MIT

package callback

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-ethernetip/internal/logx"
)

// recorder is an ethernetip.Logger that keeps its entries.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(level, f string, a []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, level+" "+fmt.Sprintf(f, a...))
}
func (r *recorder) Debugf(f string, a ...any) { r.add("D", f, a) }
func (r *recorder) Infof(f string, a ...any)  { r.add("I", f, a) }
func (r *recorder) Warnf(f string, a ...any)  { r.add("W", f, a) }
func (r *recorder) Errorf(f string, a ...any) { r.add("E", f, a) }

// stopsAbnormally is application code that does not return normally.
func stopsAbnormally() { panic(errors.New("stopped by test")) }

func TestDo(t *testing.T) {
	rec := &recorder{}
	log := logx.New(rec, "test")
	ran := false
	if !Do(log, "Normal", func() { ran = true }) || !ran {
		t.Fatal("a function that returns normally is not reported as such")
	}
	if len(rec.lines) != 0 {
		t.Fatalf("entries for a normal return: %q", rec.lines)
	}
	if Do(log, "Handler", stopsAbnormally) {
		t.Fatal("a function that does not return normally is reported as returned")
	}
	if len(rec.lines) != 1 {
		t.Fatalf("%d entries, want 1: %q", len(rec.lines), rec.lines)
	}
	e := rec.lines[0]
	for _, want := range []string{"E ", "callback=Handler", "value=stopped by test", "stopsAbnormally"} {
		if !strings.Contains(e, want) {
			t.Errorf("entry %q lacks %q", e, want)
		}
	}
	// Without a logger the failure is still stopped.
	if Do(nil, "Handler", stopsAbnormally) {
		t.Fatal("a function that does not return normally is reported as returned")
	}
}
