// SPDX-License-Identifier: MIT

package testenv

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// fakeM is a test run: run is called as m.Run.
type fakeM func() int

func (f fakeM) Run() int { return f() }

// fatalRec records Fatalf.
type fatalRec struct{ msg string }

func (r *fatalRec) Helper()                        {}
func (r *fatalRec) Fatalf(format string, _ ...any) { r.msg = format }

// park runs a goroutine of this module until stop is closed.
func park(stop <-chan struct{}) {
	started := make(chan struct{})
	go func() {
		close(started)
		<-stop
	}()
	<-started
}

func TestRunLeakChecked(t *testing.T) {
	var out bytes.Buffer
	if code := runLeakChecked(fakeM(func() int { return 0 }), 50*time.Millisecond, &out); code != 0 || out.Len() != 0 {
		t.Fatalf("clean run: code %d, output %q", code, out.String())
	}
	if code := runLeakChecked(fakeM(func() int { return 3 }), 50*time.Millisecond, &out); code != 3 {
		t.Fatalf("failed run: code %d, want 3", code)
	}
	// A goroutine that runs before the tests is not counted.
	early := make(chan struct{})
	park(early)
	defer close(early)
	if code := runLeakChecked(fakeM(func() int { return 0 }), 50*time.Millisecond, &out); code != 0 {
		t.Fatalf("goroutine from before the tests: code %d, output %q", code, out.String())
	}
	stop := make(chan struct{})
	code := runLeakChecked(fakeM(func() int { park(stop); return 0 }), 50*time.Millisecond, &out)
	close(stop)
	if code != 1 || !strings.Contains(out.String(), "leak: 1 goroutine(s) left") || !strings.Contains(out.String(), "testenv.park") {
		t.Fatalf("goroutine left: code %d, output %q", code, out.String())
	}
	// One that ends within the wait is not a leak.
	out.Reset()
	code = runLeakChecked(fakeM(func() int {
		s := make(chan struct{})
		park(s)
		time.AfterFunc(10*time.Millisecond, func() { close(s) })
		return 0
	}), 5*time.Second, &out)
	if code != 0 {
		t.Fatalf("goroutine ending in time: code %d, output %q", code, out.String())
	}
}

func TestNoGoroutine(t *testing.T) {
	var r fatalRec
	noGoroutine(&r, "testenv.park", 50*time.Millisecond)
	if r.msg != "" {
		t.Fatalf("no goroutine: %s", r.msg)
	}
	stop := make(chan struct{})
	park(stop)
	noGoroutine(&r, "testenv.park", 50*time.Millisecond)
	close(stop)
	if r.msg == "" {
		t.Fatal("goroutine in the frame not reported")
	}
	r.msg = ""
	stop = make(chan struct{})
	park(stop)
	noGoroutine(&r, "testenv.(*Other).run", 50*time.Millisecond)
	close(stop)
	if r.msg != "" {
		t.Fatalf("goroutine of another frame reported: %s", r.msg)
	}
	NoGoroutine(&r, "testenv.(*Other).run")
	if r.msg != "" {
		t.Fatalf("NoGoroutine: %s", r.msg)
	}
}

func TestLeftOver(t *testing.T) {
	stacks := []string{
		"goroutine 1 [chan receive]:\n" + module + "client.(*session).read()",
		"goroutine 2 [select]:\nnet/http.(*persistConn).readLoop()",
		"goroutine 3 [chan receive]:\ntesting.(*M).Run()\n" + module + "client.TestMain()",
		"goroutine 4 [IO wait]:\n" + module + "implicit.(*Connection).run()",
		"not a stack",
	}
	if got := leftOver(stacks, map[string]bool{"1": true}, ""); len(got) != 1 || !strings.HasPrefix(got[0], "goroutine 4 ") {
		t.Errorf("leftOver = %q", got)
	}
	if got := leftOver(stacks, nil, "client.(*session)"); len(got) != 1 || !strings.HasPrefix(got[0], "goroutine 1 ") {
		t.Errorf("leftOver with frame = %q", got)
	}
	if id := goroutineID("not a stack"); id != "" {
		t.Errorf("goroutineID = %q", id)
	}
	if ids := goroutineIDs(stacks[:2]); !ids["1"] || !ids["2"] || len(ids) != 2 {
		t.Errorf("goroutineIDs = %v", ids)
	}
}
