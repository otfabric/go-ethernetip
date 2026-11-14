// SPDX-License-Identifier: MIT

package testenv

import (
	"bytes"
	"strings"
	"sync"
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

// waitIn waits for wg in a function of its own: the waiter of the tests of
// Waiting.
func waitIn(wg *sync.WaitGroup) { wg.Wait() }

func TestWaiting(t *testing.T) {
	var r fatalRec
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		waitIn(&wg)
		close(done)
	}()
	if !waiting(&r, done, "testenv.waitIn", []string{"testenv.TestWaiting"}, 5*time.Second) || r.msg != "" {
		t.Fatalf("goroutine in waitIn not found: %q", r.msg)
	}
	if !Waiting(&r, done, "testenv.waitIn") || r.msg != "" {
		t.Fatalf("Waiting: goroutine in waitIn not found: %q", r.msg)
	}
	never := make(chan struct{})
	for _, tc := range []struct {
		waiter string
		in     []string
	}{
		{"testenv.park", nil},
		{"testenv.waitIn", []string{"not in the stack"}},
	} {
		r.msg = ""
		if waiting(&r, never, tc.waiter, tc.in, 20*time.Millisecond) || r.msg == "" {
			t.Errorf("waiter %s, in %q: found, or no failure (%q)", tc.waiter, tc.in, r.msg)
		}
	}
	wg.Done()
	<-done
	r.msg = ""
	if waiting(&r, done, "testenv.waitIn", nil, 5*time.Second) || r.msg != "" {
		t.Errorf("done closed: found, or a failure (%q)", r.msg)
	}
}

func TestWaitsIn(t *testing.T) {
	stack := "goroutine 7 [semacquire]:\nsync.runtime_SemacquireWaitGroup(0x1)\n\tsema.go:1 +0x1\n" +
		"sync.(*WaitGroup).Wait(0x1)\n\twaitgroup.go:1 +0x1\n" +
		module + "implicit.(*Connection).close(0x1)\n\tconnection.go:1 +0x1\n" +
		module + "implicit.(*Endpoint).Close(0x1)\n\tendpoint.go:1 +0x1"
	for _, tc := range []struct {
		stack, waiter string
		in            []string
		want          bool
	}{
		{stack, "implicit.(*Connection).", nil, true},
		{stack, "implicit.(*Connection).", []string{"implicit.(*Endpoint).Close"}, true},
		{stack, "implicit.(*Endpoint).Close", nil, false},
		{stack, "implicit.(*Connection).", []string{"server."}, false},
		{"goroutine 7 [semacquire]:\nsync.(*WaitGroup).Wait(0x1)\n\twaitgroup.go:1 +0x1", "implicit.", nil, false},
		{"goroutine 7 [chan receive]:\n" + module + "implicit.(*Connection).close(0x1)", "implicit.", nil, false},
	} {
		if got := waitsIn(tc.stack, tc.waiter, tc.in); got != tc.want {
			t.Errorf("waitsIn(%q, %q, %q) = %v, want %v", tc.stack, tc.waiter, tc.in, got, tc.want)
		}
	}
}

func TestBlocking(t *testing.T) {
	// A Close that waits for the callback's goroutine.
	b := NewBlocking()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.Call()
	}()
	var r fatalRec
	b.Check(&r, func() {
		go func() {
			waitIn(&wg)
			b.Closed()
		}()
	}, "testenv.waitIn")
	if r.msg != "" {
		t.Fatalf("Close that waits: %s", r.msg)
	}
	b.Call() // a later call returns at once

	// A Close that does not wait.
	b = NewBlocking()
	called := make(chan struct{})
	go func() {
		b.Call()
		close(called)
	}()
	b.check(&r, func() { go b.Closed() }, "testenv.waitIn", nil, 5*time.Second)
	<-called // released by check
	if r.msg != "Close returned while the callback was in progress" {
		t.Errorf("Close that does not wait: %q", r.msg)
	}

	// A Close that waits for something else, which does not end.
	b = NewBlocking()
	var other sync.WaitGroup
	other.Add(1)
	go b.Call()
	r.msg = ""
	b.check(&r, func() {
		go func() {
			waitIn(&other)
			b.Closed()
		}()
	}, "testenv.waitIn", nil, 50*time.Millisecond)
	if r.msg != "Close has not returned after the callback returned" {
		t.Errorf("Close that does not return: %q", r.msg)
	}
	other.Done()
	<-b.done

	// A callback that is not called.
	b = NewBlocking()
	r.msg = ""
	b.check(&r, func() { t.Error("start called") }, "testenv.waitIn", nil, 20*time.Millisecond)
	if r.msg != "the callback was not called" {
		t.Errorf("callback not called: %q", r.msg)
	}
}
