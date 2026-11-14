// SPDX-License-Identifier: MIT

package scanner

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
)

// The application's code that does not return normally: OnInput and
// OnState are logged with their stack at Error level, and the connection
// goes on.

// stopAbnormally ends the application's code that calls it without a
// normal return.
func stopAbnormally() { panic(errors.New("stopped by test")) }

// recLogger records the entries of a scanner.
type recLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLogger) add(level, f string, a []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(f, a...))
}
func (l *recLogger) Debugf(f string, a ...any) { l.add("DEBUG", f, a) }
func (l *recLogger) Infof(f string, a ...any)  { l.add("INFO", f, a) }
func (l *recLogger) Warnf(f string, a ...any)  { l.add("WARN", f, a) }
func (l *recLogger) Errorf(f string, a ...any) { l.add("ERROR", f, a) }

// failed returns the number of Error entries, with their stack, of the
// application's code named name that did not return normally.
func (l *recLogger) failed(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.lines {
		if strings.HasPrefix(e, "ERROR ") && strings.Contains(e, "application code did not return normally callback="+name+" ") &&
			strings.Contains(e, "value=stopped by test") && strings.Contains(e, "stopAbnormally") {
			n++
		}
	}
	return n
}

// TestOnInputDoesNotReturnNormally: the failure is logged and the
// connection goes on: the next input reaches OnInput.
func TestOnInputDoesNotReturnNormally(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	log := &recLogger{}
	s := newScanner(t, dial(t, a.addr), WithLogger(log))
	var calls atomic.Int32
	again := make(chan struct{})
	cfg := owner(5 * time.Millisecond)
	cfg.OnInput = func([]byte, bool) {
		switch calls.Add(1) {
		case 1:
			// New data at the target: a new input follows.
			_ = a.in.SetData([]byte{1, 0, 0, 0, 0, 0, 0, 0})
			stopAbnormally()
		case 2:
			close(again)
		}
	}
	ctx := ctxT(t)
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-again:
	case <-time.After(5 * time.Second):
		t.Fatal("OnInput not called after the call that did not return normally")
	}
	if n := log.failed("OnInput"); n != 1 {
		t.Errorf("%d Error entries for OnInput, want 1", n)
	}
	if st := io.State(); st != ethernetip.StateConnected {
		t.Errorf("state %v, want connected", st)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestOnStateDoesNotReturnNormally: the failure is logged and the state
// change stands.
func TestOnStateDoesNotReturnNormally(t *testing.T) {
	a := startAdapter(t, "127.0.0.1:0")
	log := &recLogger{}
	s := newScanner(t, dial(t, a.addr), WithLogger(log))
	cfg := owner(5 * time.Millisecond)
	cfg.OnState = func(ethernetip.State, error) { stopAbnormally() }
	ctx := ctxT(t)
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st := io.State(); st != ethernetip.StateConnected {
		t.Errorf("state %v after Open, want connected", st)
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if st := io.State(); st != ethernetip.StateDisconnected {
		t.Errorf("state %v after Close, want disconnected", st)
	}
	// Connecting, connected and disconnected.
	if n := log.failed("OnState"); n != 3 {
		t.Errorf("%d Error entries for OnState, want 3", n)
	}
}
