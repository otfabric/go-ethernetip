// SPDX-License-Identifier: MIT

package logx

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
)

// plainLogger records formatted entries; it implements only ethernetip.Logger.
type plainLogger struct {
	mu    sync.Mutex
	lines []string
}

func (p *plainLogger) add(level, f string, a []any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, level+" "+fmt.Sprintf(f, a...))
}
func (p *plainLogger) Debugf(f string, a ...any) { p.add("D", f, a) }
func (p *plainLogger) Infof(f string, a ...any)  { p.add("I", f, a) }
func (p *plainLogger) Warnf(f string, a ...any)  { p.add("W", f, a) }
func (p *plainLogger) Errorf(f string, a ...any) { p.add("E", f, a) }

// debugGate is a plain logger that reports whether debug is enabled.
type debugGate struct {
	plainLogger
	on bool
}

func (d *debugGate) DebugEnabled() bool { return d.on }

func TestNilLogger(t *testing.T) {
	if New(nil, "client") != nil {
		t.Fatal("New(nil) must return nil")
	}
	var l *Logger
	if l.With("a", 1) != nil {
		t.Error("nil With must return nil")
	}
	if l.DebugEnabled() {
		t.Error("nil logger reports debug enabled")
	}
	// None of these may panic.
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.DebugContext(context.Background(), "x")
	l.WarnContext(context.Background(), "x")
}

func TestPlainLogger(t *testing.T) {
	p := &plainLogger{}
	l := New(p, "server", "addr", "1.2.3.4")
	if !l.DebugEnabled() {
		t.Error("a logger without DebugEnabled must report debug enabled")
	}
	l.Debug("d", "k", 1)
	l.Info("i")
	l2 := l.With("session", 7)
	l2.Warn("w", "err", "boom")
	l2.Error("e")
	l2.DebugContext(context.Background(), "dc", "n", 2)
	l2.WarnContext(context.Background(), "wc")
	want := []string{
		"D ethernetip server addr=1.2.3.4: d k=1",
		"I ethernetip server addr=1.2.3.4: i",
		"W ethernetip server addr=1.2.3.4 session=7: w err=boom",
		"E ethernetip server addr=1.2.3.4 session=7: e",
		"D ethernetip server addr=1.2.3.4 session=7: dc n=2",
		"W ethernetip server addr=1.2.3.4 session=7: wc",
	}
	if strings.Join(p.lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(p.lines, "\n"), strings.Join(want, "\n"))
	}
	// With must not alias the parent's fields.
	l.Info("again")
	if got := p.lines[len(p.lines)-1]; got != "I ethernetip server addr=1.2.3.4: again" {
		t.Errorf("parent logger changed by With: %q", got)
	}
}

func TestDebugEnabledDelegates(t *testing.T) {
	g := &debugGate{}
	l := New(g, "scanner")
	if l.DebugEnabled() {
		t.Error("DebugEnabled = true, want false from the base logger")
	}
	g.on = true
	if !l.DebugEnabled() {
		t.Error("DebugEnabled = false, want true from the base logger")
	}
}

func TestFieldAndContextLogger(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}})
	l := New(ethernetip.NewSlogLogger(h), "client", "remote", "r1")
	if !l.DebugEnabled() {
		t.Error("slog handler at debug level must enable debug")
	}
	l.Debug("d", "k", 1)
	l.Info("i", "k", 2)
	l.Warn("w", "k", 3)
	l.Error("e", "k", 4)
	l.With("conn", 9).DebugContext(context.Background(), "dc", "k", 5)
	l.WarnContext(context.Background(), "wc", "k", 6)
	for _, want := range []string{
		"level=DEBUG msg=d component=ethernetip.client remote=r1 k=1",
		"level=INFO msg=i component=ethernetip.client remote=r1 k=2",
		"level=WARN msg=w component=ethernetip.client remote=r1 k=3",
		"level=ERROR msg=e component=ethernetip.client remote=r1 k=4",
		"level=DEBUG msg=dc component=ethernetip.client remote=r1 conn=9 k=5",
		"level=WARN msg=wc component=ethernetip.client remote=r1 k=6",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, buf.String())
		}
	}

	var info bytes.Buffer
	li := New(ethernetip.NewSlogLogger(slog.NewTextHandler(&info, nil)), "client")
	if li.DebugEnabled() {
		t.Error("slog handler at info level must disable debug")
	}
}
