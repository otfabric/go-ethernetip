// SPDX-License-Identifier: MIT

package ethernetip

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestNopLogger(t *testing.T) {
	l := NopLogger()
	l.Debugf("a %d", 1)
	l.Infof("b")
	l.Warnf("c")
	l.Errorf("d")
	if _, ok := l.(FieldLogger); ok {
		t.Error("NopLogger unexpectedly implements FieldLogger")
	}
}

func TestStdLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Debugf("d %d", 1)
	l.Infof("i %s", "x")
	l.Warnf("w")
	l.Errorf("e")
	want := "DEBUG d 1\nINFO  i x\nWARN  w\nERROR e\n"
	if buf.String() != want {
		t.Errorf("output = %q, want %q", buf.String(), want)
	}
	if NewStdLogger(nil) == nil {
		t.Error("NewStdLogger(nil) returned nil")
	}
	if sl, ok := NewStdLogger(nil).(stdLogger); !ok || sl.l == nil {
		t.Error("NewStdLogger(nil) has no underlying logger")
	}
}

func newTextHandler(buf *bytes.Buffer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
}

func TestSlogLoggerNilHandler(t *testing.T) {
	l := NewSlogLogger(nil)
	l.Infof("nothing")
	if _, ok := l.(FieldLogger); ok {
		t.Error("NewSlogLogger(nil) must be a plain no-op logger")
	}
	fl := NewSlogFieldLogger(nil)
	if fl.With("k", "v") == nil {
		t.Error("With on the no-op field logger returned nil")
	}
	fl.Debugf("x")
	fl.DebugKV("x", "k", 1)
	fl.InfoKV("x")
	fl.WarnKV("x")
	fl.ErrorKV("x")
}

func TestSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewSlogLogger(newTextHandler(&buf, slog.LevelInfo))
	l.Debugf("hidden %d", 1)
	l.Infof("info %d", 2)
	l.Warnf("warn")
	l.Errorf("error")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Errorf("debug entry written below the handler level: %q", out)
	}
	for _, want := range []string{`level=INFO msg="info 2"`, "level=WARN msg=warn", "level=ERROR msg=error"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
	if d, ok := l.(interface{ DebugEnabled() bool }); !ok || d.DebugEnabled() {
		t.Error("DebugEnabled must be false at info level")
	}
}

func TestSlogFieldLogger(t *testing.T) {
	var buf bytes.Buffer
	fl := NewSlogFieldLogger(newTextHandler(&buf, slog.LevelDebug)).With("component", "test")
	fl.DebugKV("d", "k", 1)
	fl.InfoKV("i", "k", 2)
	fl.WarnKV("w", "k", 3)
	fl.ErrorKV("e", "k", 4)
	for _, want := range []string{
		"level=DEBUG msg=d component=test k=1",
		"level=INFO msg=i component=test k=2",
		"level=WARN msg=w component=test k=3",
		"level=ERROR msg=e component=test k=4",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output %q lacks %q", buf.String(), want)
		}
	}
	if d, ok := fl.(interface{ DebugEnabled() bool }); !ok || !d.DebugEnabled() {
		t.Error("DebugEnabled must be true at debug level")
	}

	buf.Reset()
	cl, ok := fl.(ContextLogger)
	if !ok {
		t.Fatal("slog field logger does not implement ContextLogger")
	}
	ctx := context.Background()
	cl.DebugContext(ctx, "dc", "n", 1)
	cl.InfoContext(ctx, "ic", "n", 2)
	cl.WarnContext(ctx, "wc", "n", 3)
	cl.ErrorContext(ctx, "ec", "n", 4)
	for _, want := range []string{"msg=dc component=test n=1", "msg=ic component=test n=2",
		"msg=wc component=test n=3", "msg=ec component=test n=4"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output %q lacks %q", buf.String(), want)
		}
	}
}
