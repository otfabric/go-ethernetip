// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/logix"
	"github.com/otfabric/go-ethernetip/scanner"
)

// monkeyDuration is how long the chaos monkey runs:
// ETHERNETIP_MONKEY_DURATION (a Go duration), else 3 s (1 s with -short).
func monkeyDuration(t *testing.T) time.Duration {
	t.Helper()
	if s := os.Getenv("ETHERNETIP_MONKEY_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("ETHERNETIP_MONKEY_DURATION=%q", s)
		}
		return d
	}
	if testing.Short() {
		return time.Second
	}
	return 3 * time.Second
}

// monkeyError reports whether err is one the monkey's faults may cause:
// what allowedChaosError allows, a CIP refusal (an owned assembly, a
// connection point in use, a full connection table) or the operation's
// own deadline.
func monkeyError(err error) bool {
	var ce *ethernetip.CIPError
	return allowedChaosError(err) || errors.As(err, &ce) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ethernetip.ErrClosed)
}

// monkeyTag tracks a tag only one worker writes. A write whose reply was
// lost may still be applied, even after later writes (its request can sit
// in a dying connection and arrive late): its value stays possible for
// good, and so do the bits of unconfirmed bit writes.
type monkeyTag struct {
	name        string
	ok          int64   // the value last seen confirmed
	unconfirmed []int64 // values of writes never confirmed
	lateBits    int64   // bits of bit writes never confirmed
}

// possible reports whether the tag can hold v given that its last
// confirmed value is ok: ok or an unconfirmed write, with any of the late
// bits set.
func (m *monkeyTag) possible(ok, v int64) bool {
	mask := ^m.lateBits
	if v&mask == ok&mask {
		return true
	}
	for _, u := range m.unconfirmed {
		if v&mask == u&mask {
			return true
		}
	}
	return false
}

// TestChaosMonkey runs workers that pick operations at random (explicit
// requests, Multiple Service Packets, Class 3 connections, Logix reads,
// writes and bit writes, Class 1 connections, client churn) through a
// proxy that splits, delays and kills connections. Every answer that
// arrives must be right, every failure of an allowed kind; afterwards the
// adapter serves a clean client, each worker's tag holds a value the worker
// wrote, the I/O connections are gone and nothing leaks (TestMain).
// ETHERNETIP_CHAOS_SEED repeats a run.
func TestChaosMonkey(t *testing.T) {
	seed := chaosSeed(t)
	a, ts := startLogix(t)
	const workers = 4
	for i := 0; i < workers; i++ {
		must(t, ts.AddTag(fmt.Sprintf("Monkey%d", i), cip.TypeDINT))
	}
	p := newChaosProxy(t, a.addr, seed, false)
	name := testIdentity.ProductName
	end := time.Now().Add(monkeyDuration(t))

	var ops, fails atomic.Int64
	tags := make([]*monkeyTag, workers)
	errc := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		tags[w] = &monkeyTag{name: fmt.Sprintf("Monkey%d", w)}
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			errc <- monkeyWorker(rand.New(rand.NewSource(seed+int64(w))), p, tags[w], name, end, &ops, &fails)
		}(w)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ops.Load() == 0 || p.kills.Load() == 0 {
		t.Fatalf("%d operations, %d connections killed: the monkey did nothing", ops.Load(), p.kills.Load())
	}

	// The faults stop: everything works and the state is consistent.
	p.enabled.Store(false)
	ctx := ctxT(t)
	c := dial(t, a.addr)
	if id, err := c.Identity(ctx); err != nil || id.ProductName != name {
		t.Fatalf("identity after the monkey: %+v %v", id, err)
	}
	lc := logix.NewClient(c)
	for _, tg := range tags {
		v, err := lc.Read(ctx, tg.name, 1)
		if err != nil {
			t.Fatal(err)
		}
		if x, _ := v.Int(0); !tg.possible(tg.ok, x) {
			t.Fatalf("%s = %d, not a value its worker wrote (last confirmed %d)", tg.name, x, tg.ok)
		}
	}
	// I/O connections whose Forward_Close was lost time out.
	eventually(t, 15*time.Second, "I/O connections gone", func() bool { return len(a.srv.Connections()) == 0 })
	t.Logf("%d operations, %d allowed failures, %d connections killed", ops.Load(), fails.Load(), p.kills.Load())
}

func monkeyWorker(rng *rand.Rand, p *chaosProxy, tag *monkeyTag, name string, end time.Time,
	ops, fails *atomic.Int64) error {
	newClient := func() (*client.Client, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return client.Dial(ctx, p.addr(), client.WithAutoReconnect(), client.WithTimeout(500*time.Millisecond))
	}
	var c *client.Client
	defer func() {
		if c != nil {
			_ = c.Close()
		}
	}()
	var s *scanner.Scanner
	closeScanner := func() {
		if s != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = s.Close(ctx)
			cancel()
			s = nil
		}
	}
	defer closeScanner()
	check := func(what string, err error) error {
		if err == nil {
			return nil
		}
		if !monkeyError(err) {
			return fmt.Errorf("%s: unexpected error: %w", what, err)
		}
		fails.Add(1)
		return nil
	}
	for time.Now().Before(end) {
		if c == nil {
			var err error
			if c, err = newClient(); err != nil {
				if e := check("dial", err); e != nil {
					return e
				}
				c = nil
				continue
			}
		}
		ops.Add(1)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var err error
		var what string
		switch op := rng.Intn(9); op {
		case 0:
			what = "Get_Attribute_Single"
			var b []byte
			if b, err = c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7); err == nil && string(b[1:]) != name {
				err = fmt.Errorf("product name %q", b)
			}
		case 1:
			what = "Multiple Service Packet"
			var rs []cip.Response
			rs, err = c.MultipleService(ctx, []cip.Request{
				{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
				{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)},
			})
			if err == nil && (len(rs) != 2 || rs[0].Status != 0 || rs[1].Status != cip.StatusAttributeNotSupported) {
				err = fmt.Errorf("replies %+v", rs)
			}
		case 2:
			what = "Class 3"
			var cn *client.Conn
			if cn, err = c.OpenConnection(ctx, client.ConnectionOptions{Large: rng.Intn(2) == 0}); err == nil {
				var r cip.Response
				if r, err = cn.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)}); err == nil && string(r.Data[1:]) != name {
					err = fmt.Errorf("Class 3 product name %q", r.Data)
				}
				_ = cn.Close(ctx)
			}
		case 3, 4:
			what = "Logix write and read"
			v := rng.Int63n(1<<31) - 1<<30
			val, _ := logix.Ints(cip.TypeDINT, v)
			lc := logix.NewClient(c)
			if err = lc.Write(ctx, tag.name, val); err != nil {
				tag.unconfirmed = append(tag.unconfirmed, v)
			} else {
				tag.ok = v
				var got logix.Value
				if got, err = lc.Read(ctx, tag.name, 1); err == nil {
					if x, _ := got.Int(0); !tag.possible(v, x) {
						err = fmt.Errorf("%s = %d after writing %d", tag.name, x, v)
					} else {
						tag.ok = x
					}
				}
			}
		case 5:
			what = "Logix bit write"
			bit := rng.Intn(32)
			lc := logix.NewClient(c)
			if err = lc.WriteBit(ctx, fmt.Sprintf("%s.%d", tag.name, bit), 4, true); err != nil {
				tag.lateBits |= 1 << bit
			} else {
				// The bit is set, unless an unconfirmed write landed after
				// it.
				var got logix.Value
				if got, err = lc.Read(ctx, tag.name, 1); err == nil {
					x, _ := got.Int(0)
					if x&(1<<bit) == 0 && !tag.possible(int64(int32(tag.ok|1<<bit)), x) {
						err = fmt.Errorf("%s = %#x: bit %d not set", tag.name, x, bit)
					}
					tag.ok = x
				}
			}
		case 6:
			what = "Class 1 I/O"
			if s == nil {
				// Each worker's I/O has its own endpoint (its own UDP port):
				// T->O goes to the originator's announced port.
				if s, err = scanner.New(c, scanner.WithLocalAddr("127.0.0.1:0")); err != nil {
					break
				}
			}
			cfg := exclusiveOwner(10 * time.Millisecond)
			cfg.TimeoutMultiplier = 3
			if rng.Intn(2) == 0 {
				cfg.OutputInstance, cfg.OutputSize = asmInputOnly, 0 // input-only: no ownership conflict
				cfg.ConfigInstance = 0
			}
			var io *scanner.IO
			if io, err = s.Open(ctx, cfg); err == nil {
				out := bytes.Repeat([]byte{byte(rng.Intn(256))}, cfg.OutputSize)
				if cfg.OutputSize > 0 {
					_ = io.SetOutput(out)
				}
				time.Sleep(time.Duration(20+rng.Intn(60)) * time.Millisecond)
				err = io.Close(ctx)
			}
		case 7:
			what = "client churn"
			_ = c.Close()
			closeScanner()
			c = nil
		default:
			what = "Set_Attribute_Single"
			// Assembly 150 may be owned by a Class 1 connection: then it is
			// refused, which is allowed.
			err = c.SetAttributeSingle(ctx, cip.ClassAssembly, asmOutput, 3, bytes.Repeat([]byte{byte(rng.Intn(256))}, ioSize))
		}
		cancel()
		if e := check(what, err); e != nil {
			return e
		}
	}
	return nil
}
