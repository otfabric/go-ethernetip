// SPDX-License-Identifier: MIT

package implicit

import (
	"encoding/binary"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chaosSeed returns the seed of a chaos test: ETHERNETIP_CHAOS_SEED when
// set, the clock otherwise. The test logs it on failure, so that a failing
// run can be repeated.
func chaosSeed(t *testing.T) int64 {
	t.Helper()
	seed := time.Now().UnixNano()
	if s := os.Getenv("ETHERNETIP_CHAOS_SEED"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("ETHERNETIP_CHAOS_SEED=%q", s)
		}
		seed = v
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("chaos seed %d: repeat with ETHERNETIP_CHAOS_SEED=%d", seed, seed)
		}
	})
	return seed
}

// lossy returns a fault function that drops, duplicates and reorders
// datagrams with the given probabilities, from a seeded generator. While
// off is set, datagrams pass unchanged (and a held one is released).
func lossy(seed int64, drop, dup, reorder float64, off *atomic.Bool) func([]byte) [][]byte {
	rng := rand.New(rand.NewSource(seed))
	var held []byte
	return func(b []byte) [][]byte {
		b = append([]byte(nil), b...)
		if off.Load() {
			out := [][]byte{b}
			if held != nil {
				out = append([][]byte{held}, out...)
				held = nil
			}
			return out
		}
		r := rng.Float64()
		switch {
		case r < drop:
			return nil
		case r < drop+dup:
			return [][]byte{b, b}
		case r < drop+dup+reorder && held == nil:
			held = b // sent after the next one
			return nil
		}
		if held != nil {
			h := held
			held = nil
			return [][]byte{b, h}
		}
		return [][]byte{b}
	}
}

// TestChaosExchange runs a connection in both directions while the network
// drops, duplicates and reorders datagrams: the connection stays up, the
// consumer never takes an older value for a newer one, and the data
// converges once the network behaves.
func TestChaosExchange(t *testing.T) {
	seed := chaosSeed(t)
	a, b := listen(t), listen(t)
	var off atomic.Bool
	a.faults = lossy(seed, 0.2, 0.1, 0.1, &off)
	b.faults = lossy(seed+1, 0.2, 0.1, 0.1, &off)

	var mu sync.Mutex
	var counter uint32
	produce := func() ([]byte, bool) {
		mu.Lock()
		defer mu.Unlock()
		return binary.BigEndian.AppendUint32(nil, counter), true
	}
	var gotMu sync.Mutex
	var got []uint32
	var timeouts atomic.Int32
	cb, err := b.Open(Config{Class: 1, ConsumedID: 1, ConsumeSize: 4, Timeout: 500 * time.Millisecond,
		ProducedID: 2, Destination: a.LocalAddr(), ProduceRPI: 2 * time.Millisecond, ProduceSize: 4,
		OnData: func(d []byte, _ bool) {
			gotMu.Lock()
			got = append(got, binary.BigEndian.Uint32(d))
			gotMu.Unlock()
		},
		OnTimeout: func() { timeouts.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	ca, err := a.Open(Config{Class: 1, ConsumedID: 2, ConsumeSize: 4, Timeout: 500 * time.Millisecond,
		ProducedID: 1, Destination: b.LocalAddr(), ProduceRPI: 2 * time.Millisecond, ProduceSize: 4,
		Produce: produce, OnTimeout: func() { timeouts.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()

	for i := 0; i < 150; i++ {
		mu.Lock()
		counter++
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	off.Store(true)
	mu.Lock()
	final := counter
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		gotMu.Lock()
		n := len(got)
		last := uint32(0)
		if n > 0 {
			last = got[n-1]
		}
		gotMu.Unlock()
		if last == final {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("data did not converge: last %d, want %d", last, final)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := timeouts.Load(); n != 0 {
		t.Fatalf("%d timeouts", n)
	}
	gotMu.Lock()
	defer gotMu.Unlock()
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("value %d after %d: an old datagram was taken for new", got[i], got[i-1])
		}
	}
	st := cb.Stats()
	if st.Dropped == 0 && st.Duplicates == 0 {
		t.Fatalf("no faults observed: %+v", st)
	}
	t.Logf("received %d values, stats %+v", len(got), st)
}

// TestChaosBlackout drops everything: the consumer times out once, within
// its timeout, and production stops.
func TestChaosBlackout(t *testing.T) {
	a, b := listen(t), listen(t)
	a.faults = func([]byte) [][]byte { return nil }
	timedOut := make(chan time.Time, 2)
	start := time.Now()
	cb, err := b.Open(Config{Class: 1, ConsumedID: 7, ConsumeSize: 4, Timeout: 80 * time.Millisecond,
		OnTimeout: func() { timedOut <- time.Now() }})
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	ca, err := a.Open(Config{Class: 1, ProducedID: 7, Destination: b.LocalAddr(), ProduceRPI: 2 * time.Millisecond, ProduceSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	select {
	case at := <-timedOut:
		if d := at.Sub(start); d < 80*time.Millisecond || d > 2*time.Second {
			t.Fatalf("timed out after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no timeout")
	}
	select {
	case <-cb.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed")
	}
	if !cb.TimedOut() {
		t.Fatal("TimedOut false")
	}
	select {
	case <-timedOut:
		t.Fatal("OnTimeout called twice")
	case <-time.After(100 * time.Millisecond):
	}
}
