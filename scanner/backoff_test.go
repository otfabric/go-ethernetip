// SPDX-License-Identifier: MIT

package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// TestReopenJitter: the reopen loop waits d/2 plus a random part of d/2
// before each attempt (equal jitter), d doubling from MinDelay up to
// MaxDelay. The test replaces the timer and the random source: nothing
// sleeps.
func TestReopenJitter(t *testing.T) {
	const minD, maxD = 10 * time.Millisecond, 160 * time.Millisecond
	var opens atomic.Int32
	f := newFakeTarget(t, func(fo cip.ForwardOpen) (cip.ForwardOpenReply, []encap.Item) {
		if opens.Add(1) == 1 {
			return okReply(fo), nil
		}
		return cip.ForwardOpenReply{}, nil // refused: the reopen loop goes on
	})
	s := newScanner(t, dial(t, f.ln.Addr().String()))
	const attempts = 10
	var mu sync.Mutex
	var waits []time.Duration
	var draws []int64
	enough := make(chan struct{})
	s.after = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		defer mu.Unlock()
		waits = append(waits, d)
		ch := make(chan time.Time, 1)
		switch {
		case len(waits) <= attempts:
			ch <- time.Time{}
		case len(waits) == attempts+1:
			close(enough) // this wait does not end
		}
		return ch
	}
	s.rnd = func(n int64) int64 {
		mu.Lock()
		defer mu.Unlock()
		v := int64(len(draws)) * 7919 % n
		draws = append(draws, n)
		return v
	}
	ctx := ctxT(t)
	cfg := owner(5 * time.Millisecond)
	cfg.Reconnect = &Reconnect{MinDelay: minD, MaxDelay: maxD}
	io, err := s.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-enough:
	case <-time.After(10 * time.Second):
		t.Fatalf("%d reopen waits", len(waits))
	}
	if err := io.Close(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	d := minD
	for i, w := range waits {
		want := d/2 + time.Duration(int64(i)*7919%int64(d-d/2+1))
		if w != want || w < d/2 || w > d || w > maxD {
			t.Errorf("wait %d = %v, want %v (d %v)", i, w, want, d)
		}
		d = min(2*d, maxD)
	}
}

// TestBackoffBounds: the waits stay within [d/2, d] for the extreme draws,
// the first delay is capped by MaxDelay, and doubling near the largest
// duration does not wrap.
func TestBackoffBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Reconnect
		rnd  func(int64) int64
	}{
		{"defaults, lowest draw", Reconnect{}, func(int64) int64 { return 0 }},
		{"defaults, highest draw", Reconnect{}, func(n int64) int64 { return n - 1 }},
		{"MinDelay above MaxDelay", Reconnect{MinDelay: time.Hour, MaxDelay: time.Second}, func(n int64) int64 { return n - 1 }},
		{"1 ns", Reconnect{MinDelay: 1, MaxDelay: 1}, func(n int64) int64 { return n - 1 }},
		{"largest duration", Reconnect{MinDelay: 1 << 61, MaxDelay: 1<<63 - 1}, func(n int64) int64 { return n - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBackoff(tc.r, tc.rnd)
			for i := range 8 {
				d := b.d
				w := b.next()
				if w < d/2 || w > d || w > b.max || w < 0 {
					t.Fatalf("wait %d = %v, d %v, max %v", i, w, d, b.max)
				}
			}
		})
	}
}
