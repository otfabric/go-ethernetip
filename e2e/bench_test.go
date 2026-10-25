// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/logix"
)

// BenchmarkExplicitLatency is the round trip of one unconnected
// Get_Attribute_Single over loopback.
func BenchmarkExplicitLatency(b *testing.B) {
	a := startAdapter(b)
	c := dial(b, a.addr)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConnectedLatency is the round trip of one Get_Attribute_Single
// on a Class 3 connection.
func BenchmarkConnectedLatency(b *testing.B) {
	a := startAdapter(b)
	c := dial(b, a.addr)
	ctx := context.Background()
	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = cn.Close(ctx) }()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSharedSessionThroughput sends requests from 8 goroutines over
// one session with 8 outstanding at a time.
func BenchmarkSharedSessionThroughput(b *testing.B) {
	a := startAdapter(b)
	c := dial(b, a.addr, client.WithMaxPending(8))
	ctx := context.Background()
	b.ReportAllocs()
	b.SetParallelism(8)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkConcurrentClients runs one session per goroutine.
func BenchmarkConcurrentClients(b *testing.B) {
	a := startAdapter(b)
	ctx := context.Background()
	var mu sync.Mutex
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c, err := client.Dial(ctx, a.addr)
		if err != nil {
			b.Error(err)
			return
		}
		defer func() { mu.Lock(); _ = c.Close(); mu.Unlock() }()
		for pb.Next() {
			if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkMultipleService16 reads 16 attributes in one packet.
func BenchmarkMultipleService16(b *testing.B) {
	a := startAdapter(b)
	c := dial(b, a.addr)
	ctx := context.Background()
	reqs := make([]cip.Request, 16)
	for i := range reqs {
		reqs[i] = cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, uint16(1+i%7))}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.MultipleService(ctx, reqs); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLogixReadArray reads a 1000-element INT array (2000 octets,
// fragmented) over a Class 3 connection.
func BenchmarkLogixReadArray(b *testing.B) {
	a := startAdapter(b)
	ts := logix.NewTagServer()
	if err := ts.AddTag("Big", cip.TypeINT, 1000); err != nil {
		b.Fatal(err)
	}
	ts.Attach(a.srv)
	c := dial(b, a.addr)
	ctx := context.Background()
	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{Large: true})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = cn.Close(ctx) }()
	lc := logix.NewClient(cn, logix.WithMaxData(3900))
	b.SetBytes(2000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := lc.Read(ctx, "Big", 1000); err != nil {
			b.Fatal(err)
		}
	}
}
