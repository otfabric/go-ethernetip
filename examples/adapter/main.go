// SPDX-License-Identifier: MIT

// Command adapter runs an EtherNet/IP adapter with OpENer's sample layout:
// input assembly 100, output 150 (copied to the input), configuration 151,
// heartbeats 152 (input only) and 153 (listen only). It serves until
// interrupted, on port 44818 and I/O port 2222 by default:
//
//	go run ./examples/adapter [address]
//
// The adapter has no authentication: run it on isolated networks only.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/server"
)

func main() {
	addr := ":44818"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	srv, err := server.New(server.WithLogger(ethernetip.NewSlogLogger(slog.NewTextHandler(os.Stderr, nil))))
	if err != nil {
		log.Fatal(err)
	}
	in, _ := srv.AddAssembly(100, server.AssemblyInput, 32)
	out, _ := srv.AddAssembly(150, server.AssemblyOutput, 32)
	_, _ = srv.AddAssembly(151, server.AssemblyConfig, 10)
	_, _ = srv.AddAssembly(152, server.AssemblyInputOnly, 0)
	_, _ = srv.AddAssembly(153, server.AssemblyListenOnly, 0)
	out.OnWrite(func(data []byte, run bool) { _ = in.SetData(data) })
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("serving on %s", addr)
	if err := srv.ListenAndServe(addr); err != nil && err != ethernetip.ErrClosed {
		log.Fatal(err)
	}
}
