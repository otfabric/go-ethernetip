// SPDX-License-Identifier: MIT

// Command io runs a Class 1 I/O connection between a scanner and an
// adapter in the same process: the adapter copies its output assembly to
// its input assembly, the scanner sends a counter and reads it back. It
// exits after a second.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

func main() {
	srv, err := server.New(server.WithIOAddress("127.0.0.1:0"))
	if err != nil {
		log.Fatal(err)
	}
	in, _ := srv.AddAssembly(100, server.AssemblyInput, 8)
	out, _ := srv.AddAssembly(150, server.AssemblyOutput, 8)
	if _, err := srv.AddAssembly(151, server.AssemblyConfig, 0); err != nil {
		log.Fatal(err)
	}
	out.OnWrite(func(data []byte, run bool) { _ = in.SetData(data) })
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, srv.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := scanner.New(c, scanner.WithLocalAddr("127.0.0.1:0"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	io, err := s.Open(ctx, scanner.IOConfig{
		ConfigInstance: 151, OutputInstance: 150, InputInstance: 100,
		OutputSize: 8, InputSize: 8, RPI: 10 * time.Millisecond,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("connection open: %+v\n", io.Info())
	for i := uint64(1); i <= 100; i++ {
		_ = io.SetOutput(binary.BigEndian.AppendUint64(nil, i))
		time.Sleep(10 * time.Millisecond)
	}
	data, run, at := io.Input()
	fmt.Printf("input %d (run %v) at %s; %+v\n", binary.BigEndian.Uint64(data), run, at.Format(time.StampMilli), io.Stats())
	if err := io.Close(ctx); err != nil {
		log.Fatal(err)
	}
}
