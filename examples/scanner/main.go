// SPDX-License-Identifier: MIT

// Command scanner opens an exclusive owner connection to an adapter with
// OpENer's sample layout (config 151, output 150, input 100, 32 octets)
// and prints its inputs for ten seconds:
//
//	go run ./examples/scanner 192.168.1.20
//
// It binds UDP port 2222, where the adapter sends its inputs.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/scanner"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: scanner ADDRESS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := scanner.New(c)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	io, err := s.Open(ctx, scanner.IOConfig{
		ConfigInstance: 151, OutputInstance: 150, InputInstance: 100,
		OutputSize: 32, InputSize: 32, RPI: 50 * time.Millisecond,
		Reconnect: &scanner.Reconnect{},
		OnInput: func(data []byte, run bool) {
			fmt.Printf("%s input % x (run %v)\n", time.Now().Format(time.StampMilli), data[:8], run)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	select {
	case <-time.After(10 * time.Second):
	case <-io.Done():
		log.Printf("connection ended: %v", io.Err())
	}
	_ = io.Close(ctx)
}
