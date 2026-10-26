// SPDX-License-Identifier: MIT

// Command quickstart starts an EtherNet/IP adapter and talks to it with a
// client in the same process: identity, attributes, a Multiple Service
// Packet and a Class 3 connection. It exits when done.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/server"
)

func main() {
	srv, err := server.New(server.WithIOAddress("127.0.0.1:0"))
	if err != nil {
		log.Fatal(err)
	}
	in, err := srv.AddAssembly(100, server.AssemblyInput, 4)
	if err != nil {
		log.Fatal(err)
	}
	_ = in.SetData([]byte{1, 2, 3, 4})
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

	id, err := c.Identity(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("identity:", id)

	data, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, 100, 3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("assembly 100: % x\n", data)

	resps, err := c.MultipleService(ctx, []cip.Request{
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)},
	})
	if err != nil {
		log.Fatal(err)
	}
	for i, r := range resps {
		fmt.Printf("reply %d: status %s, data % x\n", i, r.Status, r.Data)
	}

	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{})
	if err != nil {
		log.Fatal(err)
	}
	name, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("product name over Class 3: %q\n", name[1:])
	if err := cn.Close(ctx); err != nil {
		log.Fatal(err)
	}
}
