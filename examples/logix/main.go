// SPDX-License-Identifier: MIT

// Command logix reads and writes Logix tags. Without arguments it starts
// the library's Logix emulation and uses it; with an address it talks to a
// controller (slot 0 of its chassis):
//
//	go run ./examples/logix 192.168.1.10
//
// The Logix services are Rockwell Automation extensions of CIP.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/logix"
	"github.com/otfabric/go-ethernetip/server"
)

func main() {
	addr := ""
	if len(os.Args) > 1 {
		addr = os.Args[1]
	} else {
		srv, err := server.New(server.WithIOAddress("127.0.0.1:0"))
		if err != nil {
			log.Fatal(err)
		}
		ts := logix.NewTagServer(logix.WithProgramName("example"))
		_ = ts.AddTag("Counter", cip.TypeDINT)
		_ = ts.AddTag("Speeds", cip.TypeREAL, 4)
		ts.Attach(srv)
		if err := srv.Listen("127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		defer func() { _ = srv.Close() }()
		addr = srv.Addr().String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	route, _ := cip.ParseRoute("1/0")
	c, err := client.Dial(ctx, addr, client.WithRoute(route))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	lc := logix.NewClient(c)

	tags, err := lc.ListTags(ctx, "")
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range tags {
		fmt.Printf("tag %-12s %s dims %v\n", t.Name, t.Type, t.Dims)
	}
	if len(os.Args) > 1 {
		return // do not write to a real controller from an example
	}
	v, _ := logix.Ints(cip.TypeDINT, 1234)
	if err := lc.Write(ctx, "Counter", v); err != nil {
		log.Fatal(err)
	}
	got, err := lc.Read(ctx, "Counter", 1)
	if err != nil {
		log.Fatal(err)
	}
	n, _ := got.Int(0)
	fmt.Println("Counter =", n)
	f, _ := logix.Floats(cip.TypeREAL, 1.5, 2.5, 3.5, 4.5)
	if err := lc.Write(ctx, "Speeds", f); err != nil {
		log.Fatal(err)
	}
	res, err := lc.ReadMany(ctx, []string{"Counter", "Speeds[2]"})
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range res {
		fmt.Println(r.Tag, r.Value, r.Err)
	}
}
