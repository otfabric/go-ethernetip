// SPDX-License-Identifier: MIT

// Command discover sends one ListIdentity request to a broadcast address
// (or one device) and lists the devices that answer:
//
//	go run ./examples/discover 192.168.1.255
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
)

func main() {
	addr := "255.255.255.255"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	devs, err := client.Discover(context.Background(), client.DiscoverOptions{Address: addr, Wait: 3 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range devs {
		id := d.Identity
		fmt.Printf("%-21s %-32s vendor %d (%s), %s, rev %s, serial 0x%08X\n",
			d.Addr, id.ProductName, id.VendorID, cip.VendorName(id.VendorID), id.DeviceType, id.Revision, id.SerialNumber)
	}
}
