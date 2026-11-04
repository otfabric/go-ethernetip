// SPDX-License-Identifier: MIT

// Command eds validates an EDS file and prints its identity, assemblies
// and connections, then the Go code eds.GenerateGo makes of it:
//
//	go run ./examples/eds eds/testdata/otfabric_adapter.eds
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/otfabric/go-ethernetip/eds"
)

func main() {
	path := "eds/testdata/otfabric_adapter.eds"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	// The file is opened through a root of its directory, so a name that
	// is a symbolic link out of that directory is refused.
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	fh, err := root.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := eds.Parse(fh)
	if err != nil {
		log.Fatal(err)
	}
	for _, is := range eds.Validate(f) {
		fmt.Println(is)
	}
	dev, err := f.Device()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: vendor %d, product %d, revision %s\n", dev.ProductName, dev.VendorID, dev.ProductCode, dev.Revision)
	asms, _ := f.Assemblies()
	for _, a := range asms {
		inst, _ := a.Instance()
		fmt.Printf("assembly %d %q: %d octets\n", inst, a.Name, a.Size)
	}
	conns, _ := f.Connections()
	for _, c := range conns {
		fmt.Printf("connection %d %q: class %d, path %s\n", c.Number, c.Name, c.Class(), c.Path)
	}
	src, err := eds.GenerateGo(f, eds.GenerateOptions{Package: "device", Source: path})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n%d octets of Go generated; first lines:\n%s\n", len(src), src[:min(len(src), 400)])
}
