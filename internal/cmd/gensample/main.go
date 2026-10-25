// SPDX-License-Identifier: MIT

// Command gensample generates eds/internal/sampledevice/device_gen.go from
// eds/testdata/otfabric_adapter.eds with eds.GenerateGo: the generator's
// output, committed, compiled and tested like any package. With -check it
// fails when the committed file differs from what the generator writes.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/otfabric/go-ethernetip/eds"
)

const (
	source = "eds/testdata/otfabric_adapter.eds"
	target = "eds/internal/sampledevice/device_gen.go"
)

func main() {
	check := flag.Bool("check", false, "fail when the generated file is out of date instead of writing it")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, "gensample:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	f, err := eds.ParseString(string(b))
	if err != nil {
		return err
	}
	for _, is := range eds.Validate(f) {
		if is.Severity == eds.Error {
			return fmt.Errorf("%s: %s", source, is)
		}
	}
	src, err := eds.GenerateGo(f, eds.GenerateOptions{Package: "sampledevice", Source: source})
	if err != nil {
		return err
	}
	if check {
		have, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(have, src) {
			return fmt.Errorf("out of date, run make generate: %s", target)
		}
		return nil
	}
	return os.WriteFile(target, src, 0o644)
}
