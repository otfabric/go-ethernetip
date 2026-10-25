// SPDX-License-Identifier: MIT

package logix_test

import (
	"fmt"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/logix"
)

func ExampleParseTag() {
	tp, _ := logix.ParseTag("Program:Main.Motors[2].Speed")
	fmt.Println(tp.Path)
	tp, _ = logix.ParseTag("Flags.5")
	fmt.Println(tp.Path, "bit", tp.Bit)
	// Output:
	// [symbol Program:Main] [symbol Motors] [member 2] [symbol Speed]
	// [symbol Flags] bit 5
}

func ExampleInts() {
	v, _ := logix.Ints(cip.TypeDINT, 1, -2)
	fmt.Println(v)
	x, _ := v.Int(1)
	fmt.Println(x)
	// Output:
	// DINT[2] 01000000feffffff
	// -2
}
