// SPDX-License-Identifier: MIT

package eds_test

import (
	"fmt"
	"strings"

	"github.com/otfabric/go-ethernetip/eds"
)

const sample = `[File]
	DescText = "Example"; CreateDate = 10-25-2026; CreateTime = 12:00:00; Revision = 1.0;
[Device]
	VendCode = 65535; ProdType = 12; ProdCode = 7; MajRev = 1; MinRev = 2; ProdName = "Example";
[Device Classification]
	Class1 = EtherNetIP;
[Assembly]
	Assem100 = "Input", "20 04 24 64", 4, 0x0000, ,, 32, ;
`

func ExampleParse() {
	f, err := eds.Parse(strings.NewReader(sample))
	if err != nil {
		panic(err)
	}
	fmt.Println(len(eds.Validate(f)), "issues")
	dev, _ := f.Device()
	fmt.Println(dev.ProductName, dev.Revision)
	asms, _ := f.Assemblies()
	inst, _ := asms[0].Instance()
	fmt.Println(asms[0].Name, inst, asms[0].Size)
	// Output:
	// 0 issues
	// Example 1.2
	// Input 100 4
}

func ExampleGenerateGo() {
	f, _ := eds.ParseString(sample)
	src, err := eds.GenerateGo(f, eds.GenerateOptions{Package: "example"})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.Contains(string(src), "AssemblyInputInstance uint32 = 100"))
	// Output:
	// true
}
