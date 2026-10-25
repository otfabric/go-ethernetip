// SPDX-License-Identifier: MIT

package cip_test

import (
	"fmt"

	"github.com/otfabric/go-ethernetip/cip"
)

func ExampleParsePath() {
	p, _ := cip.ParsePath("@1/1/7")
	b, _ := p.Encode()
	fmt.Printf("% X\n", b)
	q, _ := cip.ParsePath("20 04 24 97 2C 96 2C 64")
	fmt.Println(q)
	// Output:
	// 20 01 24 01 30 07
	// [class 0x04] [instance 151] [point 150] [point 100]
}

func ExampleRequest_Encode() {
	req := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)}
	b, _ := req.Encode()
	fmt.Println(req)
	fmt.Printf("% X\n", b)
	// Output:
	// Get_Attribute_Single @1/1/7
	// 0E 03 20 01 24 01 30 07
}

func ExampleForwardOpen_Encode() {
	fo := cip.ForwardOpen{
		TOConnID:  0x12345678,
		Triad:     cip.Triad{Serial: 1, VendorID: 0xFFFF, OriginatorSerial: 42},
		OTRPI:     10000,
		OTParams:  cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 38},
		TORPI:     10000,
		TOParams:  cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 34},
		Transport: cip.TransportClass1Cyclic,
		Path:      cip.Path{cip.ClassSegment(cip.ClassAssembly), cip.InstanceSegment(151), cip.ConnectionPointSegment(150), cip.ConnectionPointSegment(100)},
	}
	b, _ := fo.Encode()
	fmt.Println(fo.Service(), len(b), "octets")
	fmt.Println(fo.OTParams, "/", fo.TOParams)
	// Output:
	// Forward_Open 44 octets
	// point-to-point scheduled fixed 38 / point-to-point scheduled fixed 34
}

func ExampleServiceName() {
	fmt.Println(cip.ServiceName(cip.ClassSymbol, 0x4C))
	fmt.Println(cip.ServiceName(cip.ClassTemplate, 0x4C))
	fmt.Println(cip.GeneralStatus(0x05), "/", cip.ConnectionStatus(0x0127))
	fmt.Println(cip.VendorName(1))
	// Output:
	// Read_Tag
	// Read_Template
	// path destination unknown / invalid O->T size
	// Rockwell Automation/Allen-Bradley
}
