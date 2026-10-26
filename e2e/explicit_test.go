// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/server"
)

func TestIdentity(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	ctx := ctxT(t)

	id, err := c.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := testIdentity
	want.State = 0xFF // not part of Get_Attributes_All
	if id != want {
		t.Fatalf("identity %+v, want %+v", id, want)
	}
	name, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if string(name[1:]) != testIdentity.ProductName || int(name[0]) != len(testIdentity.ProductName) {
		t.Fatalf("product name %q", name)
	}
	li, err := c.ListIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if li.Identity != testIdentity || li.Socket.AddrPort().Addr().String() != "127.0.0.1" {
		t.Fatalf("ListIdentity %+v", li)
	}
	svcs, err := c.ListServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "Communications" || svcs[0].Capabilities&encap.CapabilityUDP == 0 {
		t.Fatalf("ListServices %+v", svcs)
	}
	ifs, err := c.ListInterfaces(ctx)
	if err != nil || len(ifs) != 0 {
		t.Fatalf("ListInterfaces %v %v", ifs, err)
	}
}

func TestAttributesAndErrors(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	ctx := ctxT(t)

	out := bytes.Repeat([]byte{0xA5}, ioSize)
	if err := c.SetAttributeSingle(ctx, cip.ClassAssembly, asmOutput, 3, out); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, asmInput, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, out) {
		t.Fatalf("input %x after writing output %x", got, out)
	}
	size, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, asmInput, 4)
	if err != nil || binary.LittleEndian.Uint16(size) != ioSize {
		t.Fatalf("size %x %v", size, err)
	}

	cases := []struct {
		name   string
		req    cip.Request
		status cip.GeneralStatus
	}{
		{"unknown class", cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x99, 1, 1)}, cip.StatusPathDestinationUnknown},
		{"unknown instance", cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, 999, 3)}, cip.StatusPathDestinationUnknown},
		{"unknown attribute", cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)}, cip.StatusAttributeNotSupported},
		{"unsupported service", cip.Request{Service: 0x33, Path: cip.ObjectPath(cip.ClassIdentity, 1)}, cip.StatusServiceNotSupported},
		{"read-only attribute", cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1), Data: []byte{1, 0}}, cip.StatusAttributeNotSettable},
		{"input not settable", cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, asmInput, 3), Data: out}, cip.StatusAttributeNotSettable},
		{"short write", cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, asmOutput, 3), Data: out[:3]}, cip.StatusNotEnoughData},
		{"long write", cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, asmOutput, 3), Data: append(out, 1)}, cip.StatusTooMuchData},
		{"no class", cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.Path{cip.InstanceSegment(1)}}, cip.StatusPathSegmentError},
		{"symbol without handler", cip.Request{Service: 0x4C, Path: cip.Path{cip.SymbolSegment{Name: "x"}}}, cip.StatusPathDestinationUnknown},
		{"reset type 2", cip.Request{Service: cip.ServiceReset, Path: cip.ObjectPath(cip.ClassIdentity, 1), Data: []byte{2}}, cip.StatusInvalidParameter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.Do(ctx, tc.req)
			var ce *ethernetip.CIPError
			if !errors.As(err, &ce) || ce.Status != tc.status || resp.Status != tc.status {
				t.Fatalf("got %v (status %s), want status %s", err, resp.Status, tc.status)
			}
		})
	}
	if err := c.Reset(ctx, cip.ClassIdentity, 1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, cip.Request{Service: 0x33, Path: cip.ObjectPath(cip.ClassIdentity, 1)}); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Fatalf("unsupported service: %v", err)
	}
}

func TestMultipleServiceAndAttributeList(t *testing.T) {
	a := startAdapter(t)
	c := dial(t, a.addr)
	ctx := ctxT(t)
	reqs := []cip.Request{
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, asmInput, 4)},
	}
	resps, err := c.MultipleService(ctx, reqs)
	if err != nil {
		t.Fatal(err)
	}
	if len(resps) != 3 || !resps[0].OK() || binary.LittleEndian.Uint16(resps[0].Data) != testIdentity.VendorID ||
		resps[1].Status != cip.StatusAttributeNotSupported || binary.LittleEndian.Uint16(resps[2].Data) != ioSize {
		t.Fatalf("responses %+v", resps)
	}
	if err := client.ResponseError(reqs[1], resps[1]); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Fatalf("ResponseError %v", err)
	}
	vals, err := c.GetAttributeList(ctx, cip.ClassIdentity, 1, []uint16{1, 3, 50}, []int{2, 2, 2})
	var ce *ethernetip.CIPError
	if !errors.As(err, &ce) || ce.Status != cip.StatusAttributeListError {
		t.Fatalf("attribute list error %v", err)
	}
	if len(vals) != 3 || binary.LittleEndian.Uint16(vals[1].Value) != testIdentity.ProductCode || vals[2].Status != cip.StatusAttributeNotSupported {
		t.Fatalf("values %+v", vals)
	}
}

func TestRoutedRequests(t *testing.T) {
	a := startAdapter(t, server.WithSlot(2))
	route, _ := cip.ParseRoute("1/2")
	c := dial(t, a.addr, client.WithRoute(route))
	ctx := ctxT(t)
	if _, err := c.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	bad, _ := cip.ParseRoute("1/3")
	_, err := c.DoRoute(ctx, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)}, bad)
	var ce *ethernetip.CIPError
	if !errors.As(err, &ce) || ce.Service != cip.ServiceUnconnectedSend || ce.Status != cip.StatusConnectionFailure {
		t.Fatalf("bad route: %v", err)
	}
	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
