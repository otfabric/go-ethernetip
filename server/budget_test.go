// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// largest returns the request built by build(n) for the largest n whose
// SendRRData fits the server's default packet limit (4096 octets).
func largest(t *testing.T, build func(n int) cip.Request) cip.Request {
	t.Helper()
	var last cip.Request
	for n := 1; ; n++ {
		r := build(n)
		msg, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		data, err := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 4096 {
			if n == 1 {
				t.Fatal("no request fits the packet")
			}
			return last
		}
		last = r
	}
}

// multiple returns a Multiple Service Packet of n copies of req.
func multiple(t *testing.T, n int, req cip.Request) cip.Request {
	t.Helper()
	reqs := make([]cip.Request, n)
	for i := range reqs {
		reqs[i] = req
	}
	data, err := cip.EncodeMultipleService(reqs)
	if err != nil {
		t.Fatal(err)
	}
	return cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: data}
}

// getList returns a Get_Attribute_List of attribute 3 of assembly inst,
// asked n times.
func getList(inst uint32, n int) cip.Request {
	data := cip.AppendUint16(nil, uint16(n))
	for range n {
		data = cip.AppendUint16(data, 3)
	}
	return cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassAssembly, inst), Data: data}
}

// TestReplyBudgetAllocation: replies that grow with the request (a
// Multiple Service Packet, Get_Attribute_List) stop at what their packet
// or connection carries, so what the server allocates for one request does
// not grow with the number of attribute reads it asks for. With a
// 65000-octet attribute asked for as often as a 4096-octet packet allows,
// the request is answered with reply data too large (0x11) and allocates
// within the limit: what the server holds is the attribute values read and
// the reply, each at most the reply budget plus the value that exceeds it;
// four times that leaves room for the growth of the reply. The request is
// handled without a session, so that no other goroutine runs while it is
// measured.
func TestReplyBudgetAllocation(t *testing.T) {
	const inst, size = 200, 65000
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAssembly(inst, AssemblyInput, size); err != nil {
		t.Fatal(err)
	}
	limit := uint64(4 * (maxUnconnectedReplyData + size))
	single := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, inst, 3)}
	unconnected := context.Background()
	// A Class 3 connection of the largest T->O size.
	connected := context.WithValue(context.Background(), exchangeKey{}, &exchange{maxReply: maxConnectedReply})
	for _, tc := range []struct {
		name      string
		req       cip.Request
		ctx       context.Context
		connected bool
	}{
		{"Multiple Service Packet of Get_Attribute_Single", largest(t, func(n int) cip.Request { return multiple(t, n, single) }), unconnected, false},
		{"Multiple Service Packet of Get_Attribute_List", largest(t, func(n int) cip.Request { return multiple(t, n, getList(inst, maxListAttributes)) }), unconnected, false},
		{"Get_Attribute_List", getList(inst, maxListAttributes), unconnected, false},
		{"Get_Attribute_List on a Class 3 connection", getList(inst, maxListAttributes), connected, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := mustEncode(t, tc.req)
			var r cip.Response
			a := testenv.PerCall(t, 4, func() { r = s.handleMessage(tc.ctx, msg, nil, tc.connected) })
			t.Logf("%v, limit %d", a, limit)
			if a.Octets > limit {
				t.Fatalf("%v for one request, limit %d", a, limit)
			}
			if r.Status != cip.StatusReplyDataTooLarge {
				t.Fatalf("status %s, want reply data too large", r.Status)
			}
		})
	}
}
