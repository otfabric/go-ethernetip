// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// allocated returns the octets the process allocates while f runs.
func allocated(f func()) uint64 { return testenv.Allocated(f) }

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

// replyBudgetLimit is what one request may make the server allocate when
// its reply exceeds what the packet or connection carries: a few times the
// encapsulation maximum, whatever the number of attribute reads it asks for.
const replyBudgetLimit = 4 * encap.MaxData

// TestReplyBudgetAllocation: replies that grow with the request (a
// Multiple Service Packet, Get_Attribute_List) stop at what their packet
// or connection carries. The request is answered with reply data too large
// (0x11), and what the server allocates for it stays within
// replyBudgetLimit with a 65000-octet attribute asked for as often as the
// packet allows.
func TestReplyBudgetAllocation(t *testing.T) {
	const inst, size = 200, 65000
	s := startIOServer(t)
	if _, err := s.AddAssembly(inst, AssemblyInput, size); err != nil {
		t.Fatal(err)
	}
	single := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, inst, 3)}
	for _, tc := range []struct {
		name string
		req  cip.Request
	}{
		{"Multiple Service Packet of Get_Attribute_Single", largest(t, func(n int) cip.Request { return multiple(t, n, single) })},
		{"Multiple Service Packet of Get_Attribute_List", largest(t, func(n int) cip.Request { return multiple(t, n, getList(inst, maxListAttributes)) })},
		{"Get_Attribute_List", getList(inst, maxListAttributes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dialPeer(t, s)
			p.register()
			var r cip.Response
			alloc := allocated(func() { r = p.do(tc.req) })
			if r.Status != cip.StatusReplyDataTooLarge {
				t.Fatalf("status %s, want reply data too large", r.Status)
			}
			t.Logf("%d octets allocated", alloc)
			if alloc > replyBudgetLimit {
				t.Fatalf("%d octets allocated for one request, budget %d", alloc, replyBudgetLimit)
			}
		})
	}
	t.Run("Get_Attribute_List on a Class 3 connection", func(t *testing.T) {
		p := dialPeer(t, s)
		p.register()
		reply, _ := p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
		var r cip.Response
		alloc := allocated(func() {
			_, _, r = connectedResponse(t, p.unitData(reply.OTConnID, 1, getList(inst, maxListAttributes)))
		})
		if r.Status != cip.StatusReplyDataTooLarge {
			t.Fatalf("status %s, want reply data too large", r.Status)
		}
		t.Logf("%d octets allocated", alloc)
		if alloc > replyBudgetLimit {
			t.Fatalf("%d octets allocated for one request, budget %d", alloc, replyBudgetLimit)
		}
	})
}

// TestReplyBudgetStopsServices: the services of a Multiple Service Packet
// after the one whose reply exceeds the budget are not handled, and a
// reply within the budget is unchanged.
func TestReplyBudgetStopsServices(t *testing.T) {
	s := startIOServer(t)
	calls := 0
	o := NewObject(0x0300, 1)
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte { calls++; return make([]byte, 40000) }, InGetAll: true})
	in.SetAttribute(2, Attribute{Get: func() []byte { calls++; return make([]byte, 40000) }, InGetAll: true})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	get := func(attr uint16) cip.Request {
		return cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, attr)}
	}
	// Three reads of 40000 octets: the second exceeds what the packet
	// carries, the third is not handled.
	if r := p.do(multiple(t, 3, get(1))); r.Status != cip.StatusReplyDataTooLarge {
		t.Fatalf("Multiple Service Packet: %s, want reply data too large", r.Status)
	}
	if calls != 2 {
		t.Errorf("%d Get calls, want 2", calls)
	}
	// Get_Attributes_All of both: the second Get exceeds the budget.
	calls = 0
	if r := p.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(0x0300, 1)}); r.Status != cip.StatusReplyDataTooLarge {
		t.Fatalf("Get_Attributes_All: %s, want reply data too large", r.Status)
	}
	if calls != 2 {
		t.Errorf("%d Get calls, want 2", calls)
	}
	// One read fits, inside a Multiple Service Packet too.
	if r := p.do(multiple(t, 1, get(2))); !r.OK() {
		t.Fatalf("Multiple Service Packet of one read: %s", r.Status)
	}
	// Called directly, without a session, an object has no budget.
	resp := o.ServeCIP(context.Background(), &Request{Request: cip.Request{Service: cip.ServiceGetAttributesAll}, Instance: 1})
	if !resp.OK() || len(resp.Data) != 80000 {
		t.Fatalf("Get_Attributes_All without a session: %s, %d octets", resp.Status, len(resp.Data))
	}
}

// TestReplyBudgetSmallConnection: on a Class 3 connection whose T->O size
// leaves 20 octets of reply data, a Multiple Service Packet or
// Get_Attribute_List is answered in full up to that size and with reply
// data too large (0x11) above it, whether its count table, an embedded
// reply's header, an embedded reply or an attribute entry crosses it.
func TestReplyBudgetSmallConnection(t *testing.T) {
	s := startIOServer(t)
	o := NewObject(0x0300, 1)
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte { return []byte{1, 2} }})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.TOParams.Size = 2 + 4 + 20 // sequence count, reply header, data
	reply, _ := p.mustOpen(fo)
	get := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, 1)}
	unsupported := func(n int) cip.Request {
		data := cip.AppendUint16(nil, uint16(n))
		for i := range n {
			data = cip.AppendUint16(data, uint16(50+i))
		}
		return cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(0x0300, 1), Data: data}
	}
	seq := uint16(0)
	for _, tc := range []struct {
		name string
		req  cip.Request
		want cip.GeneralStatus
	}{
		{"two reads: 18 octets", multiple(t, 2, get), cip.StatusSuccess},
		{"three reads: 26 octets", multiple(t, 3, get), cip.StatusReplyDataTooLarge},
		{"eight reads: the first header crosses", multiple(t, 8, get), cip.StatusReplyDataTooLarge},
		{"ten reads: the count table crosses", multiple(t, 10, get), cip.StatusReplyDataTooLarge},
		{"four unsupported attributes: 18 octets", unsupported(4), cip.StatusAttributeListError},
		{"five unsupported attributes: 22 octets", unsupported(5), cip.StatusReplyDataTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq++
			_, _, r := connectedResponse(t, p.unitData(reply.OTConnID, seq, tc.req))
			if r.Status != tc.want {
				t.Fatalf("status %s, want %s", r.Status, tc.want)
			}
			if tc.want != cip.StatusReplyDataTooLarge && len(r.Data) > 20 {
				t.Fatalf("%d octets of reply data", len(r.Data))
			}
		})
	}
}

// TestMultipleServiceWithoutBudget: served directly, without a session, a
// Multiple Service Packet whose replies do not fit its 16-bit offsets is
// answered with reply data too large.
func TestMultipleServiceWithoutBudget(t *testing.T) {
	s := startIOServer(t)
	o := NewObject(0x0300, 1)
	o.AddInstance(1).SetAttribute(1, Attribute{Get: func() []byte { return make([]byte, 40000) }})
	s.RegisterObject(o)
	get := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, 1)}
	msp := multiple(t, 3, get) // the third offset is above 65535
	r := s.Object(cip.ClassMessageRouter).ServeCIP(context.Background(), &Request{Request: msp, Instance: 1})
	if r.Status != cip.StatusReplyDataTooLarge {
		t.Fatalf("status %s, want reply data too large", r.Status)
	}
}
