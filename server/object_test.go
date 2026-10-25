// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
)

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }

func TestStandardObject(t *testing.T) {
	o := NewObject(0x70, 3)
	if o.Class() != 0x70 {
		t.Fatalf("Class = %v", o.Class())
	}
	ctx := context.Background()
	serve := func(svc cip.Service, inst uint32, attr int, data []byte) cip.Response {
		r := &Request{Request: cip.Request{Service: svc, Data: data}, Instance: inst}
		if attr >= 0 {
			r.Attribute, r.HasAttribute = uint16(attr), true
		}
		return o.ServeCIP(ctx, r)
	}
	classAttr := func(id uint16) uint16 {
		t.Helper()
		r := serve(cip.ServiceGetAttributeSingle, 0, int(id), nil)
		if !r.OK() {
			t.Fatalf("class attribute %d: %s", id, r.Status)
		}
		return u16(r.Data)
	}
	if classAttr(1) != 3 || classAttr(2) != 0 || classAttr(3) != 0 || classAttr(6) != 7 || classAttr(7) != 0 {
		t.Fatal("class attributes of an empty object")
	}
	in1 := o.AddInstance(1)
	if o.AddInstance(1) != in1 || o.Instance(1) != in1 || o.Instance(2) != nil {
		t.Fatal("AddInstance/Instance")
	}
	var stored []byte
	in1.SetAttribute(5, Attribute{Get: func() []byte { return []byte{5, 5} }, InGetAll: true})
	in1.SetAttribute(2, Attribute{Get: func() []byte { return []byte{2} }, InGetAll: true,
		Set: func(d []byte) cip.GeneralStatus {
			if len(d) != 1 {
				return cip.StatusNotEnoughData
			}
			stored = append([]byte(nil), d...)
			return cip.StatusSuccess
		}})
	in1.SetAttribute(9, Attribute{Get: func() []byte { return []byte{9} }}) // not in GAA
	in1.SetAttribute(11, Attribute{Set: func([]byte) cip.GeneralStatus { return cip.StatusSuccess }})
	o.AddInstance(7).SetAttribute(12, Attribute{Get: func() []byte { return nil }})
	if classAttr(2) != 7 || classAttr(3) != 2 || classAttr(7) != 12 {
		t.Fatalf("class attributes: max instance %d, instances %d, max attribute %d", classAttr(2), classAttr(3), classAttr(7))
	}
	// Get_Attributes_All: in attribute order, only InGetAll with a getter.
	if r := serve(cip.ServiceGetAttributesAll, 1, -1, nil); !bytes.Equal(r.Data, []byte{2, 5, 5}) {
		t.Errorf("Get_Attributes_All = %x", r.Data)
	}
	if r := serve(cip.ServiceGetAttributesAll, 0, -1, nil); len(r.Data) != 10 || u16(r.Data) != 3 {
		t.Errorf("class Get_Attributes_All = %x", r.Data)
	}
	statusCases := []struct {
		name string
		svc  cip.Service
		inst uint32
		attr int
		data []byte
		want cip.GeneralStatus
	}{
		{"get without attribute", cip.ServiceGetAttributeSingle, 1, -1, nil, cip.StatusPathSegmentError},
		{"get unknown", cip.ServiceGetAttributeSingle, 1, 3, nil, cip.StatusAttributeNotSupported},
		{"get write-only", cip.ServiceGetAttributeSingle, 1, 11, nil, cip.StatusAttributeNotSupported},
		{"set without attribute", cip.ServiceSetAttributeSingle, 1, -1, nil, cip.StatusPathSegmentError},
		{"set unknown", cip.ServiceSetAttributeSingle, 1, 3, []byte{1}, cip.StatusAttributeNotSupported},
		{"set read-only", cip.ServiceSetAttributeSingle, 1, 5, []byte{1}, cip.StatusAttributeNotSettable},
		{"set bad size", cip.ServiceSetAttributeSingle, 1, 2, nil, cip.StatusNotEnoughData},
		{"set", cip.ServiceSetAttributeSingle, 1, 2, []byte{42}, cip.StatusSuccess},
		{"unknown instance", cip.ServiceGetAttributeSingle, 2, 1, nil, cip.StatusPathDestinationUnknown},
		{"unknown service", cip.ServiceReset, 1, -1, nil, cip.StatusServiceNotSupported},
	}
	for _, tc := range statusCases {
		if r := serve(tc.svc, tc.inst, tc.attr, tc.data); r.Status != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, r.Status, tc.want)
		}
	}
	if !bytes.Equal(stored, []byte{42}) {
		t.Errorf("Set stored %x", stored)
	}

	// Get_Attribute_List.
	list := func(ids ...uint16) []byte {
		b := cip.AppendUint16(nil, uint16(len(ids)))
		for _, id := range ids {
			b = cip.AppendUint16(b, id)
		}
		return b
	}
	r := serve(cip.ServiceGetAttributeList, 1, -1, list(5, 3, 11, 2))
	want := []byte{4, 0, 5, 0, 0, 0, 5, 5, 3, 0, 0x14, 0, 11, 0, 0x14, 0, 2, 0, 0, 0, 2}
	if r.Status != cip.StatusAttributeListError || !bytes.Equal(r.Data, want) {
		t.Errorf("Get_Attribute_List = %s %x, want %x", r.Status, r.Data, want)
	}
	if r := serve(cip.ServiceGetAttributeList, 1, -1, list(9)); !r.OK() || !bytes.Equal(r.Data, []byte{1, 0, 9, 0, 0, 0, 9}) {
		t.Errorf("Get_Attribute_List(9) = %s %x", r.Status, r.Data)
	}
	big := make([]uint16, maxListAttributes+1)
	for _, tc := range []struct {
		name string
		data []byte
		want cip.GeneralStatus
	}{
		{"empty", nil, cip.StatusNotEnoughData},
		{"one octet", []byte{1}, cip.StatusNotEnoughData},
		{"zero count", list(), cip.StatusInvalidParameter},
		{"count beyond data", []byte{3, 0, 1, 0}, cip.StatusNotEnoughData},
		{"too many", list(big...), cip.StatusInvalidParameter},
	} {
		if r := serve(cip.ServiceGetAttributeList, 1, -1, tc.data); r.Status != tc.want {
			t.Errorf("Get_Attribute_List %s: %s, want %s", tc.name, r.Status, tc.want)
		}
	}

	// HandleService adds a service and overrides a standard one.
	o.HandleService(cip.ServiceReset, func(_ context.Context, r *Request) cip.Response {
		return cip.Response{Data: []byte{byte(r.Instance)}}
	})
	o.HandleService(cip.ServiceGetAttributeSingle, func(context.Context, *Request) cip.Response {
		return cip.Response{Status: cip.StatusPrivilegeViolation}
	})
	if r := serve(cip.ServiceReset, 7, -1, nil); !r.OK() || r.Data[0] != 7 {
		t.Errorf("custom service = %s %x", r.Status, r.Data)
	}
	if r := serve(cip.ServiceGetAttributeSingle, 1, 5, nil); r.Status != cip.StatusPrivilegeViolation {
		t.Errorf("overridden service = %s", r.Status)
	}

	// Class attribute changes and RemoveInstance.
	o.SetClassAttribute(20, Attribute{Get: func() []byte { return []byte{1} }})
	o.RemoveInstance(7)
	if o.Instance(7) != nil || o.maxInstance() != 1 || o.numInstances() != 1 || o.maxAttr(0) != 20 || o.maxAttr(1) != 11 {
		t.Errorf("after RemoveInstance: max %d, n %d, max class attr %d, max attr %d",
			o.maxInstance(), o.numInstances(), o.maxAttr(0), o.maxAttr(1))
	}
	o.RemoveInstance(1)
	if o.maxInstance() != 0 || o.numInstances() != 0 {
		t.Error("objects remain after removing every instance")
	}
}

func TestServerObjects(t *testing.T) {
	id := DefaultIdentity
	id.State = 0
	var resets []uint8
	s := startServer(t,
		WithIdentity(id),
		WithResetHandler(func(rt uint8) cip.GeneralStatus {
			resets = append(resets, rt)
			if rt == 1 {
				return cip.StatusDeviceStateConflict
			}
			return cip.StatusSuccess
		}),
		WithInterface(Interface{
			IP: netip.MustParseAddr("192.168.1.10"), Mask: netip.MustParseAddr("255.255.0.0"),
			Gateway: netip.MustParseAddr("192.168.1.1"), NameServer: netip.MustParseAddr("8.8.8.8"),
			DomainName: "plant", HostName: "adapter", MAC: [6]byte{1, 2, 3, 4, 5, 6}, SpeedMbps: 1000,
		}),
		WithMaxConnections(17),
	)
	if s.Identity().State != 3 {
		t.Errorf("State 0 not reported as 3: %d", s.Identity().State)
	}
	p := dialPeer(t, s)
	p.register()

	// Identity.
	s.SetIdentityStatus(0x0034)
	if r := p.get(cip.ClassIdentity, 1, 5); u16(r.Data) != 0x0034 {
		t.Errorf("status attribute = %x", r.Data)
	}
	if r := p.get(cip.ClassIdentity, 1, 8); !bytes.Equal(r.Data, []byte{3}) {
		t.Errorf("state attribute = %x", r.Data)
	}
	reset := func(inst uint32, data []byte) cip.GeneralStatus {
		return p.do(cip.Request{Service: cip.ServiceReset, Path: cip.ObjectPath(cip.ClassIdentity, inst), Data: data}).Status
	}
	for _, tc := range []struct {
		inst uint32
		data []byte
		want cip.GeneralStatus
	}{
		{1, nil, cip.StatusSuccess},
		{1, []byte{1}, cip.StatusDeviceStateConflict},
		{1, []byte{2}, cip.StatusInvalidParameter},
		{1, []byte{0, 0}, cip.StatusTooMuchData},
		{0, nil, cip.StatusServiceNotSupported},
	} {
		if got := reset(tc.inst, tc.data); got != tc.want {
			t.Errorf("Reset instance %d data %x: %s, want %s", tc.inst, tc.data, got, tc.want)
		}
	}
	if len(resets) != 2 || resets[0] != 0 || resets[1] != 1 {
		t.Errorf("reset handler calls %v", resets)
	}

	// Message Router.
	r := p.get(cip.ClassMessageRouter, 1, 1)
	if n := int(u16(r.Data)); n != len(s.Classes()) || len(r.Data) != 2+2*n {
		t.Errorf("Message Router class list %x for %v", r.Data, s.Classes())
	}
	if r := p.get(cip.ClassMessageRouter, 1, 2); u16(r.Data) != 17 {
		t.Errorf("connections supported = %x", r.Data)
	}
	if r := p.get(cip.ClassMessageRouter, 1, 3); u16(r.Data) != 0 {
		t.Errorf("connections open = %x", r.Data)
	}

	// Port.
	if r := p.get(cip.ClassPort, 0, 8); u16(r.Data) != 1 {
		t.Errorf("port class attribute 8 = %x", r.Data)
	}
	if r := p.do(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassPort, 1)}); !r.OK() ||
		!strings.Contains(string(r.Data), "EtherNet/IP") || !strings.Contains(string(r.Data), "192.168.1.10") {
		t.Errorf("Port Get_Attributes_All = %s %q", r.Status, r.Data)
	}

	// TCP/IP Interface.
	r = p.get(cip.ClassTCPIPInterface, 1, 5)
	wantCfg := []byte{0x0A, 1, 0xA8, 0xC0, 0, 0, 0xFF, 0xFF, 1, 1, 0xA8, 0xC0, 8, 8, 8, 8, 0, 0, 0, 0, 5, 0, 'p', 'l', 'a', 'n', 't', 0}
	if !bytes.Equal(r.Data, wantCfg) {
		t.Errorf("interface configuration = %x, want %x", r.Data, wantCfg)
	}
	if r := p.get(cip.ClassTCPIPInterface, 1, 6); !bytes.Equal(r.Data, []byte{7, 0, 'a', 'd', 'a', 'p', 't', 'e', 'r', 0}) {
		t.Errorf("host name = %x", r.Data)
	}
	// Multicast base: host 10.1.0.10 & 0.0.255.255 = 266 -> 239.192.1.0 + 265*32.
	r = p.get(cip.ClassTCPIPInterface, 1, 9)
	base := binary.LittleEndian.Uint32(r.Data[4:])
	if u16(r.Data[2:]) != 32 || base != 0xEFC00100+265*32 {
		t.Errorf("multicast configuration = %x", r.Data)
	}
	if g := s.multicastGroup(33); g != netip.AddrFrom4([4]byte{239, 192, 0x22, 0x21}) {
		t.Errorf("multicast group 33 = %v", g)
	}
	for _, tc := range []struct {
		data []byte
		want cip.GeneralStatus
	}{
		{nil, cip.StatusNotEnoughData},
		{[]byte{0}, cip.StatusInvalidAttributeValue},
		{[]byte{16}, cip.StatusSuccess},
	} {
		if r := p.set(cip.ClassTCPIPInterface, 1, 8, tc.data); r.Status != tc.want {
			t.Errorf("TTL set %x: %s, want %s", tc.data, r.Status, tc.want)
		}
	}
	if r := p.get(cip.ClassTCPIPInterface, 1, 8); !bytes.Equal(r.Data, []byte{16}) {
		t.Errorf("TTL = %x", r.Data)
	}

	// Ethernet Link.
	if r := p.get(cip.ClassEthernetLink, 1, 1); binary.LittleEndian.Uint32(r.Data) != 1000 {
		t.Errorf("speed = %x", r.Data)
	}
	if r := p.get(cip.ClassEthernetLink, 1, 3); !bytes.Equal(r.Data, []byte{1, 2, 3, 4, 5, 6}) {
		t.Errorf("MAC = %x", r.Data)
	}
	for attr, want := range map[uint16][]byte{7: {2}, 8: {1}, 9: {1}, 10: {5, 'p', 'o', 'r', 't', '1'}} {
		if r := p.get(cip.ClassEthernetLink, 1, attr); !bytes.Equal(r.Data, want) {
			t.Errorf("Ethernet Link attribute %d = %x", attr, r.Data)
		}
	}
}

func TestDefaultInterfaceAttributes(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	if r := p.get(cip.ClassEthernetLink, 1, 1); binary.LittleEndian.Uint32(r.Data) != 100 {
		t.Errorf("default speed = %x", r.Data)
	}
	// 127.0.0.1 with a /24 mask is host 1: the first block.
	if r := p.get(cip.ClassTCPIPInterface, 1, 9); binary.LittleEndian.Uint32(r.Data[4:]) != 0xEFC00100 {
		t.Errorf("multicast base = %x", r.Data)
	}
	if r := p.get(cip.ClassTCPIPInterface, 1, 5); !bytes.Equal(r.Data[:4], []byte{1, 0, 0, 127}) || len(r.Data) != 22 {
		t.Errorf("interface configuration = %x", r.Data)
	}
	if r := p.get(cip.ClassTCPIPInterface, 1, 6); !bytes.Equal(r.Data, []byte{0, 0}) {
		t.Errorf("empty host name = %x", r.Data)
	}
	for attr, want := range map[uint16][]byte{
		1: {1, 0, 0, 0}, 2: {0x20, 0, 0, 0}, 3: {0, 0, 0, 0},
		4: {2, 0, 0x20, 0xF6, 0x24, 1}, // path to the Ethernet Link object
	} {
		if r := p.get(cip.ClassTCPIPInterface, 1, attr); !bytes.Equal(r.Data, want) {
			t.Errorf("TCP/IP attribute %d = %x, want %x", attr, r.Data, want)
		}
	}
	if r := p.get(cip.ClassEthernetLink, 1, 2); !bytes.Equal(r.Data, []byte{0x0D, 0, 0, 0}) {
		t.Errorf("interface flags = %x", r.Data)
	}
}

func TestLocalIP(t *testing.T) {
	s := &Server{opts: defaultOptions()}
	if got := s.localIP(nil); got != netip.IPv4Unspecified() {
		t.Errorf("localIP(nil) = %v", got)
	}
	if got := s.localIP(&netAddr{}); got != netip.IPv4Unspecified() {
		t.Errorf("localIP(other) = %v", got)
	}
	if got := s.localIP(udpAddr("10.0.0.3:1")); got != netip.MustParseAddr("10.0.0.3") {
		t.Errorf("localIP(udp) = %v", got)
	}
	if got := s.localIP(udpAddr("0.0.0.0:1")); got != netip.IPv4Unspecified() {
		t.Errorf("localIP(unspecified udp) = %v", got)
	}
	s.opts.iface.IP = netip.MustParseAddr("10.9.9.9")
	if got := s.localIP(udpAddr("10.0.0.3:1")); got != s.opts.iface.IP {
		t.Errorf("localIP with an interface = %v", got)
	}
	if remoteIP(nil).IsValid() || remoteIP(&netAddr{}).IsValid() {
		t.Error("remoteIP of a non-IP address is valid")
	}
	if remoteIP(udpAddr("10.0.0.4:5")) != netip.MustParseAddr("10.0.0.4") {
		t.Error("remoteIP of a UDP address")
	}
	if addrString(nil) != "" {
		t.Error("addrString(nil)")
	}
}

func TestRouting(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	cases := []struct {
		name string
		msg  []byte
		want cip.GeneralStatus
	}{
		{"one octet", []byte{0x0E}, cip.StatusNotEnoughData},
		{"truncated path", []byte{0x0E, 3, 0x20, 1}, cip.StatusPathSizeInvalid},
		{"bad segment", []byte{0x0E, 1, 0xFF, 0xFF}, cip.StatusPathSegmentError},
		{"no class", []byte{0x0E, 1, 0x24, 1}, cip.StatusPathSegmentError},
		{"unknown class", mustEncode(t, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x99, 1, 1)}), cip.StatusPathDestinationUnknown},
		{"attribute too large", []byte{0x0E, 5, 0x20, 1, 0x24, 1, 0x33, 0, 0, 0, 1, 0}, cip.StatusPathSegmentError},
		{"symbol without handler", mustEncode(t, cip.Request{Service: 0x4C, Path: cip.Path{cip.SymbolSegment{Name: "tag"}}}), cip.StatusPathDestinationUnknown},
	}
	for _, tc := range cases {
		r, _ := p.rrData(tc.msg)
		if r.Status != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, r.Status, tc.want)
		}
		if len(tc.msg) > 0 && r.Service != cip.Service(tc.msg[0]) {
			t.Errorf("%s: reply service %v", tc.name, r.Service)
		}
	}
	// An empty message: not enough data, service 0.
	if r, _ := p.rrData(nil); r.Status != cip.StatusNotEnoughData {
		t.Errorf("empty message: %s", r.Status)
	}
	// A request with the reply bit is malformed.
	if r, _ := p.rrData([]byte{0x8E, 0}); r.Status != cip.StatusPathSegmentError || r.Service != 0x0E {
		t.Errorf("reply bit: %s service %v", r.Status, r.Service)
	}

	s.HandleSymbols(symbolFunc(func(_ context.Context, r *Request) cip.Response {
		return cip.Response{Data: []byte(r.Path[0].(cip.SymbolSegment).Name)}
	}))
	if r := p.do(cip.Request{Service: 0x4C, Path: cip.Path{cip.SymbolSegment{Name: "tag"}}}); !r.OK() || string(r.Data) != "tag" {
		t.Errorf("symbol handler: %s %q", r.Status, r.Data)
	}

	// RegisterObject and Rest.
	custom := NewObject(0x64, 1)
	custom.AddInstance(1)
	custom.HandleService(0x4B, func(_ context.Context, r *Request) cip.Response {
		return cip.Response{Data: []byte{byte(len(r.Rest)), byte(r.Attribute)}}
	})
	s.RegisterObject(custom)
	if s.Object(0x64) != custom {
		t.Fatal("Object did not return the registered object")
	}
	r := p.do(cip.Request{Service: 0x4B, Path: cip.Path{cip.ClassSegment(0x64), cip.InstanceSegment(1), cip.AttributeSegment(3), cip.MemberSegment(2)}})
	if !r.OK() || !bytes.Equal(r.Data, []byte{1, 3}) {
		t.Errorf("custom service = %s %x", r.Status, r.Data)
	}
	found := false
	for _, c := range s.Classes() {
		found = found || c == 0x64
	}
	if !found {
		t.Error("Classes lacks the registered class")
	}
}

// netAddr is a net.Addr that is neither TCP nor UDP.
type netAddr struct{}

func (netAddr) Network() string { return "test" }
func (netAddr) String() string  { return "test" }

func udpAddr(s string) *net.UDPAddr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

type symbolFunc func(context.Context, *Request) cip.Response

func (f symbolFunc) ServeSymbol(ctx context.Context, r *Request) cip.Response { return f(ctx, r) }

func mustEncode(t testing.TB, r cip.Request) []byte {
	t.Helper()
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMultipleServicePacket(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	msp := func(inst uint32, data []byte) cip.Response {
		return p.do(cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.ObjectPath(cip.ClassMessageRouter, inst), Data: data})
	}
	get := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}
	bad := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)}
	nested, _ := cip.EncodeMultipleService([]cip.Request{get})
	data, err := cip.EncodeMultipleService([]cip.Request{get, bad,
		{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: nested}})
	if err != nil {
		t.Fatal(err)
	}
	r := msp(1, data)
	if r.Status != cip.StatusEmbeddedServiceError {
		t.Fatalf("status %s", r.Status)
	}
	parts, err := cip.SplitMultiple(r.Data)
	if err != nil || len(parts) != 3 {
		t.Fatalf("replies %d, %v", len(parts), err)
	}
	want := []cip.GeneralStatus{cip.StatusSuccess, cip.StatusAttributeNotSupported, cip.StatusServiceNotSupported}
	for i, part := range parts {
		resp, err := cip.DecodeResponse(part)
		if err != nil || resp.Status != want[i] {
			t.Errorf("reply %d: %v %v, want %s", i, resp.Status, err, want[i])
		}
	}
	data, _ = cip.EncodeMultipleService([]cip.Request{get, get})
	if r := msp(1, data); !r.OK() {
		t.Errorf("all succeed: %s", r.Status)
	}
	many := make([]cip.Request, maxEmbedded+1)
	for i := range many {
		many[i] = get
	}
	data, _ = cip.EncodeMultipleService(many)
	for _, tc := range []struct {
		name string
		inst uint32
		data []byte
		want cip.GeneralStatus
	}{
		{"class", 0, data, cip.StatusServiceNotSupported},
		{"too many", 1, data, cip.StatusResourceUnavailable},
		{"empty", 1, []byte{0, 0}, cip.StatusNotEnoughData},
		{"no count", 1, nil, cip.StatusNotEnoughData},
		{"offset outside", 1, []byte{1, 0, 0x40, 0}, cip.StatusNotEnoughData},
		{"decreasing offsets", 1, []byte{2, 0, 8, 0, 6, 0, 0x0E, 0, 0x0E, 0}, cip.StatusNotEnoughData},
	} {
		if r := msp(tc.inst, tc.data); r.Status != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, r.Status, tc.want)
		}
	}
}

func TestUnconnectedSend(t *testing.T) {
	s := startServer(t, WithSlot(2))
	p := dialPeer(t, s)
	p.register()
	us := func(u cip.UnconnectedSend) cip.Response {
		data, err := u.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return p.do(cip.Request{Service: cip.ServiceUnconnectedSend, Path: cip.ConnectionManagerPath(), Data: data})
	}
	get := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}
	local := cip.Path{cip.PortSegment{Port: 1, Link: []byte{2}}}
	r := us(cip.UnconnectedSend{PriorityTick: 10, TimeoutTicks: 10, Request: get, Route: local})
	if !r.OK() || r.Service != cip.ServiceGetAttributeSingle || u16(r.Data) != DefaultIdentity.VendorID {
		t.Fatalf("local route: %s %v %x", r.Status, r.Service, r.Data)
	}
	// Errors of the embedded request come back with its service.
	r = us(cip.UnconnectedSend{Request: cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)}, Route: local})
	if r.Status != cip.StatusAttributeNotSupported || r.Service != cip.ServiceGetAttributeSingle {
		t.Errorf("embedded error: %s %v", r.Status, r.Service)
	}
	for _, route := range []cip.Path{
		{cip.PortSegment{Port: 1, Link: []byte{3}}},
		{cip.PortSegment{Port: 2, Link: []byte{2}}},
		{cip.PortSegment{Port: 1, Link: []byte{2}}, cip.PortSegment{Port: 1, Link: []byte{5}}},
		{cip.PortSegment{Port: 1, Link: []byte{2}}, cip.ClassSegment(1)},
	} {
		r := us(cip.UnconnectedSend{Request: get, Route: route})
		words, _ := route.Words()
		if connStatus(r) != cip.ConnStatusPortNotAvailable || r.Service != cip.ServiceUnconnectedSend || !bytes.Equal(r.Data, []byte{byte(words), 0}) {
			t.Errorf("route %v: %s %x data %x", route, r.Status, r.Extended, r.Data)
		}
	}
	inner, _ := cip.UnconnectedSend{Request: get, Route: local}.Encode()
	r = us(cip.UnconnectedSend{Request: cip.Request{Service: cip.ServiceUnconnectedSend, Path: cip.ConnectionManagerPath(), Data: inner}, Route: local})
	if connStatus(r) != cip.ConnStatusUnconnectedParameterError {
		t.Errorf("nested Unconnected_Send: %s %x", r.Status, r.Extended)
	}
	// Truncated and malformed.
	raw := func(inst uint32, data []byte) cip.Response {
		return p.do(cip.Request{Service: cip.ServiceUnconnectedSend, Path: cip.ObjectPath(cip.ClassConnectionManager, inst), Data: data})
	}
	if r := raw(1, []byte{10, 10, 4}); r.Status != cip.StatusNotEnoughData {
		t.Errorf("truncated: %s", r.Status)
	}
	if r := raw(1, []byte{10, 10, 2, 0, 0x8E, 0, 1, 0, 0x01, 0x02}); connStatus(r) != cip.ConnStatusUnconnectedParameterError {
		t.Errorf("malformed embedded request: %s %x", r.Status, r.Extended)
	}
	if r := raw(0, nil); r.Status != cip.StatusServiceNotSupported {
		t.Errorf("class instance: %s", r.Status)
	}
}

func TestAssemblyAPI(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inst uint32
		kind AssemblyKind
		size int
	}{
		{0, AssemblyInput, 1},
		{1, AssemblyInput, -1},
		{1, AssemblyInput, 65001},
		{1, AssemblyInputOnly, 1},
		{1, AssemblyListenOnly, 2},
		{1, 0, 1},
		{1, AssemblyListenOnly + 1, 1},
	} {
		if _, err := s.AddAssembly(tc.inst, tc.kind, tc.size); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("AddAssembly(%d, %v, %d) = %v", tc.inst, tc.kind, tc.size, err)
		}
	}
	a, err := s.AddAssembly(5, AssemblyOutput, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAssembly(5, AssemblyInput, 4); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("duplicate instance: %v", err)
	}
	if s.Assembly(5) != a || s.Assembly(6) != nil {
		t.Error("Assembly lookup")
	}
	if a.Instance() != 5 || a.Kind() != AssemblyOutput || a.Size() != 4 || a.Run() {
		t.Errorf("assembly %d %v %d run %v", a.Instance(), a.Kind(), a.Size(), a.Run())
	}
	if err := a.SetData([]byte{1}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("SetData of the wrong size: %v", err)
	}
	if err := a.SetData([]byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	d := a.Data()
	d[0] = 9
	if !bytes.Equal(a.Data(), []byte{1, 2, 3, 4}) {
		t.Error("Data is not a copy")
	}
	for k, want := range map[AssemblyKind]string{AssemblyInput: "input", AssemblyOutput: "output", AssemblyConfig: "config",
		AssemblyInputOnly: "input-only", AssemblyListenOnly: "listen-only", 9: "kind-9"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", k, k.String())
		}
	}
	// Explicit access: Set_Attribute_Single on an output assembly calls
	// OnWrite with run.
	type write struct {
		data []byte
		run  bool
	}
	writes := make(chan write, 4)
	a.OnWrite(func(data []byte, run bool) { writes <- write{append([]byte(nil), data...), run} })
	in, _ := s.AddAssembly(6, AssemblyInput, 2)
	_ = in.SetData([]byte{7, 8})
	serve(t, s, "127.0.0.1:0")
	p := dialPeer(t, s)
	p.register()
	if r := p.set(cip.ClassAssembly, 5, 3, []byte{5, 6, 7, 8}); !r.OK() {
		t.Fatalf("Set data: %s", r.Status)
	}
	if w := <-writes; !bytes.Equal(w.data, []byte{5, 6, 7, 8}) || !w.run {
		t.Errorf("OnWrite(%x, %v)", w.data, w.run)
	}
	if !a.Run() || !bytes.Equal(a.Data(), []byte{5, 6, 7, 8}) {
		t.Error("assembly not updated by Set_Attribute_Single")
	}
	if r := p.set(cip.ClassAssembly, 5, 3, []byte{1}); r.Status != cip.StatusNotEnoughData {
		t.Errorf("short Set: %s", r.Status)
	}
	if r := p.set(cip.ClassAssembly, 6, 3, []byte{1, 2}); r.Status != cip.StatusAttributeNotSettable {
		t.Errorf("Set of an input assembly: %s", r.Status)
	}
	if r := p.get(cip.ClassAssembly, 6, 3); !bytes.Equal(r.Data, []byte{7, 8}) {
		t.Errorf("input data = %x", r.Data)
	}
	if r := p.get(cip.ClassAssembly, 6, 4); u16(r.Data) != 2 {
		t.Errorf("input size = %x", r.Data)
	}
	if r := p.get(cip.ClassAssembly, 0, 2); u16(r.Data) != 6 {
		t.Errorf("max instance = %x", r.Data)
	}
}
