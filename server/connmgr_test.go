// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

// explicitPath is the connection path of a Class 3 connection.
var explicitPath = cip.Path{cip.ClassSegment(cip.ClassMessageRouter), cip.InstanceSegment(1)}

func (p *peer) cmRaw(svc cip.Service, inst uint32, data []byte) cip.Response {
	p.t.Helper()
	return p.do(cip.Request{Service: svc, Path: cip.ObjectPath(cip.ClassConnectionManager, inst), Data: data})
}

func encodeFO(t testing.TB, fo cip.ForwardOpen) []byte {
	t.Helper()
	b, err := fo.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cmCounter(t testing.TB, p *peer, attr uint16) uint16 {
	t.Helper()
	r := p.get(cip.ClassConnectionManager, 1, attr)
	if !r.OK() {
		t.Fatalf("Connection Manager attribute %d: %s", attr, r.Status)
	}
	return u16(r.Data)
}

func TestForwardOpenRefusals(t *testing.T) {
	s := startIOServer(t, WithRPIRange(time.Millisecond, time.Minute))
	p := dialPeer(t, s)
	p.register()

	if r := p.cmRaw(cip.ServiceForwardOpen, 0, nil); r.Status != cip.StatusServiceNotSupported {
		t.Errorf("Forward_Open to the class: %s", r.Status)
	}
	if r := p.cmRaw(cip.ServiceForwardOpen, 1, []byte{1, 2}); r.Status != cip.StatusNotEnoughData {
		t.Errorf("truncated Forward_Open: %s", r.Status)
	}
	bad := encodeFO(t, fwdOpen(3, cip.TriggerApplication, explicitPath))
	bad[len(bad)-2], bad[len(bad)-1] = 0xFF, 0xFF
	if r := p.cmRaw(cip.ServiceForwardOpen, 1, bad); connStatus(r) != cip.ConnStatusInvalidSegment {
		t.Errorf("malformed path: %s %x", r.Status, r.Extended)
	}
	mult := encodeFO(t, fwdOpen(3, cip.TriggerApplication, explicitPath))
	mult[18] = 8
	if r := p.cmRaw(cip.ServiceForwardOpen, 1, mult); connStatus(r) != cip.ConnStatusTimeoutMultiplierNotAcceptable {
		t.Errorf("timeout multiplier 8: %s %x", r.Status, r.Extended)
	}

	ioOwner := func() cip.ForwardOpen { return fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn)) }
	cases := []struct {
		name string
		mod  func(*cip.ForwardOpen)
		want cip.ConnectionStatus
	}{
		{"port", func(f *cip.ForwardOpen) {
			f.Path = append(cip.Path{cip.PortSegment{Port: 2, Link: []byte{0}}}, f.Path...)
		}, cip.ConnStatusPortNotAvailable},
		{"slot", func(f *cip.ForwardOpen) {
			f.Path = append(cip.Path{cip.PortSegment{Port: 1, Link: []byte{4}}}, f.Path...)
		}, cip.ConnStatusPortNotAvailable},
		{"vendor", func(f *cip.ForwardOpen) { f.Path = append(cip.Path{cip.KeySegment{VendorID: 7}}, f.Path...) }, cip.ConnStatusVendorMismatch},
		{"product", func(f *cip.ForwardOpen) { f.Path = append(cip.Path{cip.KeySegment{ProductCode: 7}}, f.Path...) }, cip.ConnStatusVendorMismatch},
		{"device type", func(f *cip.ForwardOpen) { f.Path = append(cip.Path{cip.KeySegment{DeviceType: 7}}, f.Path...) }, cip.ConnStatusDeviceTypeMismatch},
		{"major", func(f *cip.ForwardOpen) { f.Path = append(cip.Path{cip.KeySegment{Major: 2}}, f.Path...) }, cip.ConnStatusRevisionMismatch},
		{"minor", func(f *cip.ForwardOpen) { f.Path = append(cip.Path{cip.KeySegment{Major: 1, Minor: 2}}, f.Path...) }, cip.ConnStatusRevisionMismatch},
		{"compatible newer minor", func(f *cip.ForwardOpen) {
			f.Path = append(cip.Path{cip.KeySegment{Major: 1, Minor: 2, Compatible: true}}, f.Path...)
		}, cip.ConnStatusRevisionMismatch},
		{"two classes", func(f *cip.ForwardOpen) { f.Path = append(f.Path, cip.ClassSegment(4)) }, cip.ConnStatusInvalidSegment},
		{"point before class", func(f *cip.ForwardOpen) { f.Path = cip.Path{cip.InstanceSegment(1), cip.ClassSegment(4)} }, cip.ConnStatusInvalidSegment},
		{"attribute", func(f *cip.ForwardOpen) { f.Path = append(f.Path, cip.AttributeSegment(3)) }, cip.ConnStatusInvalidSegment},
		{"symbol", func(f *cip.ForwardOpen) { f.Path = cip.Path{cip.SymbolSegment{Name: "x"}} }, cip.ConnStatusInvalidSegment},
		{"no class", func(f *cip.ForwardOpen) { f.Path = cip.Path{cip.KeySegment{}} }, cip.ConnStatusInvalidSegment},
		{"O->T RPI", func(f *cip.ForwardOpen) { f.OTRPI = 500 }, cip.ConnStatusRPINotAcceptable},
		{"T->O RPI", func(f *cip.ForwardOpen) { f.TORPI = 61_000_000 }, cip.ConnStatusRPINotAcceptable},
		{"class 2", func(f *cip.ForwardOpen) { f.Transport = cip.NewTransportTrigger(2, cip.TriggerCyclic, false) }, cip.ConnStatusTransportClassNotSupported},
		{"I/O class", func(f *cip.ForwardOpen) { f.Path = explicitPath }, cip.ConnStatusInvalidApplicationPath},
		{"one point", func(f *cip.ForwardOpen) { f.Path = f.Path[:2] }, cip.ConnStatusInvalidApplicationPath},
		{"four points", func(f *cip.ForwardOpen) {
			f.Path = append(ioPath(asmCfg, asmOut, asmIn), cip.ConnectionPointSegment(1))
		}, cip.ConnStatusInvalidApplicationPath},
		{"unknown consumer", func(f *cip.ForwardOpen) { f.Path = ioPath(0, 999, asmIn) }, cip.ConnStatusInvalidConsumingPath},
		{"input as consumer", func(f *cip.ForwardOpen) { f.Path = ioPath(0, asmIn, asmIn) }, cip.ConnStatusInvalidConsumingPath},
		{"unknown producer", func(f *cip.ForwardOpen) { f.Path = ioPath(0, asmOut, 999) }, cip.ConnStatusInvalidProducingPath},
		{"output as producer", func(f *cip.ForwardOpen) { f.Path = ioPath(0, asmOut, asmOut) }, cip.ConnStatusInvalidProducingPath},
		{"data without config", func(f *cip.ForwardOpen) { f.Path = append(f.Path, cip.DataSegment{Data: []byte{1, 2, 3, 4}}) }, cip.ConnStatusInvalidConfigurationAppPath},
		{"data to input", func(f *cip.ForwardOpen) {
			f.Path = append(ioPath(asmIn, asmOut, asmIn), cip.DataSegment{Data: []byte{1, 2, 3, 4}})
		}, cip.ConnStatusInvalidConfigurationAppPath},
		{"config size", func(f *cip.ForwardOpen) {
			f.Path = append(ioPath(asmCfg, asmOut, asmIn), cip.DataSegment{Data: []byte{1, 2}})
		}, cip.ConnStatusInvalidConfigurationSize},
		{"application trigger", func(f *cip.ForwardOpen) { f.Transport = cip.NewTransportTrigger(1, cip.TriggerApplication, false) }, cip.ConnStatusTriggerNotSupported},
		{"O->T multicast", func(f *cip.ForwardOpen) { f.OTParams.Type = cip.ConnectionMulticast }, cip.ConnStatusInvalidOTType},
		{"T->O null", func(f *cip.ForwardOpen) { f.TOParams.Type = cip.ConnectionNull }, cip.ConnStatusInvalidTOType},
		{"O->T size", func(f *cip.ForwardOpen) { f.OTParams.Size-- }, cip.ConnStatusInvalidOTSize},
		{"O->T variable too small", func(f *cip.ForwardOpen) { f.OTParams.Variable, f.OTParams.Size = true, 5 }, cip.ConnStatusInvalidOTSize},
		{"T->O size", func(f *cip.ForwardOpen) { f.TOParams.Size++ }, cip.ConnStatusInvalidTOSize},
		{"listen only point to point", func(f *cip.ForwardOpen) {
			f.Path, f.OTParams.Size = ioPath(0, asmListenOnly, asmIn), 2
		}, cip.ConnStatusNonListenOnlyNotOpened},
		{"listen only without producer", func(f *cip.ForwardOpen) {
			f.Path, f.OTParams.Size, f.TOParams.Type = ioPath(0, asmListenOnly, asmIn), 2, cip.ConnectionMulticast
		}, cip.ConnStatusNonListenOnlyNotOpened},
		{"class 3 to an assembly", func(f *cip.ForwardOpen) {
			f.Transport = cip.NewTransportTrigger(3, cip.TriggerApplication, false)
		}, cip.ConnStatusInvalidSegment},
		{"class 3 with data", func(f *cip.ForwardOpen) {
			f.Transport = cip.NewTransportTrigger(3, cip.TriggerApplication, false)
			f.Path = append(explicitPath, cip.DataSegment{Data: []byte{1, 2}})
		}, cip.ConnStatusInvalidSegment},
		{"class 3 instance 2", func(f *cip.ForwardOpen) {
			f.Transport = cip.NewTransportTrigger(3, cip.TriggerApplication, false)
			f.Path = cip.Path{cip.ClassSegment(cip.ClassMessageRouter), cip.InstanceSegment(2)}
		}, cip.ConnStatusInvalidSegment},
		{"class 3 multicast", func(f *cip.ForwardOpen) {
			f.Transport = cip.NewTransportTrigger(3, cip.TriggerApplication, false)
			f.Path, f.TOParams.Type = explicitPath, cip.ConnectionMulticast
		}, cip.ConnStatusInvalidNetworkParameter},
		{"class 3 change of state", func(f *cip.ForwardOpen) {
			f.Transport = cip.NewTransportTrigger(3, cip.TriggerChangeOfState, false)
			f.Path = explicitPath
		}, cip.ConnStatusTriggerNotSupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fo := ioOwner()
			tc.mod(&fo)
			r, _ := p.open(fo)
			if connStatus(r) != tc.want {
				t.Fatalf("got %s %x, want %s", r.Status, r.Extended, tc.want)
			}
			if cf, err := cip.DecodeConnectionFailure(r.Data); err != nil || cf.Triad != fo.Triad {
				t.Errorf("failure data %x: %v", r.Data, err)
			}
			if tc.want == cip.ConnStatusInvalidConfigurationSize && (len(r.Extended) != 2 || r.Extended[1] != cfgSize/2) {
				t.Errorf("config size extended status %x", r.Extended)
			}
		})
	}
	if len(s.Connections()) != 0 {
		t.Fatalf("connections after refusals: %v", s.Connections())
	}
	// Counters: every request counted, format and other rejects split.
	if n := cmCounter(t, p, 1); int(n) != len(cases)+3 {
		t.Errorf("open requests = %d, want %d", n, len(cases)+3)
	}
	if n := cmCounter(t, p, 2); n < 7 {
		t.Errorf("format rejects = %d", n)
	}
	if n := cmCounter(t, p, 4); n < 20 {
		t.Errorf("other rejects = %d", n)
	}
	// A key that matches, a compatible key, a route to this slot and a
	// network segment are accepted.
	fo := ioOwner()
	id := s.Identity()
	fo.Path = append(cip.Path{
		cip.PortSegment{Port: 1, Link: []byte{0}},
		cip.KeySegment{VendorID: id.VendorID, DeviceType: uint16(id.DeviceType), ProductCode: id.ProductCode, Major: 1, Minor: 0, Compatible: true},
		cip.NetworkSegment{Subtype: cip.NetworkProductionInhibit, Data: []byte{1}},
	}, fo.Path...)
	p.mustOpen(fo)
	// Out of connections and duplicate triad.
	for _, rest := range []func(*cip.ForwardOpen){
		func(f *cip.ForwardOpen) { f.Path = ioPath(0, asmInputOnly, asmIn); f.OTParams.Size = 2 },
	} {
		f := ioOwner()
		rest(&f)
		f.Triad = fo.Triad
		if r, _ := p.open(f); connStatus(r) != cip.ConnStatusInUse {
			t.Errorf("duplicate triad: %s %x", r.Status, r.Extended)
		}
	}
}

func TestForwardOpenLimits(t *testing.T) {
	s := startIOServer(t, WithMaxConnections(1))
	p := dialPeer(t, s)
	p.register()
	p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
	if r, _ := p.open(fwdOpen(3, cip.TriggerCyclic, explicitPath)); connStatus(r) != cip.ConnStatusOutOfConnections {
		t.Errorf("beyond the maximum: %s %x", r.Status, r.Extended)
	}
	if n := cmCounter(t, p, 3); n != 1 {
		t.Errorf("resource rejects = %d", n)
	}
	// No exchange in the context: the request cannot be served.
	data := encodeFO(t, fwdOpen(3, cip.TriggerApplication, explicitPath))
	r := s.cm.forwardOpen(context.Background(), &Request{Request: cip.Request{Service: cip.ServiceForwardOpen, Data: data}, Instance: 1})
	if r.Status != cip.StatusDeviceStateConflict {
		t.Errorf("Forward_Open without an exchange: %s", r.Status)
	}
	// Without a session (an exchange from UDP, say) Class 3 is refused.
	_, _, f := s.cm.openExplicit(&exchange{}, fwdOpen(3, cip.TriggerApplication, explicitPath),
		openParts{class: cip.ClassMessageRouter, points: []uint32{1}}, nil)
	if f == nil || f.extended[0] != uint16(cip.ConnStatusMiscellaneous) {
		t.Errorf("Class 3 without a session: %+v", f)
	}
	// An I/O connection needs the originator's IP address.
	_, _, f = s.cm.openIO(&exchange{}, fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn)),
		openParts{class: cip.ClassAssembly, points: []uint32{asmOut, asmIn}}, netAddr{})
	if f == nil || f.extended[0] != uint16(cip.ConnStatusMiscellaneous) {
		t.Errorf("I/O without an originator address: %+v", f)
	}
}

// countingObject counts the requests it serves.
func countingObject(n *atomic.Int32) *StandardObject {
	o := NewObject(0x65, 1)
	o.AddInstance(1)
	o.HandleService(0x4B, func(context.Context, *Request) cip.Response {
		return cip.Response{Data: []byte{byte(n.Add(1))}}
	})
	return o
}

func TestClass3Connection(t *testing.T) {
	m := newRecMetrics()
	s := startServer(t, WithMetrics(m))
	var calls atomic.Int32
	s.RegisterObject(countingObject(&calls))
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.Large, fo.OTRPI = true, 1_000_000 // times out after 8 s
	reply, items := p.mustOpen(fo)
	if len(items) != 2 {
		t.Errorf("Class 3 reply items %v", items)
	}
	if reply.TOConnID != fo.TOConnID || reply.OTAPI != fo.OTRPI || reply.OTConnID == 0 {
		t.Errorf("reply %+v", reply)
	}
	conns := s.Connections()
	if len(conns) != 1 || conns[0].Class != 3 || conns[0].OTConnID != reply.OTConnID {
		t.Fatalf("Connections = %+v", conns)
	}
	if r := p.get(cip.ClassMessageRouter, 1, 3); u16(r.Data) != 1 {
		t.Errorf("connections open = %x", r.Data)
	}
	req := cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)}
	id, seq, r := connectedResponse(t, p.unitData(reply.OTConnID, 1, req))
	if id != fo.TOConnID || seq != 1 || !r.OK() || r.Data[0] != 1 {
		t.Fatalf("first request: id %#x seq %d %s %x", id, seq, r.Status, r.Data)
	}
	// A repeated sequence count is answered from the cache.
	_, seq, r = connectedResponse(t, p.unitData(reply.OTConnID, 1, req))
	if seq != 1 || r.Data[0] != 1 || calls.Load() != 1 {
		t.Fatalf("duplicate: seq %d data %x calls %d", seq, r.Data, calls.Load())
	}
	_, _, r = connectedResponse(t, p.unitData(reply.OTConnID, 2, req))
	if r.Data[0] != 2 {
		t.Fatalf("next request: %x", r.Data)
	}
	// Connected requests are dispatched as connected, malformed ones
	// answered with an error status.
	pkt := p.unitData(reply.OTConnID, 3, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)})
	if _, _, r := connectedResponse(t, pkt); r.Status != cip.StatusAttributeNotSupported {
		t.Errorf("connected error: %s", r.Status)
	}
	// Another session cannot use the connection: no reply.
	q := dialPeer(t, s)
	q.register()
	msg, _ := req.Encode()
	data, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(reply.OTConnID), {Type: encap.ItemConnectedData, Data: append([]byte{9, 0}, msg...)}}}.Encode()
	q.send(encap.CommandSendUnitData, q.handle, data)
	q.expectSilence(100 * time.Millisecond)
	if calls.Load() != 2 {
		t.Errorf("request of another session served: %d calls", calls.Load())
	}

	// Forward_Close.
	if r := p.close(fo.Triad, fo.Path); !r.OK() {
		t.Fatalf("Forward_Close: %s %x", r.Status, r.Extended)
	}
	if len(s.Connections()) != 0 {
		t.Error("connection remains after Forward_Close")
	}
	p.send(encap.CommandSendUnitData, p.handle, data)
	p.expectSilence(50 * time.Millisecond)
	if r := p.close(fo.Triad, fo.Path); connStatus(r) != cip.ConnStatusNotFound {
		t.Errorf("Forward_Close of an unknown triad: %s %x", r.Status, r.Extended)
	}
	if r := p.cmRaw(cip.ServiceForwardClose, 1, []byte{1}); r.Status != cip.StatusNotEnoughData {
		t.Errorf("truncated Forward_Close: %s", r.Status)
	}
	if r := p.cmRaw(cip.ServiceForwardClose, 1, []byte{10, 10, 1, 0, 2, 0, 3, 0, 0, 0, 1, 0, 0xFF, 0xFF}); connStatus(r) != cip.ConnStatusForwardClosePathError {
		t.Errorf("malformed Forward_Close: %s %x", r.Status, r.Extended)
	}
	if r := p.cmRaw(cip.ServiceForwardClose, 0, nil); r.Status != cip.StatusServiceNotSupported {
		t.Errorf("Forward_Close to the class: %s", r.Status)
	}
	if cmCounter(t, p, 5) != 4 || cmCounter(t, p, 6) != 2 || cmCounter(t, p, 7) != 1 {
		t.Errorf("close counters %d %d %d", cmCounter(t, p, 5), cmCounter(t, p, 6), cmCounter(t, p, 7))
	}
	waitFor(t, "metrics", func() bool {
		return m.with(func(m *recMetrics) bool {
			return len(m.opened) == 1 && len(m.closed) == 1 && m.closed[0] == nil &&
				len(m.handled[cip.ServiceForwardOpen]) == 0 && len(m.handled[cip.ServiceLargeForwardOpen]) == 1
		})
	})
}

func TestClass3TimeoutAndSession(t *testing.T) {
	m := newRecMetrics()
	s := startServer(t, WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerCyclic, explicitPath)
	fo.OTRPI, fo.TimeoutMultiplier = 1000, 0 // 4 ms
	p.mustOpen(fo)
	waitFor(t, "Class 3 timeout", func() bool { return len(s.Connections()) == 0 })
	if n := cmCounter(t, p, 8); n != 1 {
		t.Errorf("timeouts = %d", n)
	}
	waitFor(t, "closed metric", func() bool {
		return m.with(func(m *recMetrics) bool { return len(m.closed) == 1 && errors.Is(m.closed[0], ethernetip.ErrTimeout) })
	})

	// A connection ends with its session.
	fo = fwdOpen(3, cip.TriggerApplication, explicitPath)
	p.mustOpen(fo)
	if len(s.Connections()) != 1 {
		t.Fatal("connection not open")
	}
	_ = p.c.Close()
	waitFor(t, "connection closed with the session", func() bool { return len(s.Connections()) == 0 })
	waitFor(t, "closed metric", func() bool {
		return m.with(func(m *recMetrics) bool {
			return len(m.closed) == 2 && errors.Is(m.closed[1], ethernetip.ErrConnectionLost)
		})
	})
	// A request on a connection that was closed is not answered.
	ec := &explicitConn{closed: true}
	if _, ok := ec.request(1, func() []byte { t.Error("handled"); return nil }); ok {
		t.Error("closed connection answered")
	}
}

func TestForwardCloseOtherOriginator(t *testing.T) {
	s := startServer(t)
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	p.mustOpen(fo)
	data, _ := cip.ForwardClose{Triad: fo.Triad, Path: fo.Path}.Encode()
	req := &Request{Request: cip.Request{Service: cip.ServiceForwardClose, Data: data}, Instance: 1,
		Remote: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5000}}
	if r := s.cm.forwardClose(context.Background(), req); connStatus(r) != cip.ConnStatusNotFound {
		t.Errorf("Forward_Close from another address: %s %x", r.Status, r.Extended)
	}
	if len(s.Connections()) != 1 {
		t.Fatal("connection closed by another originator")
	}
	req.Remote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if r := s.cm.forwardClose(context.Background(), req); !r.OK() {
		t.Errorf("Forward_Close from the originator: %s", r.Status)
	}
}

func TestIOConnection(t *testing.T) {
	m := newRecMetrics()
	s := startIOServer(t, WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	sock := newIOSocket(t)
	out := s.Assembly(asmOut)
	writes := make(chan bool, 16)
	out.OnWrite(func(_ []byte, run bool) { writes <- run })

	fo := fwdOpen(1, cip.TriggerCyclic, append(ioPath(asmCfg, asmOut, asmIn), cip.DataSegment{Data: []byte{1, 2, 3, 4}}))
	fo.Large = true
	reply, items := p.mustOpen(fo, sock.sockaddrTO())
	if !bytes.Equal(s.Assembly(asmCfg).Data(), []byte{1, 2, 3, 4}) {
		t.Errorf("configuration data = %x", s.Assembly(asmCfg).Data())
	}
	it, ok := encap.Find(items, encap.ItemSockaddrOT)
	if !ok {
		t.Fatal("no Sockaddr O->T item for an I/O port other than 2222")
	}
	if sa, _ := encap.DecodeSockaddr(it.Data); sa.AddrPort() != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.IOAddr().Port()) {
		t.Errorf("Sockaddr O->T %v", sa.AddrPort())
	}
	// T->O data arrives at the socket of the Sockaddr T->O item.
	_ = s.Assembly(asmIn).SetData([]byte{9, 9, 9, 9, 9, 9, 9, 9})
	msg := sock.recv(reply.TOConnID, func(m implicit.Message) bool { return len(m.Payload) == 2+asmSize && m.Payload[2] == 9 })
	if len(msg.Payload) != 2+asmSize {
		t.Fatalf("T->O payload %x", msg.Payload)
	}
	// O->T data is written to the output assembly with its run state.
	payload := implicit.AppendPayload(nil, 1, implicit.FormatHeader32, implicit.Payload{SeqCount: 1, Header: implicit.RunBit, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}})
	sock.sendIO(s, reply.OTConnID, 1, payload)
	if run := <-writes; !run {
		t.Error("O->T data with run consumed as idle")
	}
	if !out.Run() || !bytes.Equal(out.Data(), []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("output %x run %v", out.Data(), out.Run())
	}
	// The connection owns the output: explicit writes conflict, and a
	// second owner is refused.
	if r := p.set(cip.ClassAssembly, asmOut, 3, make([]byte, asmSize)); r.Status != cip.StatusObjectStateConflict {
		t.Errorf("Set of an owned output: %s", r.Status)
	}
	if r, _ := p.open(fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))); connStatus(r) != cip.ConnStatusOwnershipConflict {
		t.Errorf("second owner: %s %x", r.Status, r.Extended)
	}
	if r := p.close(fo.Triad, fo.Path); !r.OK() {
		t.Fatalf("Forward_Close: %s", r.Status)
	}
	if out.Run() {
		t.Error("output still says run after Forward_Close")
	}
	// The output is free again.
	p.mustOpen(fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn)), sock.sockaddrTO())
	waitFor(t, "I/O metrics", func() bool {
		return m.with(func(m *recMetrics) bool { return m.ioSent > 0 && m.ioRecv > 0 && len(m.opened) == 2 })
	})
}

func TestIOVariantsAndChangeOfState(t *testing.T) {
	s := startIOServer(t, WithRunIdleHeader(false, true))
	p := dialPeer(t, s)
	p.register()
	sock := newIOSocket(t)

	// Class 0, modeless both ways with these formats.
	fo := fwdOpen(0, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))
	fo.OTParams.Size, fo.TOParams.Size = asmSize, asmSize+4
	p.mustOpen(fo, sock.sockaddrTO())
	// Input-only with a variable T->O size.
	fo = fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmInputOnly, asmIn))
	fo.OTParams.Size = 2
	fo.TOParams.Variable, fo.TOParams.Size = true, 100
	p.mustOpen(fo, sock.sockaddrTO())

	// Change of state: data goes out on SetData, long before the RPI.
	fo = fwdOpen(1, cip.TriggerChangeOfState, ioPath(0, asmInputOnly, asmIn))
	fo.OTParams.Size, fo.TOParams.Size = 2, asmSize+2+4
	fo.TORPI = 30_000_000
	reply, _ := p.mustOpen(fo, sock.sockaddrTO())
	sock.recv(reply.TOConnID, nil) // the first production
	in := s.Assembly(asmIn)
	if n := len(in.producers); n != 1 {
		t.Fatalf("change-of-state producers = %d", n)
	}
	_ = in.SetData([]byte{4, 4, 4, 4, 4, 4, 4, 4})
	start := time.Now()
	sock.recv(reply.TOConnID, func(m implicit.Message) bool { return bytes.Equal(m.Payload[6:], []byte{4, 4, 4, 4, 4, 4, 4, 4}) })
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("change of state produced after %v", d)
	}
	// SetData with the same data does not trigger.
	_ = in.SetData([]byte{4, 4, 4, 4, 4, 4, 4, 4})
	if r := p.close(fo.Triad, fo.Path); !r.OK() {
		t.Fatal(r.Status)
	}
	in.mu.Lock()
	n := len(in.producers)
	in.mu.Unlock()
	if n != 0 {
		t.Errorf("producers after Forward_Close = %d", n)
	}
}

func TestMulticastProduction(t *testing.T) {
	m := newRecMetrics()
	s := startIOServer(t, WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	sock := newIOSocket(t)
	mc := func(path cip.Path, otSize uint16) cip.ForwardOpen {
		f := fwdOpen(1, cip.TriggerCyclic, path)
		f.OTParams.Size, f.TOParams.Type = otSize, cip.ConnectionMulticast
		return f
	}
	group := func(items []encap.Item) netip.AddrPort {
		t.Helper()
		it, ok := encap.Find(items, encap.ItemSockaddrTO)
		if !ok {
			t.Fatal("no Sockaddr T->O item for a multicast connection")
		}
		sa, err := encap.DecodeSockaddr(it.Data)
		if err != nil {
			t.Fatal(err)
		}
		return sa.AddrPort()
	}
	owner := mc(ioPath(0, asmOut, asmIn), asmSize+2+4)
	r1, items := p.mustOpen(owner, sock.sockaddrTO())
	g := group(items)
	if g.Addr() != s.multicastGroup(0) || g.Port() != sock.port() {
		t.Errorf("group %v, want %v port %d", g, s.multicastGroup(0), sock.port())
	}
	if r1.TOConnID == owner.TOConnID {
		t.Error("multicast T->O ID chosen by the originator")
	}
	io := mc(ioPath(0, asmInputOnly, asmIn), 2)
	r2, items := p.mustOpen(io)
	if r2.TOConnID != r1.TOConnID || group(items).Addr() != g.Addr() {
		t.Errorf("second multicast connection: T->O %#x group %v", r2.TOConnID, group(items))
	}
	lo := mc(ioPath(0, asmListenOnly, asmIn), 2)
	r3, _ := p.mustOpen(lo)
	if r3.TOConnID != r1.TOConnID {
		t.Errorf("listen-only T->O %#x, want %#x", r3.TOConnID, r1.TOConnID)
	}
	if len(s.Connections()) != 3 {
		t.Fatalf("connections %d", len(s.Connections()))
	}
	// The listen-only connection stays while an owner remains.
	if r := p.close(owner.Triad, owner.Path); !r.OK() {
		t.Fatal(r.Status)
	}
	if len(s.Connections()) != 2 {
		t.Fatalf("connections after closing one owner: %d", len(s.Connections()))
	}
	// The last owner takes the listen-only connection with it.
	if r := p.close(io.Triad, io.Path); !r.OK() {
		t.Fatal(r.Status)
	}
	if len(s.Connections()) != 0 {
		t.Fatalf("listen-only connection survived its owners: %+v", s.Connections())
	}
	s.cm.mu.Lock()
	prods := len(s.cm.productions)
	s.cm.mu.Unlock()
	if prods != 0 {
		t.Errorf("productions left: %d", prods)
	}
	waitFor(t, "orphan closed metric", func() bool {
		return m.with(func(m *recMetrics) bool {
			for _, err := range m.closed {
				if errors.Is(err, ethernetip.ErrConnectionLost) {
					return true
				}
			}
			return false
		})
	})
	// A production started again uses the next group.
	_, items = p.mustOpen(mc(ioPath(0, asmInputOnly, asmIn), 2))
	if group(items).Addr() != s.multicastGroup(1) {
		t.Errorf("second production group %v", group(items))
	}
}

func TestIOEndpointFailure(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	addAssemblies(t, s)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UseListeners(l, nil, ep); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		_ = s.Close()
		if err := <-done; !errors.Is(err, ethernetip.ErrClosed) {
			t.Errorf("Serve = %v", err)
		}
	})
	p := dialPeer(t, s)
	p.register()
	// The shared endpoint is closed by its owner: connections cannot open.
	_ = ep.Close()
	for _, fo := range []cip.ForwardOpen{
		fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn)),
		func() cip.ForwardOpen {
			f := fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmInputOnly, asmIn))
			f.OTParams.Size, f.TOParams.Type = 2, cip.ConnectionMulticast
			return f
		}(),
	} {
		if r, _ := p.open(fo); connStatus(r) != cip.ConnStatusNoBufferMemory {
			t.Errorf("Forward_Open on a closed endpoint: %s %x", r.Status, r.Extended)
		}
	}
	if len(s.Connections()) != 0 {
		t.Errorf("connections %+v", s.Connections())
	}
	if s.Assembly(asmOut).owner != nil {
		t.Error("output owned by a failed connection")
	}
}

// TestConcurrentOwners opens exclusive owner connections to one output
// assembly from several sessions at once: exactly one may succeed.
func TestConcurrentOwners(t *testing.T) {
	s := startIOServer(t)
	const n = 8
	peers := make([]*peer, n)
	for i := range peers {
		peers[i] = dialPeer(t, s)
		peers[i].register()
	}
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		var ok atomic.Int32
		fos := make([]cip.ForwardOpen, n)
		statuses := make([]cip.Response, n)
		for i := range peers {
			fos[i] = fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				statuses[i], _ = peers[i].openNoFatal(fos[i])
				if statuses[i].OK() {
					ok.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Fatalf("round %d: %d exclusive owners of one output", round, ok.Load())
		}
		for i := range peers {
			if statuses[i].OK() {
				if r := peers[i].close(fos[i].Triad, fos[i].Path); !r.OK() {
					t.Fatal(r.Status)
				}
			} else if connStatus(statuses[i]) != cip.ConnStatusOwnershipConflict {
				t.Fatalf("refusal %s %x", statuses[i].Status, statuses[i].Extended)
			}
		}
	}
}
