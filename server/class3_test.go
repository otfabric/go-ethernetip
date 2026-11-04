package server

import (
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

// A Class 3 reply is bounded by the connection's T->O size, sequence count
// included: the largest that fits is sent, one octet more is answered with
// 0x11.
func TestClass3ReplyBeyondConnectionSize(t *testing.T) {
	s := startIOServer(t)
	const toSize = 500
	// The reply is the sequence count (2), the reply header (4) and the
	// attribute.
	o := NewObject(0x0300, 1)
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte { return make([]byte, toSize-6) }})
	in.SetAttribute(2, Attribute{Get: func() []byte { return make([]byte, toSize-5) }})
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.OTRPI = 10_000_000
	fo.TOParams.Size = toSize
	reply, _ := p.mustOpen(fo)
	req := func(attr uint16) cip.Request {
		return cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x0300, 1, attr)}
	}
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 1, req(1))); !r.OK() || len(r.Data) != toSize-6 {
		t.Errorf("largest reply: %s, %d octets", r.Status, len(r.Data))
	}
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 2, req(2))); r.Status != cip.StatusReplyDataTooLarge || r.Service != cip.ServiceGetAttributeSingle {
		t.Errorf("one octet more: %s service %v", r.Status, r.Service)
	}
	// The connection stays usable.
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 3, req(1))); !r.OK() {
		t.Errorf("after the refused reply: %s", r.Status)
	}
}

// A Class 3 Forward_Open whose sizes cannot carry the smallest message is
// refused with 0x01/0x0127 or 0x0128 and the smallest size accepted.
func TestClass3MinimumSizes(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	for _, tc := range []struct {
		name   string
		ot, to uint16
		ext    []uint16
	}{
		{"O->T 0", 0, 500, []uint16{uint16(cip.ConnStatusInvalidOTSize), minClass3OT}},
		{"O->T 3", minClass3OT - 1, 500, []uint16{uint16(cip.ConnStatusInvalidOTSize), minClass3OT}},
		{"T->O 0", 500, 0, []uint16{uint16(cip.ConnStatusInvalidTOSize), minClass3TO}},
		{"T->O 5", 500, minClass3TO - 1, []uint16{uint16(cip.ConnStatusInvalidTOSize), minClass3TO}},
		{"smallest", minClass3OT, minClass3TO, nil},
	} {
		fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
		fo.OTParams.Size, fo.TOParams.Size = tc.ot, tc.to
		resp, _ := p.open(fo)
		if tc.ext == nil {
			if !resp.OK() {
				t.Errorf("%s: %s %x", tc.name, resp.Status, resp.Extended)
			}
			continue
		}
		if resp.Status != cip.StatusConnectionFailure || len(resp.Extended) != 2 || resp.Extended[0] != tc.ext[0] || resp.Extended[1] != tc.ext[1] {
			t.Errorf("%s: %s %x, want 0x01 %x", tc.name, resp.Status, resp.Extended, tc.ext)
		}
	}
}

// The smallest T->O size still carries the 0x11 answer to a reply that
// does not fit.
func TestClass3SmallestConnectionTooLarge(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.OTRPI = 10_000_000
	fo.TOParams.Size = minClass3TO
	reply, _ := p.mustOpen(fo)
	req := cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)}
	if _, _, r := connectedResponse(t, p.unitData(reply.OTConnID, 1, req)); r.Status != cip.StatusReplyDataTooLarge {
		t.Errorf("Identity on a %d-octet connection: %s", minClass3TO, r.Status)
	}
}

// WithMaxConnectionsPerOriginator counts the Class 3 and I/O connections
// of one originator address; a closed connection frees its place.
func TestMaxConnectionsPerOriginator(t *testing.T) {
	s := startIOServer(t, WithMaxConnectionsPerOriginator(2))
	p := dialPeer(t, s)
	p.register()
	io := fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))
	p.mustOpen(io)
	first := fwdOpen(3, cip.TriggerApplication, explicitPath)
	p.mustOpen(first)
	// A second session of the same originator shares the limit.
	q := dialPeer(t, s)
	q.register()
	resp, _ := q.open(fwdOpen(3, cip.TriggerApplication, explicitPath))
	if resp.Status != cip.StatusConnectionFailure || len(resp.Extended) == 0 || resp.Extended[0] != uint16(cip.ConnStatusOutOfConnections) {
		t.Fatalf("third connection: %s %x, want 0x01/0x0113", resp.Status, resp.Extended)
	}
	// I/O connections count too: a second I/O owner is refused for the
	// limit, not for ownership.
	listen := fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))
	resp, _ = q.open(listen)
	if resp.Status != cip.StatusConnectionFailure || len(resp.Extended) == 0 || resp.Extended[0] != uint16(cip.ConnStatusOutOfConnections) {
		t.Fatalf("I/O beyond the limit: %s %x, want 0x01/0x0113", resp.Status, resp.Extended)
	}
	if r := p.close(first.Triad, explicitPath); !r.OK() {
		t.Fatalf("Forward_Close: %s", r.Status)
	}
	q.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
}

// Without the option, one originator may use every connection.
func TestMaxConnectionsPerOriginatorDefault(t *testing.T) {
	s := startIOServer(t, WithMaxConnections(3))
	p := dialPeer(t, s)
	p.register()
	for range 3 {
		p.mustOpen(fwdOpen(3, cip.TriggerApplication, explicitPath))
	}
	resp, _ := p.open(fwdOpen(3, cip.TriggerApplication, explicitPath))
	if resp.Status != cip.StatusConnectionFailure || len(resp.Extended) == 0 || resp.Extended[0] != uint16(cip.ConnStatusOutOfConnections) {
		t.Fatalf("beyond WithMaxConnections: %s %x", resp.Status, resp.Extended)
	}
}
