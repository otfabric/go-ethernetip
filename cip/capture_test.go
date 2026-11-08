// SPDX-License-Identifier: MIT

package cip_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/internal/capture"
)

// Recorded traffic of real devices (testdata/captures/README.md).
const captures = "../testdata/captures"

func recordings(t *testing.T) []capture.Recording {
	t.Helper()
	recs, err := capture.Load(captures, capture.Extended)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// f8 marks a logical segment as recorded with an 8-bit value.
func f8(s cip.LogicalSegment) cip.LogicalSegment {
	s.Format = cip.Format8
	return s
}

// exchange returns the CIP request and response of the exchange whose
// request frame n completed.
func exchange(t *testing.T, r capture.Recording, n int) (cip.Request, cip.Response) {
	t.Helper()
	e, ok := r.Exchange(n)
	if !ok || e.Reply == nil {
		t.Fatalf("%s: no exchange at frame %d", r.File.ID, n)
	}
	q, err1 := capture.ParseExplicit(e.Request.Data)
	a, err2 := capture.ParseExplicit(e.Reply.Data)
	req, err3 := cip.DecodeRequest(q.CIP)
	resp, err4 := cip.DecodeResponse(a.CIP)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		t.Fatalf("%s frame %d: %v %v %v %v", r.File.ID, n, err1, err2, err3, err4)
	}
	return req, resp
}

// Every recorded CIP request and response decodes and encodes back to the
// recorded octets: the requests and replies themselves, the parts of
// Multiple Service Packets, Unconnected_Send and the requests it carries,
// Forward_Open, Forward_Close and their replies. The replies of a Multiple
// Service Packet answer its requests one by one.
func TestCapturesDecode(t *testing.T) {
	var reqs, resps, parts, fwd int
	for _, r := range recordings(t) {
		for _, c := range r.Conversations {
			if c.Transport != capture.TCP {
				continue
			}
			ex, orphans := capture.Exchanges(c)
			for _, e := range ex {
				q, err := capture.ParseExplicit(e.Request.Data)
				if err != nil {
					continue // not SendRRData or SendUnitData
				}
				reqs++
				req := decodeRequest(t, r, e.Request.Frame, q.CIP)
				parts += checkRequest(t, r, e.Request.Frame, req, &fwd)
				if e.Reply == nil {
					continue
				}
				a, err := capture.ParseExplicit(e.Reply.Data)
				if err != nil {
					t.Fatalf("%s frame %d: %v", r.File.ID, e.Reply.Frame, err)
				}
				resps++
				resp := decodeResponse(t, r, e.Reply.Frame, a.CIP)
				checkResponse(t, r, e.Reply.Frame, req, resp)
			}
			for _, m := range orphans {
				if a, err := capture.ParseExplicit(m.Data); err == nil {
					resps++
					decodeResponse(t, r, m.Frame, a.CIP)
				}
			}
		}
	}
	if reqs < 250 || resps < 250 || parts < 200 || fwd < 10 {
		t.Errorf("%d requests, %d responses, %d packet parts, %d Forward_Open/Close", reqs, resps, parts, fwd)
	}
}

func decodeRequest(t *testing.T, r capture.Recording, frame int, b []byte) cip.Request {
	t.Helper()
	req, err := cip.DecodeRequest(b)
	if err != nil {
		t.Fatalf("%s frame %d: % x: %v", r.File.ID, frame, b, err)
	}
	if enc, err := req.Encode(); err != nil || !bytes.Equal(enc, b) {
		t.Errorf("%s frame %d: request encodes to % x, want % x (%v)", r.File.ID, frame, enc, b, err)
	}
	return req
}

func decodeResponse(t *testing.T, r capture.Recording, frame int, b []byte) cip.Response {
	t.Helper()
	resp, err := cip.DecodeResponse(b)
	if err != nil {
		t.Fatalf("%s frame %d: % x: %v", r.File.ID, frame, b, err)
	}
	if enc, err := resp.Encode(); err != nil || !bytes.Equal(enc, b) {
		t.Errorf("%s frame %d: response encodes to % x, want % x (%v)", r.File.ID, frame, enc, b, err)
	}
	return resp
}

// checkRequest checks the service data of the Message Router and
// Connection Manager services and returns the number of embedded requests.
func checkRequest(t *testing.T, r capture.Recording, frame int, req cip.Request, fwd *int) int {
	t.Helper()
	cm := req.Path.String() == "@6/1"
	switch {
	case req.Service == cip.ServiceMultipleServicePacket:
		bs, err := cip.SplitMultiple(req.Data)
		if err != nil {
			t.Fatalf("%s frame %d: %v", r.File.ID, frame, err)
		}
		var rs []cip.Request
		for _, b := range bs {
			rs = append(rs, decodeRequest(t, r, frame, b))
		}
		if enc, err := cip.EncodeMultipleService(rs); err != nil || !bytes.Equal(enc, req.Data) {
			t.Errorf("%s frame %d: packet encodes to % x, %v", r.File.ID, frame, enc, err)
		}
		return len(rs)
	case cm && (req.Service == cip.ServiceForwardOpen || req.Service == cip.ServiceLargeForwardOpen):
		*fwd++
		fo, err := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
		if enc, err2 := fo.Encode(); err != nil || err2 != nil || !bytes.Equal(enc, req.Data) || fo.Service() != req.Service {
			t.Errorf("%s frame %d: Forward_Open % x, %v %v", r.File.ID, frame, enc, err, err2)
		}
	case cm && req.Service == cip.ServiceForwardClose:
		*fwd++
		fc, err := cip.DecodeForwardClose(req.Data)
		if enc, err2 := fc.Encode(); err != nil || err2 != nil || !bytes.Equal(enc, req.Data) {
			t.Errorf("%s frame %d: Forward_Close % x, %v %v", r.File.ID, frame, enc, err, err2)
		}
	case cm && req.Service == cip.ServiceUnconnectedSend:
		u, err := cip.DecodeUnconnectedSend(req.Data)
		if enc, err2 := u.Encode(); err != nil || err2 != nil || !bytes.Equal(enc, req.Data) {
			t.Errorf("%s frame %d: Unconnected_Send % x, %v %v", r.File.ID, frame, enc, err, err2)
		}
		return 1
	}
	return 0
}

func checkResponse(t *testing.T, r capture.Recording, frame int, req cip.Request, resp cip.Response) {
	t.Helper()
	cm := req.Path.String() == "@6/1"
	switch {
	case cm && req.Service == cip.ServiceUnconnectedSend:
		// A successful Unconnected_Send is answered by the embedded
		// request's reply.
		u, _ := cip.DecodeUnconnectedSend(req.Data)
		if resp.Service != u.Request.Service {
			t.Errorf("%s frame %d: reply of service %#x to Unconnected_Send of %#x", r.File.ID, frame, resp.Service, u.Request.Service)
		}
		return
	case resp.Service != req.Service:
		t.Errorf("%s frame %d: reply of service %#x to %#x", r.File.ID, frame, resp.Service, req.Service)
	case req.Service == cip.ServiceMultipleServicePacket && resp.Status == cip.StatusSuccess:
		qs, _ := cip.SplitMultiple(req.Data)
		as, err := cip.SplitMultiple(resp.Data)
		if err != nil || len(as) != len(qs) {
			t.Fatalf("%s frame %d: %d replies to %d requests, %v", r.File.ID, frame, len(as), len(qs), err)
		}
		var rs []cip.Response
		for i, b := range as {
			p := decodeResponse(t, r, frame, b)
			q, _ := cip.DecodeRequest(qs[i])
			if p.Service != q.Service {
				t.Errorf("%s frame %d part %d: reply of %#x to %#x", r.File.ID, frame, i, p.Service, q.Service)
			}
			rs = append(rs, p)
		}
		if enc, err := cip.EncodeMultipleServiceResponse(rs); err != nil || !bytes.Equal(enc, resp.Data) {
			t.Errorf("%s frame %d: packet reply encodes to % x, %v", r.File.ID, frame, enc, err)
		}
	case cm && (req.Service == cip.ServiceForwardOpen || req.Service == cip.ServiceLargeForwardOpen) && resp.OK():
		fo, _ := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
		fr, err := cip.DecodeForwardOpenReply(resp.Data)
		// The originator chooses the T->O ID of a point-to-point connection,
		// the target that of a multicast one.
		p2p := fo.TOParams.Type == cip.ConnectionPointToPoint
		if enc, err2 := fr.Encode(); err != nil || err2 != nil || !bytes.Equal(enc, resp.Data) || fr.Triad != fo.Triad || (p2p && fr.TOConnID != fo.TOConnID) {
			t.Errorf("%s frame %d: Forward_Open reply %+v, %v %v", r.File.ID, frame, fr, err, err2)
		}
	case cm && req.Service == cip.ServiceForwardClose && resp.OK():
		fc, _ := cip.DecodeForwardClose(req.Data)
		fr, err := cip.DecodeForwardCloseReply(resp.Data)
		if enc, err2 := fr.Encode(); err != nil || err2 != nil || !bytes.Equal(enc, resp.Data) || fr.Triad != fc.Triad {
			t.Errorf("%s frame %d: Forward_Close reply %+v, %v %v", r.File.ID, frame, fr, err, err2)
		}
	}
}

// The 1756-L63's Identity object, read through its EtherNet/IP module by
// RSLinx (Unconnected_Send to port 1, link 0; frames 221 and 222).
func TestCaptureIdentity1756L63(t *testing.T) {
	r, _ := capture.Get(recordings(t), "controllogix-download")
	req, resp := exchange(t, r, 221)
	u, err := cip.DecodeUnconnectedSend(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	want := cip.UnconnectedSend{
		PriorityTick: 7, TimeoutTicks: 249,
		Request: cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.Path{f8(cip.ClassSegment(cip.ClassIdentity)), f8(cip.InstanceSegment(1))}, Data: []byte{}},
		Route:   cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}},
	}
	if !reflect.DeepEqual(u, want) {
		t.Errorf("Unconnected_Send %#v, want %#v", u, want)
	}
	if d := cip.TickTimeout(u.PriorityTick, u.TimeoutTicks); d != 31872*time.Millisecond {
		t.Errorf("timeout %v", d)
	}
	id, err := cip.DecodeIdentity(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	wantID := cip.Identity{
		VendorID: 1, DeviceType: cip.DeviceTypePLC, ProductCode: 56,
		Revision: cip.Revision{Major: 15, Minor: 4}, Status: 0x3160, SerialNumber: 0x0014CD8A,
		ProductName: "1756-L63/A L6x_15_31", State: 0xFF, // not an attribute of Get_Attributes_All
	}
	if id != wantID {
		t.Errorf("identity %#v, want %#v", id, wantID)
	}
	if b, err := wantID.AppendAttributes(nil); err != nil || !bytes.Equal(b, resp.Data) {
		t.Errorf("identity attributes % x, want % x", b, resp.Data)
	}
	if cip.VendorName(id.VendorID) != "Rockwell Automation/Allen-Bradley" {
		t.Errorf("vendor %q", cip.VendorName(id.VendorID))
	}
}

// Forward_Open as RSLinx opens a Class 3 connection to the controller
// (frames 233 and 234) and as a Rockwell originator opens a Class 1
// connection (ENIP_CIP-CM frames 10 and 11), against Wireshark's decode.
func TestCaptureForwardOpen(t *testing.T) {
	recs := recordings(t)
	r, _ := capture.Get(recs, "controllogix-download")
	req, resp := exchange(t, r, 233)
	fo, err := cip.DecodeForwardOpen(req.Data, false)
	if err != nil {
		t.Fatal(err)
	}
	p := cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityLow, Variable: true, Size: 500}
	// RSLinx proposes an O->T connection ID (0x80000002); the target
	// chooses its own (0x01510B01).
	want := cip.ForwardOpen{
		PriorityTick: 7, TimeoutTicks: 249, OTConnID: 0x80000002, TOConnID: 0x80FE0001,
		Triad: cip.Triad{Serial: 2, VendorID: 0x4D, OriginatorSerial: 0x21217FA7},
		OTRPI: 8_000_000, OTParams: p, TORPI: 8_000_000, TOParams: p,
		Transport: 0xA3,
		Path:      cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}, f8(cip.ClassSegment(cip.ClassMessageRouter)), f8(cip.InstanceSegment(1))},
	}
	if !reflect.DeepEqual(fo, want) {
		t.Errorf("Forward_Open\n got %#v\nwant %#v", fo, want)
	}
	if fo.Transport.Class() != 3 || !fo.Transport.Server() || fo.Transport.Trigger() != cip.TriggerApplication {
		t.Errorf("transport %v", fo.Transport)
	}
	if d := cip.ConnectionTimeout(time.Duration(fo.OTRPI)*time.Microsecond, fo.TimeoutMultiplier); d != 32*time.Second {
		t.Errorf("connection timeout %v", d)
	}
	fr, err := cip.DecodeForwardOpenReply(resp.Data)
	if err != nil || fr.OTConnID != 0x01510B01 || fr.TOConnID != 0x80FE0001 || fr.Triad != want.Triad || fr.OTAPI != 8_000_000 || fr.TOAPI != 8_000_000 || len(fr.AppReply) != 0 {
		t.Errorf("reply %+v %v", fr, err)
	}

	cm, _ := capture.Get(recs, "enip-cip-cm")
	req, resp = exchange(t, cm, 10)
	fo, err = cip.DecodeForwardOpen(req.Data, false)
	if err != nil {
		t.Fatal(err)
	}
	ot := cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityScheduled, Size: 26}
	to := cip.NetworkParams{Type: cip.ConnectionMulticast, Priority: cip.PriorityScheduled, Size: 26}
	want = cip.ForwardOpen{
		PriorityTick: 5, TimeoutTicks: 155,
		Triad:             cip.Triad{Serial: 0x0E, VendorID: 1, OriginatorSerial: 0x0013F522},
		TimeoutMultiplier: 2,
		OTRPI:             10_000, OTParams: ot, TORPI: 10_000, TOParams: to,
		Transport: cip.TransportClass1Cyclic,
		Path: cip.Path{cip.KeySegment{}, f8(cip.ClassSegment(cip.ClassAssembly)), f8(cip.InstanceSegment(6)),
			f8(cip.ConnectionPointSegment(2)), f8(cip.ConnectionPointSegment(1))},
	}
	if !reflect.DeepEqual(fo, want) {
		t.Errorf("Forward_Open\n got %#v\nwant %#v", fo, want)
	}
	fr, err = cip.DecodeForwardOpenReply(resp.Data)
	if err != nil || fr.OTConnID != 0xF1A20002 || fr.TOConnID != 0xF1A20003 || fr.OTAPI != 10_000 || fr.TOAPI != 10_000 {
		t.Errorf("reply %+v %v", fr, err)
	}
}

// RSLinx addresses objects with 16-bit instance segments even where 8 bits
// suffice; the decoded path keeps the width (FactoryTalk frame 1:
// 4c 03 20 b2 25 00 21 00). An unknown class with a 16-bit class segment
// (0x0334) is refused with general status 0x05 and no additional status
// (download frame 361).
func TestCapturePathWidths(t *testing.T) {
	recs := recordings(t)
	ft, _ := capture.Get(recs, "controllogix-factorytalk")
	req, _ := exchange(t, ft, 1)
	if len(req.Path) != 2 || req.Path[1].(cip.LogicalSegment).Format != cip.Format16 || req.Path.String() != "@178/33" {
		t.Errorf("path %#v", req.Path)
	}
	dl, _ := capture.Get(recs, "controllogix-download")
	req, resp := exchange(t, dl, 361)
	if req.Path.String() != "@820/1" || req.Path[0].(cip.LogicalSegment).Format != cip.Format16 {
		t.Errorf("path %#v", req.Path)
	}
	if resp.Status != cip.StatusPathDestinationUnknown || len(resp.Extended) != 0 || len(resp.Data) != 0 {
		t.Errorf("response %+v", resp)
	}
}

// Malformed variants of the recorded requests: a request cut inside its
// path, a Multiple Service Packet claiming one service more than it holds
// or with an offset past its end, and a Forward_Open cut anywhere, are
// refused.
func TestCaptureMalformedVariants(t *testing.T) {
	n := 0
	for _, r := range recordings(t) {
		for _, c := range r.Conversations {
			for _, m := range c.Messages {
				if !m.FromClient {
					continue
				}
				e, err := capture.ParseExplicit(m.Data)
				if err != nil {
					continue
				}
				b := e.CIP
				req, err := cip.DecodeRequest(b)
				if err != nil {
					continue
				}
				n++
				end := 2 + 2*int(b[1])
				for k := range end {
					if _, err := cip.DecodeRequest(b[:k]); err == nil {
						t.Fatalf("%s frame %d: %d octets of a %d-octet path decode", r.File.ID, m.Frame, k, end)
					}
				}
				switch {
				case req.Service == cip.ServiceMultipleServicePacket && len(req.Data) >= 4:
					more := append([]byte(nil), req.Data...)
					more[0]++
					if _, err := cip.SplitMultiple(more); err == nil {
						t.Errorf("%s frame %d: a count of one more splits", r.File.ID, m.Frame)
					}
					past := append([]byte(nil), req.Data...)
					past[2], past[3] = 0xFF, 0xFF
					if _, err := cip.SplitMultiple(past); err == nil {
						t.Errorf("%s frame %d: an offset past the end splits", r.File.ID, m.Frame)
					}
				case req.Service == cip.ServiceForwardOpen && req.Path.String() == "@6/1":
					for k := range len(req.Data) {
						if _, err := cip.DecodeForwardOpen(req.Data[:k], false); err == nil {
							t.Fatalf("%s frame %d: %d octets of Forward_Open decode", r.File.ID, m.Frame, k)
						}
					}
				}
			}
		}
	}
	if n < 250 {
		t.Errorf("%d requests", n)
	}
}
