// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/capture"
)

// Recorded traffic of real devices (testdata/captures/README.md).
const captures = "../testdata/captures"

var ctx = context.Background()

func recordings(t *testing.T) []capture.Recording {
	t.Helper()
	recs, err := capture.Load(captures, capture.Extended)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// target answers a client with the recorded replies of one conversation.
// A request is looked up by its octets after the fields an originator
// chooses itself are cleared: the session handle, the sender context, the
// SendRRData timeout, the CIP sequence count, and in Forward_Open,
// Forward_Close and Unconnected_Send the time ticks, the connection triad
// and the connection IDs the originator proposes. Everything else must be
// what the recorded client sent: a request no recorded client sent finds
// no answer and fails the test. The answer gets the client's values of
// those fields back.
type target struct {
	t       *testing.T
	answers map[string][]byte
	ln      net.Listener
	wg      sync.WaitGroup
	// toIDs maps the T->O connection IDs of the recording to the client's.
	mu    sync.Mutex
	toIDs map[uint32]uint32
	asked []string // normalized requests, in order
	// register, when set, answers a RegisterSession the recording does
	// not hold.
	register []byte
}

func newTarget(t *testing.T, convs ...capture.Conversation) *target {
	t.Helper()
	tg := &target{t: t, answers: map[string][]byte{}, toIDs: map[uint32]uint32{}}
	for _, c := range convs {
		ex, _ := capture.Exchanges(c)
		for _, e := range ex {
			if e.Reply == nil {
				continue
			}
			k := normalize(e.Request.Data)
			if _, dup := tg.answers[k]; !dup {
				tg.answers[k] = e.Reply.Data
			}
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg.ln = ln
	tg.wg.Add(1)
	go tg.serve()
	t.Cleanup(func() { _ = ln.Close(); tg.wg.Wait() })
	return tg
}

func (tg *target) addr() string { return tg.ln.Addr().String() }

func (tg *target) serve() {
	defer tg.wg.Done()
	for {
		c, err := tg.ln.Accept()
		if err != nil {
			return
		}
		tg.wg.Add(1)
		go func() {
			defer tg.wg.Done()
			defer func() { _ = c.Close() }()
			for {
				h := make([]byte, encap.HeaderSize)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				body := make([]byte, binary.LittleEndian.Uint16(h[2:]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				req := append(h, body...)
				if binary.LittleEndian.Uint16(req) == uint16(encap.CommandUnRegisterSession) {
					return
				}
				k := normalize(req)
				tg.mu.Lock()
				tg.asked = append(tg.asked, k)
				tg.mu.Unlock()
				a, ok := tg.answers[k]
				if !ok && tg.register != nil && binary.LittleEndian.Uint16(req) == uint16(encap.CommandRegisterSession) {
					a, ok = tg.register, true
				}
				if !ok {
					tg.t.Errorf("request no recorded client sent:\n  % x", req)
					return
				}
				if _, err := c.Write(tg.patch(req, a)); err != nil {
					return
				}
			}
		}()
	}
}

// patch gives the recorded answer a the client's values of request q.
func (tg *target) patch(q, a []byte) []byte {
	a = append([]byte(nil), a...)
	copy(a[12:20], q[12:20]) // sender context
	if binary.LittleEndian.Uint16(q) == uint16(encap.CommandRegisterSession) {
		return a
	}
	copy(a[4:8], q[4:8]) // session handle: the client echoes what it got
	qe, err1 := capture.ParseExplicit(q)
	ae, err2 := capture.ParseExplicit(a)
	if err1 != nil || err2 != nil {
		return a
	}
	if qe.Connected {
		tg.mu.Lock()
		id, ok := tg.toIDs[ae.ConnID]
		tg.mu.Unlock()
		if ok {
			binary.LittleEndian.PutUint32(a[encap.HeaderSize+12:], id)
		}
		binary.LittleEndian.PutUint16(a[encap.HeaderSize+20:], qe.Sequence)
		return a
	}
	req, err := cip.DecodeRequest(qe.CIP)
	if err != nil || req.Path.String() != "@6/1" || len(ae.CIP) < 4 || ae.CIP[2] != 0 {
		return a
	}
	off := ae.Offset + 4 // the reply data
	switch req.Service {
	case cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen:
		fo, _ := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
		recTO := binary.LittleEndian.Uint32(a[off+4:])
		if fo.TOParams.Type == cip.ConnectionPointToPoint {
			binary.LittleEndian.PutUint32(a[off+4:], fo.TOConnID)
			tg.mu.Lock()
			tg.toIDs[recTO] = fo.TOConnID
			tg.mu.Unlock()
		}
		binary.LittleEndian.PutUint16(a[off+8:], fo.Serial)
		binary.LittleEndian.PutUint16(a[off+10:], fo.VendorID)
		binary.LittleEndian.PutUint32(a[off+12:], fo.OriginatorSerial)
	case cip.ServiceForwardClose:
		fc, _ := cip.DecodeForwardClose(req.Data)
		binary.LittleEndian.PutUint16(a[off:], fc.Serial)
		binary.LittleEndian.PutUint16(a[off+2:], fc.VendorID)
		binary.LittleEndian.PutUint32(a[off+4:], fc.OriginatorSerial)
	default: // nothing the originator chose
	}
	return a
}

// normalize returns the lookup key of a request: see target.
func normalize(m []byte) string {
	b := append([]byte(nil), m...)
	clear(b[4:8])
	clear(b[12:20])
	e, err := capture.ParseExplicit(b)
	if err != nil {
		return hex.EncodeToString(b)
	}
	clear(b[encap.HeaderSize+4 : encap.HeaderSize+6]) // timeout
	prefix := b[:e.Offset]
	if e.Connected {
		clear(prefix[encap.HeaderSize+12 : encap.HeaderSize+16])
		clear(prefix[len(prefix)-2:])
	}
	req, err := cip.DecodeRequest(e.CIP)
	if err != nil || req.Path.String() != "@6/1" {
		return hex.EncodeToString(b)
	}
	switch req.Service {
	case cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen:
		fo, err := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
		if err == nil {
			fo.PriorityTick, fo.TimeoutTicks, fo.OTConnID, fo.Triad = 0, 0, 0, cip.Triad{}
			if fo.TOParams.Type == cip.ConnectionPointToPoint {
				fo.TOConnID = 0
			}
			req.Data, _ = fo.Encode()
		}
	case cip.ServiceForwardClose:
		if fc, err := cip.DecodeForwardClose(req.Data); err == nil {
			fc.PriorityTick, fc.TimeoutTicks, fc.Triad = 0, 0, cip.Triad{}
			req.Data, _ = fc.Encode()
		}
	case cip.ServiceUnconnectedSend:
		if u, err := cip.DecodeUnconnectedSend(req.Data); err == nil {
			u.PriorityTick, u.TimeoutTicks = 0, 0
			req.Data, _ = u.Encode()
		}
	default: // compared as sent
	}
	c, _ := req.Encode()
	return hex.EncodeToString(prefix[encap.HeaderSize:]) + "/" + hex.EncodeToString(b[:2]) + "/" + hex.EncodeToString(c)
}

func conversation(t *testing.T, rec capture.Recording, client string) capture.Conversation {
	t.Helper()
	for _, c := range rec.Conversations {
		if c.Client == client {
			return c
		}
	}
	t.Fatalf("%s: no conversation of %s", rec.File.ID, client)
	return capture.Conversation{}
}

// The client against the 1756-L63 as RSLinx talks to it (download
// capture, connection from port 1070), with the route RSLinx uses (port 1,
// link 0): RegisterSession, ListServices, ListInterfaces, the Identity
// object and its vendor attributes 0x65 and 0x66 through Unconnected_Send,
// a Class 3 connection (Forward_Open with RSLinx's parameters: 500 octets,
// RPI 8 s, multiplier 0) carrying a Get_Attribute_List, and its
// Forward_Close. Every request is one RSLinx sent.
func TestCaptureReplayClientAgainst1756L63(t *testing.T) {
	rec, _ := capture.Get(recordings(t), "controllogix-download")
	tg := newTarget(t, conversation(t, rec, "10.92.18.100:1070"))
	route := cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}}
	c, err := client.Dial(ctx, tg.addr(), client.WithRoute(route))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Session() != 0x13020200 {
		t.Errorf("session %#x", c.Session())
	}
	svcs, err := c.ListServices(ctx)
	if err != nil || len(svcs) != 1 || svcs[0].Name != "Communications" || svcs[0].Capabilities != encap.CapabilityTCP|encap.CapabilityUDP {
		t.Errorf("ListServices %+v %v", svcs, err)
	}
	if ifs, err := c.ListInterfaces(ctx); err != nil || len(ifs) != 0 {
		t.Errorf("ListInterfaces %+v %v", ifs, err)
	}
	id, err := c.Identity(ctx)
	if err != nil || id.ProductName != "1756-L63/A L6x_15_31" || id.Revision != (cip.Revision{Major: 15, Minor: 4}) || id.SerialNumber != 0x0014CD8A {
		t.Errorf("Identity %+v %v", id, err)
	}
	vals, err := c.GetAttributeList(ctx, cip.ClassIdentity, 1, []uint16{0x65, 0x66}, []int{2, 0})
	if err != nil || len(vals) != 2 || !bytes.Equal(vals[0].Value, []byte{1, 1}) || !bytes.Equal(vals[1].Value, []byte{0x1f, 0, 0, 0}) {
		t.Errorf("GetAttributeList %+v %v", vals, err)
	}
	cn, err := c.OpenConnection(ctx, client.ConnectionOptions{Timeout: 32 * time.Second, Size: 500})
	if err != nil {
		t.Fatal(err)
	}
	info := cn.Info()
	if info.OTConnID != 0x01510B01 || info.OTRPI != 8*time.Second || info.TORPI != 8*time.Second {
		t.Errorf("connection %+v", info)
	}
	resp, err := cn.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassIdentity, 1), Data: []byte{2, 0, 0x65, 0, 0x66, 0}})
	if err != nil || !resp.OK() || len(resp.Data) != 16 {
		t.Errorf("connected Get_Attribute_List %+v %v", resp, err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Errorf("Forward_Close: %v", err)
	}
}

// The client's ListIdentity over TCP, against the 1756-ENBT/A.
func TestCaptureReplayClientListIdentity1756ENBT(t *testing.T) {
	rec, _ := capture.Get(recordings(t), "icsnpp-enip-cip-example")
	tg := newTarget(t, conversation(t, rec, "10.1.1.167:5262"))
	// The recorded originator sent ListIdentity without a session; the
	// client registers one first, which the target grants (session 1).
	tg.register = []byte{0x65, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}
	c, err := client.Dial(ctx, tg.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	it, err := c.ListIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if it.ProductName != "1756-ENBT/A" || it.Socket.AddrPort() != netip.MustParseAddrPort("10.1.1.164:44818") || it.State != 3 || it.Revision != (cip.Revision{Major: 4, Minor: 3}) {
		t.Errorf("%+v", it)
	}
}

// The client opens the Class 1 connection a Rockwell originator opened
// (ENIP_CIP-CM frames 8 to 11) and takes the target's reply: the
// connection IDs it chose and its Sockaddr Info items (O->T 0.0.0.0:2222,
// T->O multicast 239.192.5.128:2222).
func TestCaptureReplayClientClass1ForwardOpen(t *testing.T) {
	rec, _ := capture.Get(recordings(t), "enip-cip-cm")
	tg := newTarget(t, conversation(t, rec, "192.168.100.28:4497"))
	c, err := client.Dial(ctx, tg.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if svcs, err := c.ListServices(ctx); err != nil || len(svcs) != 1 {
		t.Errorf("ListServices %+v %v", svcs, err)
	}
	p := func(typ cip.ConnectionType) cip.NetworkParams {
		return cip.NetworkParams{Type: typ, Priority: cip.PriorityScheduled, Size: 26}
	}
	fo := cip.ForwardOpen{
		PriorityTick: 5, TimeoutTicks: 155,
		Triad:             c.NewTriad(),
		TimeoutMultiplier: 2,
		OTRPI:             10_000, OTParams: p(cip.ConnectionPointToPoint), TORPI: 10_000, TOParams: p(cip.ConnectionMulticast),
		Transport: cip.TransportClass1Cyclic,
		Path: cip.Path{cip.KeySegment{}, cip.ClassSegment(cip.ClassAssembly), cip.InstanceSegment(6),
			cip.ConnectionPointSegment(2), cip.ConnectionPointSegment(1)},
	}
	reply, items, err := c.ForwardOpen(ctx, fo)
	if err != nil {
		t.Fatal(err)
	}
	if reply.OTConnID != 0xF1A20002 || reply.TOConnID != 0xF1A20003 || reply.OTAPI != 10_000 || reply.TOAPI != 10_000 {
		t.Errorf("reply %+v", reply)
	}
	want := map[encap.ItemType]string{encap.ItemSockaddrOT: "0.0.0.0:2222", encap.ItemSockaddrTO: "239.192.5.128:2222"}
	if len(items) != 2 {
		t.Fatalf("items %+v", items)
	}
	for _, it := range items {
		sa, err := encap.DecodeSockaddr(it.Data)
		if err != nil || sa.AddrPort().String() != want[it.Type] {
			t.Errorf("item %#x: %v %v", it.Type, sa.AddrPort(), err)
		}
	}
}
