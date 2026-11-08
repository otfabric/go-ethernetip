// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/capture"
	"github.com/otfabric/go-ethernetip/server"
)

// Recorded traffic of real devices (testdata/captures/README.md).
const captures = "../testdata/captures"

func recordings(t *testing.T) []capture.Recording {
	t.Helper()
	recs, err := capture.Load(captures)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// The 1756-L63 behind its EtherNet/IP module, and the 1756-ENBT/A, as their
// recorded answers identify them.
var (
	identity1756L63 = cip.Identity{
		VendorID: 1, DeviceType: cip.DeviceTypePLC, ProductCode: 56,
		Revision: cip.Revision{Major: 15, Minor: 4}, Status: 0x3160, SerialNumber: 0x0014CD8A,
		ProductName: "1756-L63/A L6x_15_31", State: 3,
	}
	identity1756ENBT = cip.Identity{
		VendorID: 1, DeviceType: cip.DeviceTypeCommunicationsAdapter, ProductCode: 58,
		Revision: cip.Revision{Major: 4, Minor: 3}, Status: 0x0030, SerialNumber: 0x00524D8E,
		ProductName: "1756-ENBT/A", State: 3,
	}
)

func startServer(t *testing.T, opts ...server.Option) *server.Server {
	t.Helper()
	s, err := server.New(append([]server.Option{server.WithIOAddress("127.0.0.1:0")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		_ = s.Close()
		if err := <-done; !errors.Is(err, ethernetip.ErrClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return s
}

// Differences between the server's answers and the recorded devices',
// each with its reason. Every other recorded request gets the device's
// answer byte for byte, after the comparison rules of replayer.
const (
	diffCommand0001   = "command 0x0001 (not public; the module lists itself): the server answers status 0x0001, invalid command"
	diffPrivateObject = "a Rockwell-private or Logix object the server does not hold (0x64, 0x68 to 0x8E, 0xAC, 0xB2)"
	diffVendorAttr    = "Identity attributes 0x65 and 0x66 (vendor-specific): the server answers 0x14 per attribute"
	diffRouterAll     = "Message Router Get_Attributes_All: the controller lists its 43 classes and nothing else; the server its own classes, then attributes 2 and 3"
	diffUnknownConn   = "a connection opened before the capture started"
	diffPCCC          = "PCCC Execute (0x4B to class 0x67): PCCC is not implemented"
	diffMicro800      = "Micro800 objects and attributes (classes 0xA2, 0x33A, 0x350, the File object 0x37, Identity attributes 15 to 17)"
	diffIdentityAll   = "Identity Get_Attributes_All: the Micro850 appends octets after the state (00 00 00 \"eng\" \"eng\" 00), the server ends with the state"
	diffTimeout       = "SendRRData timeout: the Micro850 answers 5 and the MicroLogix 1400 1024 whatever was asked; the server echoes the request's, as the ControlLogix"
	diffServices      = "ListServices: the Micro850 announces TCP only (capabilities 0x0020); the server also Class 0/1 over UDP (0x0120)"
	diffPorts         = "Port, TCP/IP Interface and Ethernet Link objects (0xF4 to 0xF6): the device's ports and interface, not the server's"
)

// classify returns the reason a request is expected to be answered
// differently, or "" when the server must answer it as the device did.
func classify(h capture.Header, req cip.Request, ok bool) string {
	if h.Command == 0x0001 {
		return diffCommand0001
	}
	if !ok {
		return ""
	}
	if req.Service == cip.ServiceUnconnectedSend && req.Path.String() == "@6/1" {
		if u, err := cip.DecodeUnconnectedSend(req.Data); err == nil {
			req = u.Request
		}
	}
	if req.Service == cip.ServiceMultipleServicePacket {
		parts, _ := cip.SplitMultiple(req.Data)
		for _, p := range parts {
			if q, err := cip.DecodeRequest(p); err == nil {
				if d := classify(h, q, true); d != "" {
					return d
				}
			}
		}
		return ""
	}
	if len(req.Path) == 0 {
		return ""
	}
	cls, isLogical := req.Path[0].(cip.LogicalSegment)
	if !isLogical || cls.Type != cip.LogicalClass {
		return ""
	}
	attr := uint32(0)
	if len(req.Path) >= 3 {
		if a, ok := req.Path[2].(cip.LogicalSegment); ok && a.Type == cip.LogicalAttribute {
			attr = a.Value
		}
	}
	switch c := cip.Class(cls.Value); {
	case c == 0x67:
		return diffPCCC
	case c == 0x350 || c == 0x33A || c == 0x37 || c == 0xA2 || (c == cip.ClassIdentity && attr >= 15):
		return diffMicro800
	case c == cip.ClassIdentity && req.Service == cip.ServiceGetAttributesAll:
		return diffIdentityAll
	case c >= 0xF4 && c <= 0xF6:
		return diffPorts
	case c == cip.ClassMessageRouter && req.Service == cip.ServiceGetAttributesAll:
		return diffRouterAll
	case c == cip.ClassIdentity && req.Service == cip.ServiceGetAttributeList && bytes.Contains(req.Data, []byte{0x65, 0}):
		return diffVendorAttr
	case c == 0x64 || (c >= 0x68 && c <= 0x8E) || c == 0xAC || c == 0xB2:
		return diffPrivateObject
	}
	return ""
}

// replayer sends the recorded requests of one conversation to a server and
// compares the answers with the recorded ones. Comparison rules (the
// fields a target chooses itself, or that depend on the server's socket):
// the session handle; the O->T connection ID of a Forward_Open reply, and
// the T->O ID of a multicast one, which later requests on the connection
// carry; the socket address of a ListIdentity reply.
type replayer struct {
	t       *testing.T
	conn    net.Conn
	session uint32
	recSess uint32
	// connection IDs: recorded O->T ID -> the server's.
	ids map[uint32]uint32
	// recorded connections the replay opened (their serial number).
	open map[uint16]bool
}

func newReplayer(t *testing.T, s *server.Server) *replayer {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &replayer{t: t, conn: c, ids: map[uint32]uint32{}, open: map[uint16]bool{}}
}

func (r *replayer) roundTrip(req []byte) []byte {
	r.t.Helper()
	if err := r.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.conn.Write(req); err != nil {
		r.t.Fatal(err)
	}
	h := make([]byte, encap.HeaderSize)
	if _, err := io.ReadFull(r.conn, h); err != nil {
		r.t.Fatal(err)
	}
	body := make([]byte, binary.LittleEndian.Uint16(h[2:]))
	if _, err := io.ReadFull(r.conn, body); err != nil {
		r.t.Fatal(err)
	}
	return append(h, body...)
}

// result of one recorded exchange.
type result struct {
	frame  int
	diff   string // the expected difference, "" for none
	equal  bool
	detail string
}

func (r *replayer) exchange(e capture.Exchange) (result, bool) {
	h, _ := capture.ParseHeader(e.Request.Data)
	q := append([]byte(nil), e.Request.Data...)
	if h.Session != 0 {
		if r.recSess == 0 {
			// The capture started inside a session: open one.
			r.recSess, r.session = h.Session, r.register()
		}
		binary.LittleEndian.PutUint32(q[4:], r.session)
	}
	ex, exErr := capture.ParseExplicit(q)
	var req cip.Request
	var reqOK bool
	if exErr == nil {
		req, reqOK = decode(ex.CIP)
	}
	diff := classify(h, req, reqOK)
	if reqOK && req.Service == cip.ServiceForwardClose && req.Path.String() == "@6/1" {
		if fc, err := cip.DecodeForwardClose(req.Data); err == nil && !r.open[fc.Serial] {
			diff = diffUnknownConn // the server answers 0x01 / 0x0107, connection not found
		}
	}
	if exErr == nil && ex.Connected {
		id, known := r.ids[ex.ConnID]
		if !known {
			return result{frame: e.Request.Frame, diff: diffUnknownConn, equal: false, detail: "not sent"}, true
		}
		binary.LittleEndian.PutUint32(addrItem(q), id)
	}
	if e.Reply == nil && h.Command != 0x0066 {
		return result{}, false // no recorded answer to compare with
	}
	got := r.roundTrip(q)
	want := append([]byte(nil), e.Reply.Data...)
	if h.Command == 0x0065 {
		r.recSess = binary.LittleEndian.Uint32(want[4:])
		r.session = binary.LittleEndian.Uint32(got[4:])
	}
	if binary.LittleEndian.Uint32(want[4:]) == r.recSess && r.recSess != 0 {
		binary.LittleEndian.PutUint32(want[4:], r.session)
	}
	r.normalize(h, req, reqOK, got, want)
	res := result{frame: e.Request.Frame, diff: diff, equal: bytes.Equal(got, want)}
	if !res.equal && diff == "" {
		switch {
		case h.Command == 0x0004:
			res.diff = diffServices
		case h.Command == 0x006f && len(got) > encap.HeaderSize+6 && len(want) > encap.HeaderSize+6:
			// Equal but for the timeout of the reply?
			g := append([]byte(nil), got...)
			copy(g[encap.HeaderSize+4:encap.HeaderSize+6], want[encap.HeaderSize+4:])
			if bytes.Equal(g, want) {
				res.diff = diffTimeout
			}
		}
	}
	if !res.equal {
		res.detail = fmt.Sprintf("\n  request % x\n  server  % x\n  device  % x", e.Request.Data, got, want)
	}
	return res, true
}

func (r *replayer) register() uint32 {
	reg := []byte{0x65, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}
	return binary.LittleEndian.Uint32(r.roundTrip(reg)[4:])
}

// normalize applies the comparison rules to the server's answer got and
// the recorded answer want.
func (r *replayer) normalize(h capture.Header, req cip.Request, reqOK bool, got, want []byte) {
	if h.Command == 0x0063 { // ListIdentity: the socket address
		if len(got) >= 48 && len(want) >= 48 {
			copy(got[32:38], want[32:38])
		}
		return
	}
	if !reqOK || req.Path.String() != "@6/1" {
		return
	}
	g, err1 := capture.ParseExplicit(got)
	w, err2 := capture.ParseExplicit(want)
	if err1 != nil || err2 != nil || len(g.CIP) < 12 || len(w.CIP) < 12 || g.CIP[2] != 0 || w.CIP[2] != 0 {
		return
	}
	switch req.Service {
	case cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen:
		// The O->T ID, and for a multicast T->O the T->O ID, are the
		// target's choice: later requests use the server's.
		fo, _ := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
		recOT := binary.LittleEndian.Uint32(w.CIP[4:])
		r.ids[recOT] = binary.LittleEndian.Uint32(g.CIP[4:])
		copy(g.CIP[4:8], w.CIP[4:8])
		if fo.TOParams.Type == cip.ConnectionMulticast {
			copy(g.CIP[8:12], w.CIP[8:12])
		}
		r.open[fo.Serial] = true
		// The Sockaddr Info items' port and address are the server's
		// sockets and configuration. The recorded target names
		// 0.0.0.0:2222 for O->T and 239.192.5.128:2222 for T->O; the
		// ODVA default allocation for host 36 of a /24 gives
		// 239.192.5.96, but the target's mask and multicast
		// configuration are not in the recording.
		gs, ws := sockaddrs(got), sockaddrs(want)
		for i := range min(len(gs), len(ws)) {
			copy(got[gs[i]+2:gs[i]+8], want[ws[i]+2:ws[i]+8])
		}
	default: // no field the target chooses
	}
}

// sockaddrs returns the offsets of the Sockaddr Info items' data (sin_family
// first) in the encapsulation message m.
func sockaddrs(m []byte) []int {
	var out []int
	off := encap.HeaderSize + 6
	if len(m) < off+2 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(m[off:]))
	off += 2
	for range n {
		if len(m) < off+4 {
			return out
		}
		typ, l := binary.LittleEndian.Uint16(m[off:]), int(binary.LittleEndian.Uint16(m[off+2:]))
		if (typ == 0x8000 || typ == 0x8001) && l == 16 && len(m) >= off+4+16 {
			out = append(out, off+4)
		}
		off += 4 + l
	}
	return out
}

func decode(b []byte) (cip.Request, bool) {
	req, err := cip.DecodeRequest(b)
	return req, err == nil
}

// addrItem returns the connection ID of a SendUnitData's connected address
// item (the first item).
func addrItem(m []byte) []byte { return m[encap.HeaderSize+12 : encap.HeaderSize+16] }

// replayAll replays every conversation of a recording to a fresh server
// built by mk and returns the results.
func replayAll(t *testing.T, rec capture.Recording, mk func(t *testing.T) *server.Server, keep func(capture.Conversation) bool) []result {
	t.Helper()
	var out []result
	for _, c := range rec.Conversations {
		if c.Transport != capture.TCP || !keep(c) {
			continue
		}
		r := newReplayer(t, mk(t))
		ex, _ := capture.Exchanges(c)
		for _, e := range ex {
			if res, ok := r.exchange(e); ok {
				out = append(out, res)
			}
		}
	}
	return out
}

// check requires every result without an expected difference to be equal
// and returns the number of results per difference.
func check(t *testing.T, id string, rs []result) map[string]int {
	t.Helper()
	n := map[string]int{}
	for _, r := range rs {
		switch {
		case r.diff == "" && !r.equal:
			t.Errorf("%s frame %d: the server answers otherwise than the device:%s", id, r.frame, r.detail)
		case r.diff == "":
			t.Logf("%s frame %d: equal", id, r.frame)
			n[""]++
		case r.diff != "" && r.equal:
			// An expected difference that is none is fine, but count it as
			// a match.
			n[""]++
		default:
			n[r.diff]++
		}
	}
	return n
}

// RSLinx and the 1756-L63 (rslogix5000_1756-l63_download-upload-run): every request the server
// supports gets the controller's answer byte for byte — ListServices,
// ListInterfaces, RegisterSession, the Identity object through
// Unconnected_Send to slot 0, Get_Attribute_Single of its status,
// Get_Attribute_List of an unknown class (0x05), Forward_Open and
// Forward_Close of Class 3 connections, and the SendRRData timeout.
func TestCaptureReplayMatches1756L63(t *testing.T) {
	recs := recordings(t)
	mk := func(t *testing.T) *server.Server { return startServer(t, server.WithIdentity(identity1756L63)) }
	all := map[string]int{}
	for _, id := range []string{"controllogix-download", "controllogix-factorytalk"} {
		rec, _ := capture.Get(recs, id)
		for k, v := range check(t, id, replayAll(t, rec, mk, func(capture.Conversation) bool { return true })) {
			all[k] += v
		}
	}
	if all[""] < 15 {
		t.Errorf("%d equal answers", all[""])
	}
	for _, d := range []string{diffCommand0001, diffPrivateObject, diffVendorAttr, diffRouterAll, diffUnknownConn} {
		if all[d] == 0 {
			t.Errorf("no exchange differs for %q: update the list of differences", d)
		}
	}
	t.Logf("equal %d; differences: %s", all[""], summary(all))
}

func summary(m map[string]int) string {
	var ks []string
	for k, v := range m {
		if k != "" {
			ks = append(ks, fmt.Sprintf("%d %s", v, k))
		}
	}
	sort.Strings(ks)
	return strings.Join(ks, "; ")
}

// The 1756-ENBT/A's ListIdentity answer (unknown_mixed_list-identity-browse-io and
// unknown_1756-enbt_list-identity): byte for byte, apart from the socket address, with the
// module's identity and address configured.
func TestCaptureListIdentity1756ENBT(t *testing.T) {
	recs := recordings(t)
	mk := func(t *testing.T) *server.Server {
		return startServer(t, server.WithIdentity(identity1756ENBT),
			server.WithInterface(server.Interface{IP: netip.MustParseAddr("10.1.1.164"), Mask: netip.MustParseAddr("255.255.255.0")}))
	}
	n := 0
	for _, id := range []string{"icsnpp-enip-cip-example", "iti-enip-test"} {
		rec, _ := capture.Get(recs, id)
		rs := replayAll(t, rec, mk, func(c capture.Conversation) bool { return strings.HasPrefix(c.Server, "10.1.1.164:") })
		check(t, id, rs)
		n += len(rs)
	}
	if n != 2 {
		t.Errorf("%d ListIdentity exchanges", n)
	}
}

// A Rockwell originator's Class 1 Forward_Open (rockwell-originator_unknown_forward-open-class1 frames 6 to
// 11: ListServices, RegisterSession, then 10 ms cyclic, O->T 26 octets
// point-to-point with run/idle header, T->O 26 octets multicast, Assembly
// 6 / 2 / 1): the server answers as the target did, apart from the
// connection IDs the target chooses.
func TestCaptureReplayClass1ForwardOpen(t *testing.T) {
	rec, _ := capture.Get(recordings(t), "enip-cip-cm")
	mk := func(t *testing.T) *server.Server {
		s := startServer(t)
		for _, a := range []struct {
			inst uint32
			kind server.AssemblyKind
			size int
		}{{6, server.AssemblyConfig, 0}, {2, server.AssemblyOutput, 20}, {1, server.AssemblyInput, 24}} {
			if _, err := s.AddAssembly(a.inst, a.kind, a.size); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	rs := replayAll(t, rec, mk, func(c capture.Conversation) bool { return c.Client == "192.168.100.28:4497" })
	if n := check(t, rec.File.ID, rs); n[""] != 3 {
		t.Errorf("results %v", rs)
	}
}

// The Micro850 (honeypot capture, connection from port 51333: Connected
// Components Workbench-like originator of vendor 0x004D) and the MicroLogix
// 1400 (PCCC capture): ListServices, RegisterSession, Class 3
// Forward_Open and Forward_Close are answered as the controllers did.
func TestCaptureReplayMatchesMicro850AndMicroLogix(t *testing.T) {
	recs := recordings(t)
	micro850 := cip.Identity{
		VendorID: 1, DeviceType: cip.DeviceTypePLC, ProductCode: 143,
		Revision: cip.Revision{Major: 12, Minor: 11}, Status: 0x0034, SerialNumber: 0x60D4229A,
		ProductName: "2080-LC50-48QBB", State: 3,
	}
	all := map[string]int{}
	for _, c := range []struct {
		id   string
		keep func(capture.Conversation) bool
		opts []server.Option
	}{
		{"micro850-honeypot", func(c capture.Conversation) bool { return c.Client == "192.168.1.150:51333" }, []server.Option{server.WithIdentity(micro850)}},
		{"micrologix-pccc", func(capture.Conversation) bool { return true }, nil},
	} {
		rec, _ := capture.Get(recs, c.id)
		mk := func(t *testing.T) *server.Server { return startServer(t, c.opts...) }
		for k, v := range check(t, c.id, replayAll(t, rec, mk, c.keep)) {
			all[k] += v
		}
	}
	for _, d := range []string{diffPCCC, diffMicro800, diffIdentityAll, diffTimeout, diffServices} {
		if all[d] == 0 {
			t.Errorf("no exchange differs for %q", d)
		}
	}
	if all[""] < 8 {
		t.Errorf("%d equal answers", all[""])
	}
	t.Logf("equal %d; differences: %s", all[""], summary(all))
}
