// SPDX-License-Identifier: MIT

package encap_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/internal/capture"
)

// Recorded traffic of real devices (testdata/captures/README.md).
const captures = "../testdata/captures"

func recordings(t *testing.T) []capture.Recording {
	t.Helper()
	recs, err := capture.Cached(captures)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// Every recorded encapsulation message decodes; its header equals what an
// independent reading of the octets finds; it and its common packet format
// encode back to the recorded octets.
func TestCapturesDecode(t *testing.T) {
	n, cpf := 0, 0
	for _, r := range recordings(t) {
		for _, c := range r.Conversations {
			if c.Transport == capture.UDP && strings.HasSuffix(c.Server, ":2222") {
				continue // I/O: package implicit
			}
			for _, m := range c.Messages {
				n++
				p, err := encap.Decode(m.Data)
				if err != nil {
					t.Errorf("%s frame %d: %v", r.File.ID, m.Frame, err)
					continue
				}
				h, _ := capture.ParseHeader(m.Data)
				if uint16(p.Command) != h.Command || p.Length != h.Length || p.Session != h.Session || uint32(p.Status) != h.Status || p.Context != h.Context || p.Options != h.Options {
					t.Errorf("%s frame %d: header %+v, recorded %+v", r.File.ID, m.Frame, p.Header, h)
				}
				if b, err := p.Encode(); err != nil || !bytes.Equal(b, m.Data) {
					t.Errorf("%s frame %d: encodes to % x, %v", r.File.ID, m.Frame, b, err)
				}
				// ReadPacket reads it from a stream as well.
				if q, _, err := encap.ReadPacket(bytes.NewReader(m.Data), nil, len(m.Data)); err != nil || q.Command != p.Command {
					t.Errorf("%s frame %d: ReadPacket %v", r.File.ID, m.Frame, err)
				}
				if p.Command != encap.CommandSendRRData && p.Command != encap.CommandSendUnitData {
					continue
				}
				rr, err := encap.DecodeRRData(p.Data)
				if err != nil {
					t.Errorf("%s frame %d: %v", r.File.ID, m.Frame, err)
					continue
				}
				cpf++
				if b, err := rr.Encode(); err != nil || !bytes.Equal(b, p.Data) {
					t.Errorf("%s frame %d: CPF encodes to % x, %v", r.File.ID, m.Frame, b, err)
				}
				e, _ := capture.ParseExplicit(m.Data)
				if p.Command == encap.CommandSendUnitData {
					// Originators put a timeout into SendUnitData too (RSLinx
					// 1, the HMI of hmi_logix_bit-writes 10); the targets answer 0.
					it, ok := encap.Find(rr.Items, encap.ItemConnectedAddress)
					id, err := encap.DecodeConnectedAddress(it)
					if !ok || err != nil || id != e.ConnID || (!m.FromClient && rr.Timeout != 0) {
						t.Errorf("%s frame %d: connection ID %#x, %v; recorded %#x", r.File.ID, m.Frame, id, err, e.ConnID)
					}
				}
			}
		}
	}
	if n < 500 || cpf < 450 {
		t.Errorf("%d messages, %d with a CPF", n, cpf)
	}
}

// The 1756-ENBT/A's ListIdentity reply over TCP (unknown_mixed_list-identity-browse-io
// frame 372, the same exchange as unknown_1756-enbt_list-identity frame 7).
func TestCaptureListIdentity1756ENBT(t *testing.T) {
	recs := recordings(t)
	for _, f := range []struct {
		id    string
		frame int
	}{{"icsnpp-enip-cip-example", 372}, {"iti-enip-test", 7}} {
		r, _ := capture.Get(recs, f.id)
		_, m, ok := r.Frame(f.frame)
		if !ok {
			t.Fatalf("%s: no frame %d", f.id, f.frame)
		}
		p, err := encap.Decode(m.Data)
		if err != nil || p.Command != encap.CommandListIdentity || p.Session != 0 {
			t.Fatalf("%s: %+v %v", f.id, p.Header, err)
		}
		items, err := encap.DecodeCPF(p.Data)
		if err != nil || len(items) != 1 || items[0].Type != encap.ItemListIdentity {
			t.Fatalf("%s: items %+v %v", f.id, items, err)
		}
		id, err := encap.DecodeIdentityItem(items[0].Data)
		if err != nil {
			t.Fatal(err)
		}
		want := encap.IdentityItem{
			ProtocolVersion: 1,
			Socket:          encap.SockaddrOf(netip.MustParseAddrPort("10.1.1.164:44818")),
			Identity: cip.Identity{
				VendorID: 1, DeviceType: cip.DeviceTypeCommunicationsAdapter, ProductCode: 58,
				Revision: cip.Revision{Major: 4, Minor: 3}, Status: 0x0030, SerialNumber: 0x00524D8E,
				ProductName: "1756-ENBT/A", State: 3,
			},
		}
		if id != want {
			t.Errorf("%s:\n got %+v\nwant %+v", f.id, id, want)
		}
		if b, err := id.Encode(); err != nil || !bytes.Equal(b, items[0].Data) {
			t.Errorf("%s: identity encodes to % x, %v", f.id, b, err)
		}
	}
}

// ListServices, ListInterfaces and RegisterSession replies of the
// ControlLogix's EtherNet/IP module and of the target in rockwell-originator_unknown_forward-open-class1.
func TestCaptureSessionCommands(t *testing.T) {
	recs := recordings(t)
	r, _ := capture.Get(recs, "controllogix-download")
	cm, _ := capture.Get(recs, "enip-cip-cm")
	for _, c := range []struct {
		rec   capture.Recording
		frame int
	}{{r, 216}, {cm, 7}} {
		_, m, ok := c.rec.Frame(c.frame)
		if !ok {
			t.Fatalf("%s: no frame %d", c.rec.File.ID, c.frame)
		}
		p, _ := encap.Decode(m.Data)
		items, err := encap.DecodeCPF(p.Data)
		if err != nil || p.Command != encap.CommandListServices || len(items) != 1 || items[0].Type != encap.ItemListServices {
			t.Fatalf("%s frame %d: %+v %v", c.rec.File.ID, c.frame, items, err)
		}
		svc, err := encap.DecodeServiceItem(items[0].Data)
		want := encap.ServiceItem{Version: 1, Capabilities: encap.CapabilityTCP | encap.CapabilityUDP, Name: "Communications"}
		if err != nil || svc != want {
			t.Errorf("%s: %+v %v", c.rec.File.ID, svc, err)
		}
		if b, err := want.Encode(); err != nil || !bytes.Equal(b, items[0].Data) {
			t.Errorf("%s: service item encodes to % x", c.rec.File.ID, b)
		}
	}
	// ListInterfaces: no interface item.
	_, m, _ := r.Frame(218)
	p, _ := encap.Decode(m.Data)
	if items, err := encap.DecodeCPF(p.Data); err != nil || len(items) != 0 || p.Command != encap.CommandListInterfaces {
		t.Errorf("ListInterfaces: %+v %v", items, err)
	}
	// RegisterSession: version 1, options 0, the handle the target chose.
	for _, c := range []struct {
		rec     capture.Recording
		frame   int
		session uint32
	}{{r, 220, 0x13020200}, {cm, 9, 1}} {
		_, m, _ := c.rec.Frame(c.frame)
		p, _ := encap.Decode(m.Data)
		reg, err := encap.DecodeRegister(p.Data)
		if err != nil || reg != (encap.Register{ProtocolVersion: 1}) || p.Session != c.session || p.Command != encap.CommandRegisterSession {
			t.Errorf("%s frame %d: %+v session %#x %v", c.rec.File.ID, c.frame, reg, p.Session, err)
		}
	}
}

// What the recorded targets put into the timeout of a SendRRData reply:
// the ControlLogix module (32 s and 0 s as asked) and the four Logix-like
// targets of hmi_logix_bit-writes (20 s) echo the request's; the Micro850
// answers 5 and the MicroLogix 1400 1024 whatever was asked. Package
// server echoes, as the ControlLogix does.
func TestCaptureRRDataTimeout(t *testing.T) {
	const echo = -1
	want := map[string]int{
		"controllogix-download": echo, "controllogix-factorytalk": echo, "ethernetip-cip-cloudshark": echo,
		"micro850-honeypot": 5, "micrologix-pccc": 1024,
	}
	n := map[string]int{}
	for _, r := range recordings(t) {
		w, ok := want[r.File.ID]
		if !ok {
			continue
		}
		for _, c := range r.Conversations {
			if c.Transport != capture.TCP {
				continue
			}
			ex, _ := capture.Exchanges(c)
			for _, e := range ex {
				if e.Reply == nil {
					continue
				}
				q, err1 := encap.Decode(e.Request.Data)
				a, err2 := encap.Decode(e.Reply.Data)
				if err1 != nil || err2 != nil || q.Command != encap.CommandSendRRData {
					continue
				}
				qd, _ := encap.DecodeRRData(q.Data)
				ad, _ := encap.DecodeRRData(a.Data)
				n[r.File.ID]++
				exp := w
				if w == echo {
					exp = int(qd.Timeout)
				}
				if int(ad.Timeout) != exp {
					t.Errorf("%s frame %d: request %d, reply %d, want %d", r.File.ID, e.Reply.Frame, qd.Timeout, ad.Timeout, exp)
				}
			}
		}
	}
	for id := range want {
		if n[id] == 0 {
			t.Errorf("%s: no SendRRData exchange", id)
		}
	}
}

// Every recorded message cut short is refused by Decode and by
// ReadPacket — anywhere in the header and the CPF's start, in the middle
// and one octet short — and one whose length field claims an octet more
// than it holds as well.
func TestCaptureTruncations(t *testing.T) {
	n := 0
	seen := map[string]bool{}
	for _, r := range recordings(t) {
		for _, c := range r.Conversations {
			if c.Transport == capture.UDP && strings.HasSuffix(c.Server, ":2222") {
				continue
			}
			for _, m := range c.Messages {
				// Repeated messages are checked once.
				if len(m.Data) >= 24 {
					// Equal but for session, context and sequence count.
					k := string(m.Data[:4]) + string(m.Data[20:])
					if e, err := capture.ParseExplicit(m.Data); err == nil {
						k = string(m.Data[:2]) + string(e.CIP)
					}
					if seen[k] {
						continue
					}
					seen[k] = true
				}
				n++
				for _, k := range cuts(len(m.Data)) {
					if _, err := encap.Decode(m.Data[:k]); err == nil {
						t.Fatalf("%s frame %d: %d of %d octets decode", r.File.ID, m.Frame, k, len(m.Data))
					}
					if _, _, err := encap.ReadPacket(bytes.NewReader(m.Data[:k]), nil, 0); err == nil {
						t.Fatalf("%s frame %d: ReadPacket of %d octets", r.File.ID, m.Frame, k)
					}
				}
				long := append([]byte(nil), m.Data...)
				long[2]++
				if long[2] == 0 {
					long[3]++
				}
				if _, err := encap.Decode(long); err == nil {
					t.Fatalf("%s frame %d: length +1 decodes", r.File.ID, m.Frame)
				}
			}
		}
	}
	if n < 200 {
		t.Errorf("%d messages", n)
	}
}

// cuts returns the lengths a message of n octets is cut to: 0 to 47, n/2
// and n-1.
func cuts(n int) []int {
	var out []int
	for k := 0; k < min(n, 48); k++ {
		out = append(out, k)
	}
	if n > 48 {
		out = append(out, n/2, n-1)
	}
	return out
}
