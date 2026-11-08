// SPDX-License-Identifier: MIT

package logix_test

import (
	"bytes"
	"context"
	"errors"
	"math/bits"
	"strings"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/internal/capture"
	"github.com/otfabric/go-ethernetip/logix"
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

// replay answers requests with recorded replies: a request that no
// recorded client sent finds no answer and fails the test.
type replay struct {
	t       *testing.T
	answers map[string][]byte // request octets -> response octets
	sent    [][]byte
}

func (r *replay) add(req, resp []byte) { r.answers[string(req)] = resp }

func (r *replay) Do(_ context.Context, req cip.Request) (cip.Response, error) {
	b, err := req.Encode()
	if err != nil {
		return cip.Response{}, err
	}
	r.sent = append(r.sent, b)
	a, ok := r.answers[string(b)]
	if !ok {
		r.t.Errorf("request % x: no recorded client sent it", b)
		return cip.Response{}, errors.New("not recorded")
	}
	resp, err := cip.DecodeResponse(a)
	if err != nil {
		return cip.Response{}, err
	}
	return resp, client.ResponseError(req, resp)
}

// cipOf returns the request and reply octets of the exchange at frame n.
func cipOf(t *testing.T, r capture.Recording, n int) (req, resp []byte) {
	t.Helper()
	e, ok := r.Exchange(n)
	if !ok || e.Reply == nil {
		t.Fatalf("%s: no exchange at frame %d", r.File.ID, n)
	}
	q, err1 := capture.ParseExplicit(e.Request.Data)
	a, err2 := capture.ParseExplicit(e.Reply.Data)
	if err1 != nil || err2 != nil {
		t.Fatalf("%s frame %d: %v %v", r.File.ID, n, err1, err2)
	}
	return q.CIP, a.CIP
}

// The predefined COUNTER and TIMER templates of the 1756-L63, as RSLogix
// 5000 reads them (factorytalk_1756-l63_hmi-reads, frames 99 to 113). The client asks
// Read Template for words×4 − 20 octets, the same request as RSLogix 5000
// (offset 0, 100 and 76 octets); before v0.6.0 it asked for words×4 − 23
// and, against this controller, lost the end of the last member's name
// ("U" for "UN", "D" for "DN").
//
// The client reads the template's attributes with Get_Attribute_List,
// which the recording does not hold: its reply is built from the values
// the controller gave RSLogix 5000's Get_Attributes_All (frames 101 and
// 109: handle, member count, definition words, structure size).
func TestCaptureTemplatesOf1756L63(t *testing.T) {
	r, _ := capture.Get(recordings(t), "controllogix-factorytalk")
	cases := []struct {
		id                uint16
		gaa, read         int // request frames
		members           uint16
		words, size       uint32
		name              string
		want              []logix.Member
		definitionRequest string
	}{
		{
			id: 0x0F82, gaa: 99, read: 102, members: 8, words: 30, size: 12, name: "COUNTER",
			want: []logix.Member{
				{Name: "CTL", Type: logix.NewAtomicType(cip.TypeDWORD, 0, 0)},
				{Name: "PRE", Type: logix.NewAtomicType(cip.TypeDINT, 0, 0), Offset: 4},
				{Name: "ACC", Type: logix.NewAtomicType(cip.TypeDINT, 0, 0), Offset: 8},
				{Name: "CU", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 7, Offset: 3},
				{Name: "CD", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 6, Offset: 3},
				{Name: "DN", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 5, Offset: 3},
				{Name: "OV", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 4, Offset: 3},
				{Name: "UN", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 3, Offset: 3},
			},
		},
		{
			id: 0x0F83, gaa: 108, read: 112, members: 6, words: 24, size: 12, name: "TIMER",
			want: []logix.Member{
				{Name: "CTL", Type: logix.NewAtomicType(cip.TypeDWORD, 0, 0)},
				{Name: "PRE", Type: logix.NewAtomicType(cip.TypeDINT, 0, 0), Offset: 4},
				{Name: "ACC", Type: logix.NewAtomicType(cip.TypeDINT, 0, 0), Offset: 8},
				{Name: "EN", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 7, Offset: 3},
				{Name: "TT", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 6, Offset: 3},
				{Name: "DN", Type: logix.NewAtomicType(cip.TypeBOOL, 0, 0), Info: 5, Offset: 3},
			},
		},
	}
	for _, c := range cases {
		_, gaa := cipOf(t, r, c.gaa)
		attrs, _ := cip.DecodeResponse(gaa)
		// Get_Attributes_All: handle, members, (an attribute not used
		// here), definition words, structure size, and two octets.
		rd := cip.NewReader(attrs.Data)
		handle, members, _, words, size := rd.Uint16(), rd.Uint16(), rd.Uint16(), rd.Uint32(), rd.Uint32()
		if rd.Err() != nil || handle != c.id || members != c.members || words != c.words || size != c.size {
			t.Fatalf("%s: Get_Attributes_All % x", c.name, attrs.Data)
		}
		gal := cip.AppendUint16(nil, 4)
		gal = cip.AppendUint32(cip.AppendUint16(cip.AppendUint16(gal, 4), 0), words)
		gal = cip.AppendUint32(cip.AppendUint16(cip.AppendUint16(gal, 5), 0), size)
		gal = cip.AppendUint16(cip.AppendUint16(cip.AppendUint16(gal, 2), 0), members)
		gal = cip.AppendUint16(cip.AppendUint16(cip.AppendUint16(gal, 1), 0), handle)
		galResp, _ := cip.Response{Service: cip.ServiceGetAttributeList, Data: gal}.Encode()
		galReq, _ := cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(cip.ClassTemplate, uint32(c.id)), Data: []byte{4, 0, 4, 0, 5, 0, 2, 0, 1, 0}}.Encode()

		rp := &replay{t: t, answers: map[string][]byte{}}
		rp.add(galReq, galResp)
		rp.add(cipOf(t, r, c.read))
		tm, err := logix.NewClient(rp).Template(context.Background(), c.id)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if tm.Name != c.name || tm.Handle != c.id || tm.Size != c.size || len(tm.Members) != len(c.want) {
			t.Fatalf("%s: %+v", c.name, tm)
		}
		for i, m := range tm.Members {
			if m != c.want[i] {
				t.Errorf("%s member %d: %+v, want %+v", c.name, i, m, c.want[i])
			}
		}
		// The recorded controller's definition names the structure without
		// the ";n…" suffix the emulation writes (firmware 15.4).
		read, _ := cipOf(t, r, c.read)
		resp := rp.answers[string(read)]
		if bytes.Contains(resp, []byte(c.name+";")) || !bytes.Contains(resp, []byte(c.name+"\x00")) {
			t.Errorf("%s: name in % x", c.name, resp)
		}
		// A COUNTER value decodes with the template: PRE 10, ACC 3, DN.
		if c.name == "COUNTER" {
			v := make([]byte, 12)
			v[3] = 1 << 5
			v[4], v[8] = 10, 3
			fs, err := tm.Decode(v, nil)
			if err != nil || len(fs) != 8 || fs[1].Name != "PRE" || fs[5].Name != "DN" {
				t.Fatalf("decode %+v %v", fs, err)
			}
			if b, err := fs[5].Value.Bool(0); err != nil || !b {
				t.Errorf("DN %v %v", b, err)
			}
		}
	}
}

// rmw is a recorded symbolic Read_Modify_Write_Tag with its reply.
type rmw struct {
	file      string
	frame     int
	req, resp []byte
	tag       string
	size, bit int
	set       bool
}

// recordedRMW returns the symbolic Read_Modify_Write_Tag requests of the
// recordings that change one bit, with their replies (the HMI of
// hmi_logix_bit-writes sends them in Multiple Service Packets).
func recordedRMW(t *testing.T) []rmw {
	var out []rmw
	for _, r := range recordings(t) {
		for _, c := range r.Conversations {
			if c.Transport != capture.TCP {
				continue
			}
			ex, _ := capture.Exchanges(c)
			for _, e := range ex {
				if e.Reply == nil {
					continue
				}
				q, _ := capture.ParseExplicit(e.Request.Data)
				a, _ := capture.ParseExplicit(e.Reply.Data)
				req, err1 := cip.DecodeRequest(q.CIP)
				resp, err2 := cip.DecodeResponse(a.CIP)
				if err1 != nil || err2 != nil || req.Service != cip.ServiceMultipleServicePacket || !resp.OK() {
					continue
				}
				qs, _ := cip.SplitMultiple(req.Data)
				as, _ := cip.SplitMultiple(resp.Data)
				for i, b := range qs {
					p, err := cip.DecodeRequest(b)
					if err != nil || p.Service != cip.ServiceReadModifyWriteTag || !p.Path.Symbolic() || len(p.Path) != 1 {
						continue
					}
					x := rmw{file: r.File.ID, frame: e.Request.Frame, req: b, resp: as[i], tag: p.Path[0].(cip.SymbolSegment).Name}
					rd := cip.NewReader(p.Data)
					x.size = int(rd.Uint16())
					or, and := rd.Bytes(x.size), rd.Bytes(x.size)
					x.bit, x.set = -1, false
					for j := range x.size {
						if or[j] != 0 {
							x.bit, x.set = 8*j+bits.TrailingZeros8(or[j]), true
						}
						if and[j] != 0xFF {
							x.bit = 8*j + bits.TrailingZeros8(^and[j])
						}
					}
					out = append(out, x)
				}
			}
		}
	}
	return out
}

// Client.WriteBit encodes a bit write exactly as the recorded HMI does
// (one octet of OR and AND mask: 01 00 01 ff to set bit 0, 01 00 00 fe to
// clear it), and takes the recorded targets' replies.
func TestCaptureWriteBitMatchesHMI(t *testing.T) {
	rs := recordedRMW(t)
	if len(rs) < 10 {
		t.Fatalf("%d recorded bit writes", len(rs))
	}
	for _, x := range rs {
		rp := &replay{t: t, answers: map[string][]byte{}}
		rp.add(x.req, x.resp)
		tag := x.tag + "." + string(rune('0'+x.bit))
		if err := logix.NewClient(rp).WriteBit(context.Background(), tag, x.size, x.set); err != nil {
			t.Errorf("%s frame %d: WriteBit(%s, %d, %v): %v", x.file, x.frame, tag, x.size, x.set, err)
		}
	}
}

// The emulation answers the recorded HMI's Multiple Service Packets of bit
// writes byte for byte as the recorded targets did, on SINT tags (the
// tags' type is not in the recording; their names and masks suggest BOOL,
// which the emulation does not take for Read_Modify_Write_Tag).
func TestCaptureTagServerAnswersHMIBitWrites(t *testing.T) {
	rs := recordedRMW(t)
	ts := logix.NewTagServer()
	seen := map[string]bool{}
	for _, x := range rs {
		if !seen[x.tag] {
			seen[x.tag] = true
			if err := ts.AddTag(x.tag, cip.TypeSINT); err != nil {
				t.Fatal(err)
			}
		}
	}
	srv, err := server.New(server.WithIOAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	ts.Attach(srv)
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	cl, err := client.Dial(context.Background(), srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	for _, x := range rs {
		req, _ := cip.DecodeRequest(x.req)
		resp, err := cl.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("%s frame %d: %v", x.file, x.frame, err)
		}
		b, _ := resp.Encode()
		if !bytes.Equal(b, x.resp) {
			t.Errorf("%s frame %d: % x, the target answered % x", x.file, x.frame, b, x.resp)
		}
		v, _ := ts.Get(x.tag)
		if got := v.Data[x.bit/8]>>(x.bit%8)&1 == 1; got != x.set {
			t.Errorf("%s frame %d: %s bit %d = %v", x.file, x.frame, x.tag, x.bit, got)
		}
	}
}

// tagExchange is a recorded symbolic Read Tag or Write Tag with its reply.
type tagExchange struct {
	file      string
	frame     int
	req, resp []byte
	r         cip.Request
	a         cip.Response
}

// micro850Tags returns the symbolic Read Tag and Write Tag exchanges with
// the Micro850 (2080-LC50-48QBB), in recorded order, per file.
func micro850Tags(t *testing.T) map[string][]tagExchange {
	out := map[string][]tagExchange{}
	for _, r := range recordings(t) {
		if !strings.HasPrefix(r.File.ID, "micro850-") {
			continue
		}
		for _, c := range r.Conversations {
			ex, _ := capture.Exchanges(c)
			for _, e := range ex {
				if e.Reply == nil {
					continue
				}
				q, err1 := capture.ParseExplicit(e.Request.Data)
				a, err2 := capture.ParseExplicit(e.Reply.Data)
				if err1 != nil || err2 != nil {
					continue
				}
				req, err1 := cip.DecodeRequest(q.CIP)
				resp, err2 := cip.DecodeResponse(a.CIP)
				if err1 != nil || err2 != nil || !req.Path.Symbolic() || (req.Service != cip.ServiceReadTag && req.Service != cip.ServiceWriteTag) {
					continue
				}
				out[r.File.ID] = append(out[r.File.ID], tagExchange{r.File.ID, e.Request.Frame, q.CIP, a.CIP, req, resp})
			}
		}
	}
	return out
}

// The Logix client reads and writes the Micro850's BOOL tags with the
// requests the recorded originators sent (Read Tag of one element; Write
// Tag of BOOL 0xFF and 0x00), and decodes its answers: the value, and
// general status 0x05 for a tag it did not hold.
func TestCaptureClientMicro850Tags(t *testing.T) {
	n := 0
	seen := map[string]bool{}
	for _, xs := range micro850Tags(t) {
		for _, x := range xs {
			k := string(x.req) + string(x.resp)
			if seen[k] {
				continue
			}
			seen[k] = true
			n++
			rp := &replay{t: t, answers: map[string][]byte{string(x.req): x.resp}}
			tag := x.r.Path[0].(cip.SymbolSegment).Name
			c := logix.NewClient(rp)
			switch x.r.Service {
			case cip.ServiceReadTag:
				v, err := c.Read(context.Background(), tag, 1)
				if !x.a.OK() {
					var ce *ethernetip.CIPError
					if !errors.As(err, &ce) || ce.Status != x.a.Status {
						t.Errorf("%s frame %d: %v, want status %v", x.file, x.frame, err, x.a.Status)
					}
					continue
				}
				if err != nil || v.Type != cip.TypeBOOL || v.Count != 1 || !bytes.Equal(v.Data, x.a.Data[2:]) {
					t.Errorf("%s frame %d: %+v %v", x.file, x.frame, v, err)
				}
			case cip.ServiceWriteTag:
				v := logix.Value{Type: cip.TypeBOOL, Count: 1, Data: x.r.Data[4:]}
				if err := c.Write(context.Background(), tag, v); err != nil {
					t.Errorf("%s frame %d: %v", x.file, x.frame, err)
				}
			default: // micro850Tags keeps Read Tag and Write Tag only
			}
		}
	}
	if n < 20 {
		t.Errorf("%d distinct exchanges", n)
	}
}

// The emulation, holding the Micro850's BOOL tags, answers every recorded
// Read Tag and Write Tag byte for byte as the controller did. Before each
// read the tag holds the value the controller answered, unless the
// originator wrote the tag since its last read: then the emulation's own
// value is compared, and a written 0xFF reads back as 1, as on the
// Micro850 (since v0.6.0; before, the emulation kept 0xFF). The one read
// the controller refused with 0x05 (_IO_EM_DO_04 before it existed) is
// answered with 0x05 for a tag the emulation does not hold.
func TestCaptureTagServerAnswersMicro850(t *testing.T) {
	ctx := context.Background()
	readBacks := 0
	for file, xs := range micro850Tags(t) {
		ts := logix.NewTagServer()
		written := map[string]bool{}
		for _, x := range xs {
			tag := x.r.Path[0].(cip.SymbolSegment).Name
			if _, err := ts.Get(tag); err != nil && x.a.OK() {
				if err := ts.AddTag(tag, cip.TypeBOOL); err != nil {
					t.Fatal(err)
				}
			}
			req := x.r
			if !x.a.OK() {
				req.Path = cip.Path{cip.SymbolSegment{Name: tag + "_absent"}}
			} else if x.r.Service == cip.ServiceReadTag && !written[tag] {
				v := logix.Value{Type: cip.TypeBOOL, Count: 1, Data: append([]byte(nil), x.a.Data[2:]...)}
				if err := ts.Set(tag, v); err != nil {
					t.Fatal(err)
				}
			} else if x.r.Service == cip.ServiceReadTag {
				readBacks++
			}
			written[tag] = x.r.Service == cip.ServiceWriteTag
			resp := ts.ServeSymbol(ctx, &server.Request{Request: req})
			resp.Service = req.Service // the Message Router sets it
			got, err := resp.Encode()
			if err != nil || !bytes.Equal(got, x.resp) {
				t.Fatalf("%s frame %d: % x, the Micro850 answered % x", file, x.frame, got, x.resp)
			}
		}
	}
	if readBacks < 10 {
		t.Errorf("%d reads after a write", readBacks)
	}
}
