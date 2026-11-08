// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const dir = "../../testdata/captures"

// The message counts of every committed capture equal what Wireshark 4.6
// decodes: tshark -Y enip -T fields -e enip.command, one per command (a
// frame may hold several), and tshark -Y udp.port==2222 for I/O. The
// exception is the Class 1 Forward_Open file: its frame 5 is a 1460-octet
// retransmission of the stream before frame 1, 14 Forward_Open requests
// (the last the octets of frame 1) and 60 octets of a 15th, which tshark
// does not dissect (it counts 8). In two Micro850 files tshark marks
// segments whose first copy was not captured as spurious retransmissions
// and does not dissect them either; with -o
// tcp.analyze_sequence_numbers:FALSE it counts 232 and 24,615 as here.
func TestCommittedCapturesMatchWireshark(t *testing.T) {
	want := map[string]struct{ explicit, io, convs, dropped int }{
		"icsnpp-enip/unknown_mixed_list-identity-browse-io.pcap":                    {269, 398, 4, 0},
		"icsnpp-enip/unknown_logix_multiple-service-packet.pcapng":                  {1, 0, 1, 0},
		"icsnpp-enip/unknown_unknown_set-attribute-single-vlan.pcapng":              {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_unknown_set-attribute-single-reply.pcap":    {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_logix_multiple-service-packet-request.pcap": {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_logix_multiple-service-packet-reply.pcap":   {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_unknown_start.pcap":                         {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_unknown_stop.pcap":                          {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_unknown_unlock-cpu.pcap":                    {1, 0, 1, 0},
		"iti-ics-security-tools/unknown_1756-enbt_list-identity.pcap":               {2, 0, 2, 0},
		"iti-ics-security-tools/hmi_logix_bit-writes.pcap":                          {8799, 0, 4, 0},
		"ics-pcaps/rslogix5000_1756-l63_download-upload-run.pcap":                   {346, 0, 2, 0},
		"ics-pcaps/factorytalk_1756-l63_hmi-reads.pcap":                             {272, 0, 1, 0},
		"ics-pcaps/rockwell-originator_unknown_forward-open-class1.pcap":            {21, 0, 3, 1},
		"ics-pcaps/unknown_micro850_honeypot.pcap":                                  {132593, 0, 2, 0},
		"ics-pcaps/unknown_micro850_read-write-tags.pcap":                           {24615, 0, 1, 0},
		"ics-pcaps/unknown_micro850_read-tags.pcap":                                 {232, 0, 1, 0},
		"ics-pcaps/unknown_micro850_process-reads.pcap":                             {10650, 0, 1, 0},
		"ics-pcaps/unknown_micro850_session.pcap":                                   {4136, 0, 2, 0},
		"ics-pcaps/unknown_micrologix-1400_pccc-execute.pcap":                       {18798, 0, 2, 0},
	}
	files, err := filepath.Glob(filepath.Join(dir, "*", "*.pcap*"))
	if err != nil || len(files) != len(want) {
		t.Fatalf("%d capture files, %v; want %d", len(files), err, len(want))
	}
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		w, ok := want[filepath.ToSlash(rel)]
		if !ok {
			t.Errorf("%s: no expected counts", rel)
			continue
		}
		convs, err := ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		io := Count(convs, func(c Conversation, _ Message) bool { return isIO(c) })
		explicit := Count(convs, func(Conversation, Message) bool { return true }) - io
		dropped := 0
		for _, c := range convs {
			dropped += c.Dropped
		}
		if explicit != w.explicit || io != w.io || len(convs) != w.convs || dropped != w.dropped {
			t.Errorf("%s: %d explicit, %d I/O, %d conversations, %d dropped; want %+v", rel, explicit, io, len(convs), dropped, w)
		}
	}
}

func isIO(c Conversation) bool { return c.Transport == UDP && strings.HasSuffix(c.Server, ":2222") }

// Every request and reply pair of a conversation has the same command and,
// outside SendUnitData, the same sender context; a SendUnitData reply
// echoes the request's sequence count.
func TestExchangesCorrelate(t *testing.T) {
	recs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pairs := 0
	for _, r := range recs {
		for _, c := range r.Conversations {
			if c.Transport != TCP {
				continue
			}
			ex, _ := Exchanges(c)
			for _, e := range ex {
				if e.Reply == nil {
					continue
				}
				pairs++
				q, _ := ParseHeader(e.Request.Data)
				p, _ := ParseHeader(e.Reply.Data)
				if q.Command != p.Command || e.Reply.Frame <= e.Request.Frame || !e.Request.FromClient || e.Reply.FromClient {
					t.Errorf("%s frame %d: reply %d of command %#x", r.File.ID, e.Request.Frame, e.Reply.Frame, p.Command)
				}
				if q.Command == cmdSendUnitData {
					a, _ := ParseExplicit(e.Request.Data)
					b, _ := ParseExplicit(e.Reply.Data)
					if a.Sequence != b.Sequence || !a.Connected || !b.Connected {
						t.Errorf("%s frame %d: sequence %d, reply %d", r.File.ID, e.Request.Frame, a.Sequence, b.Sequence)
					}
				} else if q.Context != p.Context {
					t.Errorf("%s frame %d: context % x, reply % x", r.File.ID, e.Request.Frame, q.Context, p.Context)
				}
			}
		}
	}
	if pairs < 250 {
		t.Errorf("%d exchanges with a reply", pairs)
	}
}

// The manifest names every file of the corpus, its source and class; the
// committed raw files have the manifest's SHA256 and size, the excerpts
// name it; SHA256SUMS covers every committed file.
func TestManifest(t *testing.T) {
	m, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	for _, s := range m.Sources {
		sources[s.ID] = true
		if s.Licence == "" || s.Redistribution == "" || s.URL == "" {
			t.Errorf("source %s: licence, redistribution or URL missing", s.ID)
		}
	}
	sums := readSums(t)
	seen := map[string]bool{}
	for _, f := range m.Files {
		if seen[f.ID] || !sources[f.Source] || m.Classes[f.Class] == "" || f.URL == "" || len(f.Operations) == 0 ||
			!cleanName.MatchString(f.Name) || f.OriginalName != filepath.Base(f.Path) || filepath.Ext(f.Name) != filepath.Ext(f.OriginalName) {
			t.Errorf("file %s: duplicate, or source %q, class %q, URL or operations missing", f.ID, f.Source, f.Class)
		}
		seen[f.ID] = true
		if stem := strings.TrimSuffix(f.Name, filepath.Ext(f.Name)); filepath.Base(f.Local) != f.Name || stem == "" || filepath.ToSlash(filepath.Dir(f.Local)) != f.Source {
			t.Errorf("%s: stored as %s, named %s", f.ID, f.Local, f.Name)
		}
		b, err := os.ReadFile(filepath.Join(dir, f.Local))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); sums[f.Local] != got {
			t.Errorf("%s: SHA256SUMS has %q, the file %s", f.Local, sums[f.Local], got)
		}
		delete(sums, f.Local)
		if hex.EncodeToString(sum[:]) != f.SHA256 || int64(len(b)) != f.Size {
			t.Errorf("%s: not the file of the manifest", f.Local)
		}

	}
	for p := range sums {
		t.Errorf("SHA256SUMS: %s is not in the manifest", p)
	}
}

// cleanName is <client-or-peer>_<device>_<operation>.<ext>: lower case,
// words joined by hyphens.
var cleanName = regexp.MustCompile(`^[a-z0-9.-]+_[a-z0-9.-]+_[a-z0-9-]+\.(pcap|pcapng)$`)

func readSums(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("SHA256SUMS: %q", sc.Text())
		}
		out[path] = sum
	}
	return out
}

// --- Synthetic captures: formats and stream edge cases. ---

type frame struct {
	udp            bool
	src, dst       [4]byte
	sport, dport   uint16
	seq            uint32
	flags          byte // TCP flags
	payload        []byte
	vlan           int // number of 802.1Q tags
	fragment       bool
	notIPv4, short bool
}

func (f frame) bytes() []byte {
	if f.short {
		return make([]byte, 10)
	}
	eth := make([]byte, 12)
	for range f.vlan {
		eth = append(eth, 0x81, 0x00, 0, 1)
	}
	if f.notIPv4 {
		return append(eth, 0x86, 0xdd, 0, 0)
	}
	eth = append(eth, 0x08, 0x00)
	var l4 []byte
	proto := byte(6)
	if f.udp {
		proto = 17
		l4 = binary.BigEndian.AppendUint16(nil, f.sport)
		l4 = binary.BigEndian.AppendUint16(l4, f.dport)
		l4 = binary.BigEndian.AppendUint16(l4, uint16(8+len(f.payload)))
		l4 = append(append(l4, 0, 0), f.payload...)
	} else {
		l4 = binary.BigEndian.AppendUint16(nil, f.sport)
		l4 = binary.BigEndian.AppendUint16(l4, f.dport)
		l4 = binary.BigEndian.AppendUint32(l4, f.seq)
		l4 = append(l4, 0, 0, 0, 0, 0x50, f.flags, 0, 0, 0, 0, 0, 0)
		l4 = append(l4, f.payload...)
	}
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	if f.fragment {
		ip[6] = 0x20
	}
	ip = append(append(append(ip, f.src[:]...), f.dst[:]...), l4...)
	return append(eth, ip...)
}

var (
	cli = [4]byte{10, 0, 0, 1}
	srv = [4]byte{10, 0, 0, 2}
)

// pcap returns a classic pcap file (little endian, microseconds) of the
// frames, one second apart.
func pcap(frames ...frame) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[20:], 1)
	for i, f := range frames {
		d := f.bytes()
		b = binary.LittleEndian.AppendUint32(b, uint32(1000+i))
		b = binary.LittleEndian.AppendUint32(b, 5)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(d)))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(d)))
		b = append(b, d...)
	}
	return b
}

// encapMsg returns an encapsulation message of command cmd with data.
func encapMsg(cmd uint16, ctx byte, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, cmd)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, make([]byte, 20)...)
	b[12] = ctx
	return append(b, data...)
}

// rrData returns SendRRData data with an unconnected data item.
func rrData(cip []byte) []byte {
	b := []byte{0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(cip)))
	return append(b, cip...)
}

// unitData returns SendUnitData data with connection ID id and sequence
// count seq.
func unitData(id uint32, seq uint16, cip []byte) []byte {
	b := []byte{0, 0, 0, 0, 0, 0, 2, 0, 0xa1, 0, 4, 0}
	b = binary.LittleEndian.AppendUint32(b, id)
	b = append(b, 0xb1, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2+len(cip)))
	b = binary.LittleEndian.AppendUint16(b, seq)
	return append(b, cip...)
}

func TestStreamReassembly(t *testing.T) {
	req := encapMsg(0x6f, 1, rrData([]byte{0x0e, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x05}))
	rep := encapMsg(0x6f, 1, rrData([]byte{0x8e, 0, 0, 0, 0x60, 0x31}))
	reg := encapMsg(0x65, 0, []byte{1, 0, 0, 0})
	two := append(append([]byte(nil), reg...), req...)
	b := pcap(
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 99, flags: 0x02},
		// Register and the first half of the request in one segment, then
		// the rest: a message split over two segments, two in one.
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 100, flags: 0x18, payload: two[:40]},
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 140, flags: 0x18, payload: two[40:]},
		// A retransmission of the second segment: dropped.
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 140, flags: 0x18, payload: two[40:]},
		frame{src: srv, dst: cli, sport: ExplicitPort, dport: 4000, seq: 500, flags: 0x18, payload: rep},
		frame{vlan: 2, src: srv, dst: cli, sport: ExplicitPort, dport: 4000, seq: 500 + uint32(len(rep)), flags: 0x18, payload: rep},
		frame{src: cli, dst: srv, sport: 7, dport: 9, seq: 1, payload: []byte{1}},    // other port
		frame{udp: true, src: cli, dst: srv, sport: 7, dport: 9, payload: []byte{1}}, // other port
		frame{notIPv4: true},
		frame{short: true},
	)
	convs, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 1 || convs[0].Client != "10.0.0.1:4000" || convs[0].Server != "10.0.0.2:44818" || convs[0].Gaps != 0 || convs[0].Dropped != 0 {
		t.Fatalf("%+v", convs)
	}
	ms := convs[0].Messages
	if len(ms) != 4 || !bytes.Equal(ms[0].Data, reg) || ms[0].Frame != 2 || !bytes.Equal(ms[1].Data, req) || ms[1].Frame != 3 || ms[2].Frame != 5 || ms[3].Frame != 6 {
		t.Fatalf("messages %+v", ms)
	}
	if !ms[1].Time.Equal(time.Unix(1002, 5000).UTC()) {
		t.Errorf("time %v", ms[1].Time)
	}
	ex, orphans := Exchanges(convs[0])
	if len(ex) != 2 || ex[0].Reply != nil || ex[1].Reply == nil || ex[1].Reply.Frame != 5 || len(orphans) != 1 {
		t.Fatalf("exchanges %+v, orphans %d", ex, len(orphans))
	}
	e, err := ParseExplicit(req)
	if err != nil || e.Connected || len(e.CIP) != 8 {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestStreamGapsAndResync(t *testing.T) {
	m1 := encapMsg(0x6f, 1, rrData([]byte{1, 0}))
	m2 := encapMsg(0x6f, 2, rrData([]byte{1, 0}))
	m3 := encapMsg(0x6f, 3, rrData([]byte{1, 0}))
	b := pcap(
		// No SYN: the capture starts inside a message (the last 5 octets of
		// one), then m1; a gap; the first half of m2 then m3 after a gap.
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 1000, flags: 0x18, payload: append([]byte{9, 9, 9, 9, 9}, m1...)},
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 2000, flags: 0x18, payload: m2[:10]},
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 3000, flags: 0x18, payload: m3},
		// An earlier retransmission that arrives last: the bytes are
		// already delivered, the earlier frame number stays.
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 1005, flags: 0x18, payload: m1},
		// A chunk without any plausible header.
		frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 5000, flags: 0x18, payload: []byte{1, 2, 3}},
	)
	convs, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	c := convs[0]
	if c.Gaps != 3 || c.Dropped != 3 || len(c.Messages) != 2 || c.Messages[0].Frame != 1 || c.Messages[1].Frame != 3 {
		t.Fatalf("gaps %d dropped %d messages %+v", c.Gaps, c.Dropped, c.Messages)
	}
	if Resync([]byte{1, 2, 3}) != -1 || Resync(append([]byte{0}, m1...)) != 1 {
		t.Error("Resync")
	}
}

func TestConnectedExchanges(t *testing.T) {
	q := encapMsg(0x70, 0, unitData(0x01020304, 7, []byte{0x0e, 0x02, 0x20, 0x01, 0x24, 0x01}))
	r := encapMsg(0x70, 0, unitData(0x80000001, 7, []byte{0x8e, 0, 0, 0}))
	stray := encapMsg(0x70, 0, unitData(0x80000001, 9, []byte{0x8e, 0, 0, 0}))
	bad := encapMsg(0x70, 0, []byte{1, 2})
	c := Conversation{Transport: TCP, Messages: []Message{
		{FromClient: true, Frame: 1, Data: q},
		{FromClient: true, Frame: 2, Data: bad},
		{Frame: 3, Data: stray},
		{Frame: 4, Data: r},
		{Frame: 5, Data: bad},
	}}
	ex, orphans := Exchanges(c)
	if len(ex) != 2 || ex[0].Reply == nil || ex[0].Reply.Frame != 4 || ex[1].Reply != nil || len(orphans) != 2 {
		t.Fatalf("%+v %+v", ex, orphans)
	}
	e, err := ParseExplicit(q)
	if err != nil || !e.Connected || e.ConnID != 0x01020304 || e.Sequence != 7 || len(e.CIP) != 6 {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestParseExplicitErrors(t *testing.T) {
	ok := encapMsg(0x6f, 0, rrData([]byte{1, 0}))
	cases := map[string][]byte{
		"short":       {0x6f},
		"command":     encapMsg(0x65, 0, rrData([]byte{1, 0})),
		"length":      append(append([]byte(nil), ok...), 0),
		"no items":    encapMsg(0x6f, 0, []byte{0, 0}),
		"item count":  encapMsg(0x6f, 0, []byte{0, 0, 0, 0, 0, 0, 1, 0}),
		"item length": encapMsg(0x6f, 0, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0xb2, 0, 9, 0}),
		"no data":     encapMsg(0x6f, 0, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0}),
		"address":     encapMsg(0x70, 0, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0xa1, 0, 1, 0, 0}),
		"connected":   encapMsg(0x70, 0, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0xb1, 0, 1, 0, 0}),
	}
	for name, b := range cases {
		if _, err := ParseExplicit(b); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ParseExplicit(ok); err != nil {
		t.Error(err)
	}
}

func TestUDP(t *testing.T) {
	io := []byte{2, 0, 0x02, 0x80, 8, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0xb1, 0, 2, 0, 1, 0}
	li := encapMsg(0x63, 0, nil)
	b := pcap(
		frame{udp: true, src: srv, dst: cli, sport: IOPort, dport: IOPort, payload: io},
		frame{udp: true, src: cli, dst: srv, sport: IOPort, dport: IOPort, payload: io},
		frame{udp: true, src: cli, dst: srv, sport: 5000, dport: ExplicitPort, payload: li},
		frame{udp: true, src: srv, dst: cli, sport: ExplicitPort, dport: 5000, payload: li},
		frame{udp: true, src: cli, dst: srv, sport: 5000, dport: IOPort, payload: io},
	)
	convs, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 3 || !isIO(convs[0]) || convs[0].Messages[0].FromClient || !convs[0].Messages[1].FromClient {
		t.Fatalf("%+v", convs)
	}
	if !convs[1].Messages[0].FromClient || convs[1].Messages[1].FromClient || convs[1].Transport != UDP {
		t.Fatalf("%+v", convs[1])
	}
}

func TestFormats(t *testing.T) {
	m := encapMsg(0x63, 0, nil)
	f := frame{udp: true, src: cli, dst: srv, sport: 5000, dport: ExplicitPort, payload: m}
	le := pcap(f)
	// Big-endian classic pcap, nanosecond time stamps.
	be := make([]byte, len(le))
	copy(be, le)
	binary.BigEndian.PutUint32(be, 0xa1b23c4d)
	binary.BigEndian.PutUint32(be[20:], 1)
	for off := 24; off < len(be); {
		n := binary.LittleEndian.Uint32(le[off+8:])
		for i := 0; i < 16; i += 4 {
			binary.BigEndian.PutUint32(be[off+i:], binary.LittleEndian.Uint32(le[off+i:]))
		}
		off += 16 + int(n)
	}
	convs, err := Read(be)
	if err != nil || len(convs) != 1 || !convs[0].Messages[0].Time.Equal(time.Unix(1000, 5).UTC()) {
		t.Fatalf("big endian: %+v %v", convs, err)
	}
	for _, magic := range []uint32{0xa1b23c4d} {
		b := append([]byte(nil), le...)
		binary.LittleEndian.PutUint32(b, magic)
		if c, err := Read(b); err != nil || !c[0].Messages[0].Time.Equal(time.Unix(1000, 5).UTC()) {
			t.Errorf("magic %#x: %v", magic, err)
		}
	}
	binary.BigEndian.PutUint32(be, 0xa1b2c3d4)
	if c, err := Read(be); err != nil || !c[0].Messages[0].Time.Equal(time.Unix(1000, 5000).UTC()) {
		t.Errorf("big endian microseconds: %v", err)
	}

	ng := pcapng(f.bytes(), 6)
	convs, err = Read(ng)
	if err != nil || len(convs) != 1 || !convs[0].Messages[0].Time.Equal(time.Unix(0, 1_500_000).UTC()) {
		t.Fatalf("pcapng: %+v %v", convs, err)
	}
	ng = pcapng(f.bytes(), 9)
	if c, err := Read(ng); err != nil || !c[0].Messages[0].Time.Equal(time.Unix(0, 1500).UTC()) {
		t.Fatalf("pcapng ns: %+v %v", c, err)
	}
	ng = pcapng(f.bytes(), 0x86) // binary resolution: not supported, microseconds
	if c, err := Read(ng); err != nil || !c[0].Messages[0].Time.Equal(time.Unix(0, 1_500_000).UTC()) {
		t.Fatalf("pcapng binary resolution: %+v %v", c, err)
	}
	if c, err := Read(pcapngSimple(f.bytes())); err != nil || len(c) != 1 {
		t.Fatalf("simple packet: %+v %v", c, err)
	}
	be2 := pcapng(f.bytes(), 6)
	be2[8], be2[9], be2[10], be2[11] = 0x1a, 0x2b, 0x3c, 0x4d // big-endian magic, the rest little endian
	if _, err := Read(be2); err == nil {
		t.Error("pcapng with mixed byte order read")
	}
}

// pcapng returns a pcapng file with one Ethernet interface whose if_tsresol
// option is res, and one enhanced packet of time stamp 1500.
func pcapng(pkt []byte, res byte) []byte {
	block := func(typ uint32, body []byte) []byte {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		b := binary.LittleEndian.AppendUint32(nil, typ)
		b = binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
		b = append(b, body...)
		return binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
	}
	shb := block(0x0a0d0d0a, []byte{0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	idb := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	idb = append(idb, 2, 0, 3, 0, 'a', 'b', 'c', 0) // if_name, padded
	idb = append(idb, 9, 0, 1, 0, res, 0, 0, 0, 0, 0, 0, 0)
	epb := binary.LittleEndian.AppendUint32(nil, 0)
	epb = binary.LittleEndian.AppendUint32(epb, 0)
	epb = binary.LittleEndian.AppendUint32(epb, 1500)
	epb = binary.LittleEndian.AppendUint32(epb, uint32(len(pkt)))
	epb = binary.LittleEndian.AppendUint32(epb, uint32(len(pkt)))
	epb = append(epb, pkt...)
	return append(append(shb, block(1, idb)...), block(6, epb)...)
}

func pcapngSimple(pkt []byte) []byte {
	b := pcapng(pkt, 6)
	// Replace the enhanced packet block by a simple packet block.
	shbLen := int(binary.LittleEndian.Uint32(b[4:]))
	idbLen := int(binary.LittleEndian.Uint32(b[shbLen+4:]))
	b = b[:shbLen+idbLen]
	body := binary.LittleEndian.AppendUint32(nil, uint32(len(pkt)))
	body = append(body, pkt...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
	b = append(b, body...)
	return binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
}

func TestMalformedFiles(t *testing.T) {
	f := frame{udp: true, src: cli, dst: srv, sport: 5000, dport: ExplicitPort, payload: encapMsg(0x63, 0, nil)}
	good := pcap(f)
	ng := pcapng(f.bytes(), 6)
	cases := map[string][]byte{
		"empty":          nil,
		"magic":          {1, 2, 3, 4, 5},
		"pcap header":    good[:20],
		"record header":  good[:30],
		"record length":  good[:len(good)-1],
		"pcapng block":   ng[:10],
		"pcapng length":  append(ng[:len(ng):len(ng)], 1, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0),
		"pcapng idb":     pcapngBody(1, []byte{1, 0}),
		"pcapng epb":     pcapngBody(6, make([]byte, 8)),
		"pcapng no idb":  pcapngBody(6, make([]byte, 20)),
		"pcapng spb":     pcapngBody(3, make([]byte, 4)),
		"pcapng section": pcapngSection(),
	}
	for name, b := range cases {
		if _, err := Read(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(other[20:], 113) // Linux cooked capture
	if _, err := Read(other); err == nil {
		t.Error("link type 113 read")
	}
	frag := frame{udp: true, fragment: true, src: cli, dst: srv, sport: 5000, dport: ExplicitPort, payload: []byte{1}}
	if _, err := Read(pcap(frag)); err == nil {
		t.Error("fragment read")
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Error("missing file read")
	}
	if _, err := ReadFile("/nonexistent-dir/x.pcap"); err == nil {
		t.Error("missing directory read")
	}
}

// pcapngBody returns a section header and one block of type typ.
func pcapngBody(typ uint32, body []byte) []byte {
	shb := pcapng(nil, 6)[:28]
	b := binary.LittleEndian.AppendUint32(append([]byte(nil), shb...), typ)
	b = binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
	b = append(b, body...)
	return binary.LittleEndian.AppendUint32(b, uint32(12+len(body)))
}

func pcapngSection() []byte {
	b := pcapng(nil, 6)[:28]
	b = append([]byte(nil), b...)
	b[8] = 0 // neither byte-order magic
	return b
}

// Truncated or implausible frames inside a valid file are skipped, not
// errors.
func TestShortFrames(t *testing.T) {
	ok := frame{src: cli, dst: srv, sport: 4000, dport: ExplicitPort, seq: 1, flags: 0x18, payload: encapMsg(0x6f, 0, rrData([]byte{1, 0}))}
	full := ok.bytes()
	cut := func(n int) []byte { return full[:n] }
	vlanCut := frame{vlan: 1}.bytes()[:15]
	udpShort := frame{udp: true, src: cli, dst: srv, sport: 1, dport: ExplicitPort}.bytes()
	udpShort = udpShort[:len(udpShort)-4]
	badUDPLen := frame{udp: true, src: cli, dst: srv, sport: 1, dport: ExplicitPort, payload: []byte{1}}.bytes()
	badUDPLen[14+20+4] = 0xff
	badTHL := append([]byte(nil), full...)
	badTHL[14+20+12] = 0x10
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[20:], 1)
	for _, d := range [][]byte{cut(13), cut(30), cut(14 + 20 + 10), vlanCut, udpShort, badUDPLen, badTHL} {
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(d)))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(d)))
		b = append(b, d...)
	}
	convs, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n := Count(convs, func(Conversation, Message) bool { return true }); n != 0 {
		t.Errorf("%d messages from broken frames", n)
	}
}

func TestLoadErrors(t *testing.T) {
	d := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadManifest(d); err == nil {
		t.Error("missing manifest read")
	}
	write("manifest.json", `{"files":[{"id":"x","local":"none.pcap"}]}`)
	if _, err := Load(d); err == nil {
		t.Error("missing capture loaded")
	}
	write("manifest.json", `{"bad":1}`)
	if _, err := Load(d); err == nil {
		t.Error("bad manifest loaded")
	}
	if _, err := ReadManifest("/nonexistent-dir"); err == nil {
		t.Error("missing directory read")
	}
}

// coverage.json, the machine-readable report of what the recorded traffic
// verifies, names files of the manifest, frames the corpus holds, results
// of its legend, and tests that exist.
func TestCoverageReport(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(dir, "coverage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Schema  int               `json:"schema"`
		Results map[string]string `json:"results"`
		Cases   []struct {
			ID                                                            string
			File                                                          string
			Frames                                                        []int
			Device, Class, Message                                        string
			RequestEncoding, ResponseDecoding, ClientReplay, ServerParity string
			Difference                                                    string
			Tests                                                         []string
		} `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	recs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range rep.Cases {
		if ids[c.ID] {
			t.Errorf("case %s twice", c.ID)
		}
		ids[c.ID] = true
		r, ok := Get(recs, c.File)
		// A case is never better evidence than its file (a merged file is
		// classed by its best part).
		if !ok || c.Class < r.File.Class || c.Class > "D" {
			t.Errorf("%s: file %s, class %s", c.ID, c.File, c.Class)
		}
		for _, f := range c.Frames {
			if _, _, ok := r.Frame(f); !ok {
				t.Errorf("%s: %s holds no frame %d", c.ID, c.File, f)
			}
		}
		for _, res := range []string{c.RequestEncoding, c.ResponseDecoding, c.ClientReplay, c.ServerParity} {
			if rep.Results[res] == "" {
				t.Errorf("%s: result %q", c.ID, res)
			}
		}
		for _, tn := range c.Tests {
			pkg, name, _ := strings.Cut(tn, " ")
			files, _ := filepath.Glob(filepath.Join("../..", pkg, "*_test.go"))
			found := false
			for _, f := range files {
				src, _ := os.ReadFile(f)
				found = found || bytes.Contains(src, []byte("func "+name+"("))
			}
			if !found {
				t.Errorf("%s: no test %s", c.ID, tn)
			}
		}
	}
}

func TestRecordingLookups(t *testing.T) {
	recs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(recs, "no-such-file"); ok {
		t.Error("Get of an unknown file")
	}
	r, ok := Get(recs, "controllogix-download")
	if !ok {
		t.Fatal("controllogix-download missing")
	}
	if _, _, ok := r.Frame(1 << 30); ok {
		t.Error("Frame beyond the file")
	}
	e, ok := r.Exchange(221)
	if !ok || e.Reply == nil || e.Reply.Frame != 222 {
		t.Errorf("Exchange(221) = %+v, %v", e, ok)
	}
	if _, ok := r.Exchange(222); ok {
		t.Error("a reply frame found as a request")
	}
	io, _ := Get(recs, "icsnpp-enip-cip-example")
	if _, ok := io.Exchange(377); ok {
		t.Error("an I/O datagram found as a request")
	}
}

// A pcapng time stamp beyond time.Time's seconds is refused.
func TestPcapngTimeOverflow(t *testing.T) {
	f := frame{udp: true, src: cli, dst: srv, sport: 5000, dport: ExplicitPort, payload: encapMsg(0x63, 0, nil)}
	b := pcapng(f.bytes(), 0) // one unit per second
	shb := int(binary.LittleEndian.Uint32(b[4:]))
	idb := int(binary.LittleEndian.Uint32(b[shb+4:]))
	epb := shb + idb
	binary.LittleEndian.PutUint32(b[epb+8+4:], 0xFFFFFFFF) // time stamp, high word
	if _, err := Read(b); !errors.Is(err, ErrFormat) {
		t.Errorf("time stamp 2^64-1 s: %v", err)
	}
	binary.LittleEndian.PutUint32(b[epb+8+4:], 1)
	if c, err := Read(b); err != nil || c[0].Messages[0].Time.Unix() != 1<<32+1500 {
		t.Errorf("time stamp 2^32+1500 s: %v", err)
	}
}
