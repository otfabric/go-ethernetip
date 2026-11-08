// SPDX-License-Identifier: MIT

// Package capture reads recorded EtherNet/IP traffic for tests: classic pcap
// and pcapng files with Ethernet frames (optionally 802.1Q tagged), IPv4,
// TCP and UDP.
//
// On TCP port 44818 it reassembles each direction of a connection in
// sequence order (retransmitted and overlapping bytes are dropped) and
// splits the byte stream into encapsulation packets: the 24-byte header and
// the number of data bytes its length field names. A packet that spans
// several segments is joined; several packets in one segment are split.
// UDP datagrams on port 44818 are encapsulation packets too (ListIdentity
// and the other discovery commands); UDP datagrams to or from port 2222 are
// implicit (Class 0/1) I/O messages, a common packet format without a
// header.
//
// A recording may lack segments (capture started mid-connection, or a
// filtered file), so a sequence gap is not an error: the bytes on each side
// of it are split separately and a packet cut by the gap is dropped and
// counted in Conversation.Dropped. A connection whose first segment was not
// captured starts at a packet boundary only if the capture begins at one;
// Resync finds the first plausible header.
//
// It is test infrastructure for testdata/captures and not part of the public
// API. It reads files from this repository or from the extended-corpus cache,
// not untrusted input, but it still checks every length it reads.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Ports of EtherNet/IP.
const (
	ExplicitPort = 44818 // TCP and UDP: encapsulation
	IOPort       = 2222  // UDP: implicit I/O
)

// Transport of a conversation.
type Transport string

// Transports.
const (
	TCP Transport = "tcp"
	UDP Transport = "udp"
)

// Message is one encapsulation packet (TCP or UDP 44818) or one implicit I/O
// datagram (UDP 2222).
type Message struct {
	// FromClient is true for a message sent by the side that is not on the
	// EtherNet/IP port (the originator). For UDP 2222, where both sides use
	// the port, it is true for the side with the lower address.
	FromClient bool
	Frame      int       // 1-based number of the frame that completed it
	Time       time.Time // capture time of that frame
	Data       []byte    // encapsulation header and data, or the I/O CPF
}

// Conversation is one TCP connection or one UDP address pair.
type Conversation struct {
	Transport      Transport
	Client, Server string // "ip:port"
	// Gaps is the number of sequence gaps in both directions; Dropped the
	// packets lost to them or cut by the start or end of the capture.
	Gaps, Dropped int
	// Messages in the order they completed. Each direction is in sequence
	// order; the two directions are merged by completing frame.
	Messages []Message
}

// ErrFormat reports a file that is neither pcap nor pcapng, or is cut short.
var ErrFormat = errors.New("capture: unsupported or malformed capture file")

const (
	linkEthernet = 1
	etherIPv4    = 0x0800
	etherVLAN    = 0x8100
	protoTCP     = 6
	protoUDP     = 17
	headerSize   = 24
)

// ReadFile reads a capture file and returns its EtherNet/IP conversations,
// ordered by the frame that opened them.
func ReadFile(path string) ([]Conversation, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	return Read(b)
}

// Read parses a capture held in memory.
func Read(b []byte) ([]Conversation, error) {
	frames, err := packets(b)
	if err != nil {
		return nil, err
	}
	a := newAssembler()
	for i, f := range frames {
		if err := a.frame(i+1, f); err != nil {
			return nil, fmt.Errorf("frame %d: %w", i+1, err)
		}
	}
	return a.conversations(), nil
}

// packet is one link-layer frame.
type packet struct {
	link uint32
	time time.Time
	data []byte
}

// packets returns the frames of a pcap or pcapng file.
func packets(b []byte) ([]packet, error) {
	if len(b) < 4 {
		return nil, ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		return pcapPackets(b, binary.LittleEndian, time.Microsecond)
	case 0xa1b23c4d:
		return pcapPackets(b, binary.LittleEndian, time.Nanosecond)
	case 0xd4c3b2a1:
		return pcapPackets(b, binary.BigEndian, time.Microsecond)
	case 0x4d3cb2a1:
		return pcapPackets(b, binary.BigEndian, time.Nanosecond)
	case 0x0a0d0d0a:
		return pcapngPackets(b)
	}
	return nil, ErrFormat
}

func pcapPackets(b []byte, bo binary.ByteOrder, unit time.Duration) ([]packet, error) {
	if len(b) < 24 {
		return nil, ErrFormat
	}
	link := bo.Uint32(b[20:24]) & 0x0fffffff
	var out []packet
	for off := 24; off < len(b); {
		if len(b)-off < 16 {
			return nil, ErrFormat
		}
		sec := int64(bo.Uint32(b[off:]))
		frac := int64(bo.Uint32(b[off+4:]))
		n := int(bo.Uint32(b[off+8 : off+12]))
		off += 16
		if n > len(b)-off {
			return nil, ErrFormat
		}
		t := time.Unix(sec, frac*int64(unit)).UTC()
		out = append(out, packet{link: link, time: t, data: b[off : off+n]})
		off += n
	}
	return out, nil
}

// iface is a pcapng interface: link type and time stamp units per second.
type iface struct {
	link   uint32
	perSec uint64
}

func pcapngPackets(b []byte) ([]packet, error) {
	var (
		bo     binary.ByteOrder = binary.LittleEndian
		ifaces []iface
		out    []packet
	)
	for off := 0; off < len(b); {
		if len(b)-off < 12 {
			return nil, ErrFormat
		}
		typ := bo.Uint32(b[off:])
		if typ == 0x0a0d0d0a { // section header: byte order from its magic
			switch binary.LittleEndian.Uint32(b[off+8:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return nil, ErrFormat
			}
			ifaces = ifaces[:0]
		}
		n := int(bo.Uint32(b[off+4:]))
		if n < 12 || n%4 != 0 || n > len(b)-off {
			return nil, ErrFormat
		}
		body := b[off+8 : off+n-4]
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				return nil, ErrFormat
			}
			ifaces = append(ifaces, iface{link: uint32(bo.Uint16(body)), perSec: tsresol(body[8:], bo)})
		case 6: // enhanced packet
			if len(body) < 20 {
				return nil, ErrFormat
			}
			ifc := int(bo.Uint32(body))
			ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
			capLen := int(bo.Uint32(body[12:]))
			if ifc >= len(ifaces) || capLen > len(body)-20 {
				return nil, ErrFormat
			}
			ps := ifaces[ifc].perSec
			sec, frac := ts/ps, ts%ps
			if sec > math.MaxInt64 {
				return nil, ErrFormat
			}
			t := time.Unix(int64(sec), int64(frac*(1e9/ps))).UTC()
			out = append(out, packet{link: ifaces[ifc].link, time: t, data: body[20 : 20+capLen]})
		case 3: // simple packet, interface 0, no time stamp
			if len(body) < 4 || len(ifaces) == 0 {
				return nil, ErrFormat
			}
			capLen := min(int(bo.Uint32(body)), len(body)-4)
			out = append(out, packet{link: ifaces[0].link, data: body[4 : 4+capLen]})
		}
		off += n
	}
	return out, nil
}

// tsresol reads the if_tsresol option of an interface description block
// and returns time stamp units per second; the default is microseconds.
// Only decimal resolutions down to 1 ns are supported; others fall back to
// the default.
func tsresol(opts []byte, bo binary.ByteOrder) uint64 {
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+n > len(opts) {
			break
		}
		if code == 9 && n == 1 && opts[4]&0x80 == 0 && opts[4] <= 9 {
			ps := uint64(1)
			for range opts[4] {
				ps *= 10
			}
			return ps
		}
		opts = opts[4+(n+3)&^3:]
	}
	return 1_000_000
}

// segment is the TCP payload of one frame.
type segment struct {
	frame   int
	time    time.Time
	seq     uint32
	payload []byte
}

// flow is one direction of a TCP connection.
type flow struct {
	syn  bool
	isn  uint32
	segs []segment
}

type connKey struct {
	transport      Transport
	client, server string
}

type conn struct {
	key        connKey
	firstFrame int
	up, down   *flow     // TCP: client to server, server to client
	datagrams  []Message // UDP
}

type assembler struct {
	conns map[connKey]*conn
}

func newAssembler() *assembler { return &assembler{conns: map[connKey]*conn{}} }

func (a *assembler) get(key connKey, num int) *conn {
	c := a.conns[key]
	if c == nil {
		c = &conn{key: key, firstFrame: num, up: &flow{}, down: &flow{}}
		a.conns[key] = c
	}
	return c
}

// frame takes one link-layer frame; frames that are not IPv4 TCP or UDP on
// an EtherNet/IP port are ignored.
func (a *assembler) frame(num int, p packet) error {
	if p.link != linkEthernet {
		return fmt.Errorf("link type %d: only Ethernet is supported", p.link)
	}
	d := p.data
	if len(d) < 14 {
		return nil
	}
	etherType := binary.BigEndian.Uint16(d[12:14])
	d = d[14:]
	for etherType == etherVLAN {
		if len(d) < 4 {
			return nil
		}
		etherType = binary.BigEndian.Uint16(d[2:4])
		d = d[4:]
	}
	if etherType != etherIPv4 || len(d) < 20 || d[0]>>4 != 4 {
		return nil
	}
	ihl := int(d[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[2:4]))
	if ihl < 20 || total < ihl || total > len(d) {
		return nil
	}
	if d[9] != protoTCP && d[9] != protoUDP {
		return nil
	}
	if binary.BigEndian.Uint16(d[6:8])&0x3fff != 0 {
		return errors.New("fragmented IPv4 is not supported")
	}
	src := fmt.Sprintf("%d.%d.%d.%d", d[12], d[13], d[14], d[15])
	dst := fmt.Sprintf("%d.%d.%d.%d", d[16], d[17], d[18], d[19])
	t := d[ihl:total]
	if d[9] == protoUDP {
		return a.udp(num, p.time, src, dst, t)
	}
	return a.tcp(num, p.time, src, dst, t)
}

func (a *assembler) udp(num int, ts time.Time, src, dst string, t []byte) error {
	if len(t) < 8 {
		return nil
	}
	sport, dport := binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
	n := int(binary.BigEndian.Uint16(t[4:6]))
	if n < 8 || n > len(t) {
		return nil
	}
	payload := t[8:n]
	s, d := fmt.Sprintf("%s:%d", src, sport), fmt.Sprintf("%s:%d", dst, dport)
	var key connKey
	var fromClient bool
	switch {
	case sport == IOPort && dport == IOPort:
		lo, hi := s, d
		if hi < lo {
			lo, hi = hi, lo
		}
		key, fromClient = connKey{UDP, lo, hi}, s == lo
	case dport == ExplicitPort || dport == IOPort:
		key, fromClient = connKey{UDP, s, d}, true
	case sport == ExplicitPort || sport == IOPort:
		key = connKey{UDP, d, s}
	default:
		return nil
	}
	c := a.get(key, num)
	c.datagrams = append(c.datagrams, Message{FromClient: fromClient, Frame: num, Time: ts, Data: payload})
	return nil
}

func (a *assembler) tcp(num int, ts time.Time, src, dst string, t []byte) error {
	if len(t) < 20 {
		return nil
	}
	sport, dport := binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
	thl := int(t[12]>>4) * 4
	if thl < 20 || thl > len(t) {
		return nil
	}
	var key connKey
	var toServer bool
	switch {
	case dport == ExplicitPort:
		key, toServer = connKey{TCP, fmt.Sprintf("%s:%d", src, sport), fmt.Sprintf("%s:%d", dst, dport)}, true
	case sport == ExplicitPort:
		key = connKey{TCP, fmt.Sprintf("%s:%d", dst, dport), fmt.Sprintf("%s:%d", src, sport)}
	default:
		return nil
	}
	c := a.get(key, num)
	f := c.down
	if toServer {
		f = c.up
	}
	seq := binary.BigEndian.Uint32(t[4:8])
	if t[13]&0x02 != 0 { // SYN: data starts at ISN+1; a new SYN starts the flow again
		f.syn, f.isn, f.segs = true, seq, nil
		return nil
	}
	if payload := t[thl:]; len(payload) > 0 {
		f.segs = append(f.segs, segment{frame: num, time: ts, seq: seq, payload: payload})
	}
	return nil
}

// chunk is reassembled flow data with the frame (and its time) that
// delivered each byte.
type chunk struct {
	data   []byte
	frames []int
	times  []time.Time
	// cut is true when the chunk follows a gap or starts without a SYN: its
	// first byte need not be a packet boundary.
	cut bool
}

// seqDiff is a - b in TCP sequence space (RFC 1982 serial arithmetic):
// negative when a lies before b.
func seqDiff(a, b uint32) int64 {
	d := int64(a - b)
	if d >= 1<<31 {
		d -= 1 << 32
	}
	return d
}

// stream reassembles a flow in sequence order into runs of contiguous
// bytes. Bytes already delivered (retransmissions, overlaps) are dropped; a
// gap starts a new run.
func (f *flow) stream() []chunk {
	if len(f.segs) == 0 {
		return nil
	}
	base := f.segs[0].seq
	if f.syn {
		base = f.isn + 1
	} else {
		for _, s := range f.segs {
			if seqDiff(s.seq, base) < 0 {
				base = s.seq
			}
		}
	}
	segs := append([]segment(nil), f.segs...)
	sort.SliceStable(segs, func(i, j int) bool { return seqDiff(segs[i].seq, base) < seqDiff(segs[j].seq, base) })
	out := []chunk{{cut: !f.syn}}
	var next int64     // offset from base of the next byte expected
	var curStart int64 // offset from base of the current chunk's first byte
	for _, s := range segs {
		start := seqDiff(s.seq, base)
		end := start + int64(len(s.payload))
		cur := &out[len(out)-1]
		// Bytes already delivered (a retransmission captured before or
		// after the original) are credited to the earliest frame.
		for i := max(start, curStart); i < min(end, next); i++ {
			if j := i - curStart; s.frame < cur.frames[j] {
				cur.frames[j], cur.times[j] = s.frame, s.time
			}
		}
		if end <= next {
			continue
		}
		p := s.payload
		if start > next { // gap: data missing from the capture
			out = append(out, chunk{cut: true})
			curStart = start
		} else {
			p = p[next-start:]
		}
		cur = &out[len(out)-1]
		cur.data = append(cur.data, p...)
		for range p {
			cur.frames = append(cur.frames, s.frame)
			cur.times = append(cur.times, s.time)
		}
		next = end
	}
	return out
}

// plausible reports whether b starts with an encapsulation header this
// reader can split on: a known command, options 0 and a length that fits
// what remains.
func plausible(b []byte) bool {
	if len(b) < headerSize {
		return false
	}
	switch binary.LittleEndian.Uint16(b) {
	case 0x0000, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006f, 0x0070:
	default:
		return false
	}
	n := int(binary.LittleEndian.Uint16(b[2:]))
	return binary.LittleEndian.Uint32(b[20:]) == 0 && n <= len(b)-headerSize
}

// Resync returns the offset of the first plausible encapsulation header in
// b, or -1.
func Resync(b []byte) int {
	for i := range b {
		if plausible(b[i:]) {
			return i
		}
	}
	return -1
}

// split splits a reassembled flow into encapsulation packets.
func split(c chunk, fromClient bool) (out []Message, dropped int) {
	off := 0
	if c.cut {
		i := Resync(c.data)
		if i < 0 {
			return nil, 1
		}
		if i > 0 {
			dropped++ // the tail of a packet that started before the chunk
		}
		off = i
	}
	for off < len(c.data) {
		if len(c.data)-off < headerSize {
			return out, dropped + 1
		}
		n := headerSize + int(binary.LittleEndian.Uint16(c.data[off+2:]))
		if n > len(c.data)-off {
			return out, dropped + 1 // cut by a gap or the end of the capture
		}
		last := off + n - 1
		out = append(out, Message{FromClient: fromClient, Frame: c.frames[last], Time: c.times[last], Data: c.data[off : off+n]})
		off += n
	}
	return out, dropped
}

// flowMessages runs split over every contiguous run of a flow.
func flowMessages(f *flow, fromClient bool) (out []Message, gaps, dropped int) {
	runs := f.stream()
	if len(runs) > 0 {
		gaps = len(runs) - 1
	}
	for _, r := range runs {
		m, d := split(r, fromClient)
		out, dropped = append(out, m...), dropped+d
	}
	return out, gaps, dropped
}

func (a *assembler) conversations() []Conversation {
	conns := make([]*conn, 0, len(a.conns))
	for _, c := range a.conns {
		conns = append(conns, c)
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].firstFrame < conns[j].firstFrame })
	out := make([]Conversation, 0, len(conns))
	for _, c := range conns {
		conv := Conversation{Transport: c.key.transport, Client: c.key.client, Server: c.key.server}
		if c.key.transport == UDP {
			conv.Messages = c.datagrams
		} else {
			up, g1, d1 := flowMessages(c.up, true)
			down, g2, d2 := flowMessages(c.down, false)
			conv.Gaps, conv.Dropped, conv.Messages = g1+g2, d1+d2, merge(up, down)
		}
		out = append(out, conv)
	}
	return out
}

// merge merges the messages of the two directions by completing frame,
// keeping each direction in its sequence order.
func merge(a, b []Message) []Message {
	out := make([]Message, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0].Frame <= b[0].Frame {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return append(append(out, a...), b...)
}

// Count returns how many messages of all conversations satisfy keep.
func Count(convs []Conversation, keep func(Conversation, Message) bool) int {
	n := 0
	for _, c := range convs {
		for _, m := range c.Messages {
			if keep(c, m) {
				n++
			}
		}
	}
	return n
}
