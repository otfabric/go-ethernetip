// SPDX-License-Identifier: MIT

package capture

import (
	"encoding/binary"
	"errors"
)

// Encapsulation commands the pairing distinguishes.
const (
	cmdSendRRData   = 0x006f
	cmdSendUnitData = 0x0070
	itemConnAddr    = 0x00a1
	itemConnData    = 0x00b1
	itemUnconnData  = 0x00b2
)

// Header is the encapsulation header of a message, read independently of
// the encap package under test.
type Header struct {
	Command uint16
	Length  uint16
	Session uint32
	Status  uint32
	Context [8]byte
	Options uint32
}

// ParseHeader reads the header of an encapsulation message.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerSize {
		return Header{}, errShort
	}
	h := Header{
		Command: binary.LittleEndian.Uint16(b),
		Length:  binary.LittleEndian.Uint16(b[2:]),
		Session: binary.LittleEndian.Uint32(b[4:]),
		Status:  binary.LittleEndian.Uint32(b[8:]),
		Options: binary.LittleEndian.Uint32(b[20:]),
	}
	copy(h.Context[:], b[12:20])
	return h, nil
}

var errShort = errors.New("capture: message too short")

// item is one common packet format item.
type item struct {
	typ  uint16
	data []byte
}

// items reads the common packet format of SendRRData and SendUnitData:
// interface handle (4), timeout (2), item count and the items. It also
// returns where each item's data starts in data.
func items(data []byte) ([]item, []int, error) {
	if len(data) < 8 {
		return nil, nil, errShort
	}
	n := int(binary.LittleEndian.Uint16(data[6:]))
	off := 8
	out := make([]item, 0, n)
	var offs []int
	for range n {
		b := data[off:]
		if len(b) < 4 {
			return nil, nil, errShort
		}
		l := int(binary.LittleEndian.Uint16(b[2:]))
		if l > len(b)-4 {
			return nil, nil, errShort
		}
		out = append(out, item{binary.LittleEndian.Uint16(b), b[4 : 4+l]})
		offs = append(offs, off+4)
		off += 4 + l
	}
	return out, offs, nil
}

// Explicit is the CIP content of a SendRRData or SendUnitData message.
type Explicit struct {
	Connected bool
	ConnID    uint32 // connected address item (connected only)
	Sequence  uint16 // CIP sequence count (connected only)
	CIP       []byte // the Message Router request or response
	// Offset is where CIP starts in the message.
	Offset int
}

// ParseExplicit reads the CIP content of a SendRRData or SendUnitData
// message.
func ParseExplicit(m []byte) (Explicit, error) {
	h, err := ParseHeader(m)
	if err != nil {
		return Explicit{}, err
	}
	if h.Command != cmdSendRRData && h.Command != cmdSendUnitData {
		return Explicit{}, errors.New("capture: not SendRRData or SendUnitData")
	}
	if int(h.Length) != len(m)-headerSize {
		return Explicit{}, errShort
	}
	its, offs, err := items(m[headerSize:])
	if err != nil {
		return Explicit{}, err
	}
	var e Explicit
	found := false
	for i, it := range its {
		switch it.typ {
		case itemConnAddr:
			if len(it.data) != 4 {
				return Explicit{}, errShort
			}
			e.ConnID = binary.LittleEndian.Uint32(it.data)
		case itemConnData:
			if len(it.data) < 2 {
				return Explicit{}, errShort
			}
			e.Connected, e.Sequence, e.CIP, found = true, binary.LittleEndian.Uint16(it.data), it.data[2:], true
			e.Offset = headerSize + offs[i] + 2
		case itemUnconnData:
			e.CIP, found = it.data, true
			e.Offset = headerSize + offs[i]
		}
	}
	if !found {
		return Explicit{}, errors.New("capture: no data item")
	}
	return e, nil
}

// Exchange is a request and the reply that answers it.
type Exchange struct {
	Request Message
	// Reply is nil when the capture holds no reply.
	Reply *Message
}

// Exchanges pairs the requests of a TCP conversation with their replies.
// A SendRRData (and every other command with a reply) is answered by the
// next reply of the same command with the same sender context; a
// SendUnitData by the next reply carrying the same CIP sequence count. The
// second result holds replies that answer no captured request (the
// capture started after the request was sent).
func Exchanges(c Conversation) (out []Exchange, orphans []Message) {
	type key struct {
		cmd uint16
		ctx [8]byte
		seq uint16
	}
	pending := map[key][]int{}
	keyOf := func(m Message) (key, bool) {
		h, err := ParseHeader(m.Data)
		if err != nil {
			return key{}, false
		}
		k := key{cmd: h.Command}
		if h.Command == cmdSendUnitData {
			e, err := ParseExplicit(m.Data)
			if err != nil || !e.Connected {
				return key{}, false
			}
			k.seq = e.Sequence
		} else {
			k.ctx = h.Context
		}
		return k, true
	}
	for _, m := range c.Messages {
		k, ok := keyOf(m)
		if m.FromClient {
			if !ok {
				out = append(out, Exchange{Request: m})
				continue
			}
			pending[k] = append(pending[k], len(out))
			out = append(out, Exchange{Request: m})
			continue
		}
		q := pending[k]
		if !ok || len(q) == 0 {
			orphans = append(orphans, m)
			continue
		}
		r := m
		out[q[0]].Reply = &r
		pending[k] = q[1:]
	}
	return out, orphans
}
