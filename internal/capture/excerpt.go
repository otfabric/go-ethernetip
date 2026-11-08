// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// An Excerpt holds the EtherNet/IP messages of a recording whose raw file
// this repository does not redistribute: only the encapsulation messages
// (and I/O datagrams) a golden case needs, without the link, IP and TCP
// headers. It names the raw file (source, original name, SHA256) so that
// `make captures-extended` can check it against the original.
type Excerpt struct {
	// Source is the manifest ID of the source; File the original file name.
	Source string `json:"source"`
	File   string `json:"file"`
	// SHA256 is the checksum of the raw file the excerpt was taken from.
	SHA256 string `json:"sha256"`
	// Note says what was kept and why the raw file is not here.
	Note          string                `json:"note"`
	Conversations []ExcerptConversation `json:"conversations"`
}

// ExcerptConversation is the excerpt of one conversation.
type ExcerptConversation struct {
	Transport Transport        `json:"transport"`
	Client    string           `json:"client"`
	Server    string           `json:"server"`
	Gaps      int              `json:"gaps,omitempty"`
	Dropped   int              `json:"dropped,omitempty"`
	Messages  []ExcerptMessage `json:"messages"`
}

// ExcerptMessage is one message: its frame, time, direction and bytes.
type ExcerptMessage struct {
	Frame      int       `json:"frame"`
	Time       time.Time `json:"time"`
	FromClient bool      `json:"fromClient"`
	Data       string    `json:"data"` // hex
}

// ToConversations returns the excerpt as conversations, as Read returns them
// for a raw file.
func (e Excerpt) ToConversations() ([]Conversation, error) {
	out := make([]Conversation, 0, len(e.Conversations))
	for _, c := range e.Conversations {
		conv := Conversation{Transport: c.Transport, Client: c.Client, Server: c.Server, Gaps: c.Gaps, Dropped: c.Dropped}
		for _, m := range c.Messages {
			b, err := hex.DecodeString(m.Data)
			if err != nil {
				return nil, fmt.Errorf("capture: excerpt %s frame %d: %w", e.File, m.Frame, err)
			}
			conv.Messages = append(conv.Messages, Message{FromClient: m.FromClient, Frame: m.Frame, Time: m.Time, Data: b})
		}
		out = append(out, conv)
	}
	return out, nil
}

// ReadExcerpt reads an excerpt file.
func ReadExcerpt(path string) (Excerpt, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return Excerpt{}, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return Excerpt{}, err
	}
	var e Excerpt
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Excerpt{}, fmt.Errorf("capture: excerpt %s: %w", path, err)
	}
	if e.Source == "" || e.File == "" || len(e.SHA256) != 64 {
		return Excerpt{}, fmt.Errorf("capture: excerpt %s: %w", path, errExcerpt)
	}
	return e, nil
}

var errExcerpt = errors.New("source, file or sha256 missing")

// Excerpts keeps, of the conversations of a raw file, every message that
// is not a repetition: a request whose encapsulation data (after the CIP
// sequence count of a connected request) equals an earlier request's in
// the same conversation, with a reply equal to that earlier reply, is
// dropped together with its reply. Discovery and session commands are
// always kept. maxPerKind > 0 also bounds the exchanges kept per request
// shape (service and path, ignoring the data), which keeps excerpts of
// long cyclic recordings small.
func Excerpts(convs []Conversation, maxPerKind int) []ExcerptConversation {
	var out []ExcerptConversation
	for _, c := range convs {
		ec := ExcerptConversation{Transport: c.Transport, Client: c.Client, Server: c.Server, Gaps: c.Gaps, Dropped: c.Dropped}
		keep := func(m Message) {
			ec.Messages = append(ec.Messages, ExcerptMessage{Frame: m.Frame, Time: m.Time, FromClient: m.FromClient, Data: hex.EncodeToString(m.Data)})
		}
		if c.Transport == UDP {
			seen := map[string]int{}
			for _, m := range c.Messages {
				k := udpKind(c, m)
				if maxPerKind > 0 && seen[k] >= maxPerKind {
					continue
				}
				seen[k]++
				keep(m)
			}
			out = append(out, ec)
			continue
		}
		ex, orphans := Exchanges(c)
		seen := map[string]bool{}
		kinds := map[string]int{}
		var msgs []Message
		for _, e := range ex {
			k, kind, cyclic := exchangeKey(e)
			if cyclic {
				if seen[k] || (maxPerKind > 0 && kinds[kind] >= maxPerKind) {
					continue
				}
				seen[k] = true
				kinds[kind]++
			}
			msgs = append(msgs, e.Request)
			if e.Reply != nil {
				msgs = append(msgs, *e.Reply)
			}
		}
		msgs = append(msgs, orphans...)
		sortMessages(msgs)
		for _, m := range msgs {
			keep(m)
		}
		out = append(out, ec)
	}
	return out
}

func udpKind(c Conversation, m Message) string {
	// One kind per producer and connection ID (the first 10 octets of an
	// I/O CPF hold the item count and the sequenced address item's type,
	// length and connection ID).
	k := fmt.Sprint(m.FromClient)
	if len(m.Data) >= 10 {
		k += hex.EncodeToString(m.Data[6:10])
	}
	return c.Client + k
}

// exchangeKey returns the deduplication key of an exchange, its request
// shape, and whether it may be deduplicated at all (SendRRData and
// SendUnitData only).
func exchangeKey(e Exchange) (key, kind string, cyclic bool) {
	h, err := ParseHeader(e.Request.Data)
	if err != nil || (h.Command != cmdSendRRData && h.Command != cmdSendUnitData) {
		return "", "", false
	}
	q, err := ParseExplicit(e.Request.Data)
	if err != nil {
		return "", "", false
	}
	key = hex.EncodeToString(q.CIP)
	kind = requestShape(q.CIP)
	if e.Reply != nil {
		r, err := ParseExplicit(e.Reply.Data)
		if err != nil {
			return "", "", false
		}
		key += "/" + hex.EncodeToString(r.CIP)
	}
	return key, kind, true
}

// requestShape is the service and path of a request; for a Multiple
// Service Packet (0x0A) it is followed by those of each embedded request.
func requestShape(b []byte) string {
	shape := requestHeader(b)
	if len(b) < 2 || b[0] != 0x0a {
		return shape
	}
	data := b[min(2+2*int(b[1]), len(b)):]
	if len(data) < 2 {
		return shape
	}
	count := int(binary.LittleEndian.Uint16(data))
	for i := 0; i < count && 4+2*i <= len(data); i++ {
		if off := int(binary.LittleEndian.Uint16(data[2+2*i:])); off < len(data) {
			shape += "+" + requestHeader(data[off:])
		}
	}
	return shape
}

// requestHeader is the hex of a request's service and path.
func requestHeader(b []byte) string {
	if len(b) < 2 {
		return "?"
	}
	return hex.EncodeToString(b[:min(2+2*int(b[1]), len(b))])
}

// sortMessages orders messages by frame, keeping the order of messages
// completed by the same frame.
func sortMessages(m []Message) {
	sort.SliceStable(m, func(i, j int) bool { return m[i].Frame < m[j].Frame })
}
