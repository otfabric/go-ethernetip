// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// The tests of this file play a hostile target against the client: a
// RegisterSession that is never answered, replies cut in the middle,
// floods of unsolicited replies, CPF items longer than the packet.

// TestHostileRegisterStall answers RegisterSession with nothing, half a
// header, or a header announcing data that never comes: Dial fails with a
// timeout within the client's timeout.
func TestHostileRegisterStall(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(p *peer, req encap.Packet)
	}{
		{"nothing", func(*peer, encap.Packet) {}},
		{"half a header", func(p *peer, req encap.Packet) {
			b, _ := encap.Packet{Header: req.Header}.Encode()
			p.sendRaw(b[:12])
		}},
		{"announced data", func(p *peer, req encap.Packet) {
			h := req.Header
			h.Session = fakeSession
			h.Length = 100
			p.sendRaw(h.AppendTo(nil))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRawTarget(t, func(p *peer, pkt encap.Packet) {
				if pkt.Command == encap.CommandRegisterSession {
					c.send(p, pkt)
				}
			})
			start := time.Now()
			_, err := Dial(ctxT(t), f.addr(), WithTimeout(200*time.Millisecond))
			if !errors.Is(err, ethernetip.ErrConnectFailed) || !errors.Is(err, ethernetip.ErrTimeout) {
				t.Fatalf("Dial = %v", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("Dial took %v", d)
			}
		})
	}
}

// TestHostileRegisterReplies answers RegisterSession with what a target
// must not: the client refuses each.
func TestHostileRegisterReplies(t *testing.T) {
	for _, c := range []struct {
		name  string
		build func(req encap.Packet) []byte
	}{
		{"session 0", func(req encap.Packet) []byte {
			b, _ := encap.Packet{Header: req.Header, Data: req.Data}.Encode()
			return b
		}},
		{"other command", func(req encap.Packet) []byte {
			h := req.Header
			h.Command, h.Session = encap.CommandSendRRData, fakeSession
			b, _ := encap.Packet{Header: h}.Encode()
			return b
		}},
		{"error status with a session", func(req encap.Packet) []byte {
			h := req.Header
			h.Session, h.Status = fakeSession, encap.StatusUnsupportedProtocol
			b, _ := encap.Packet{Header: h}.Encode()
			return b
		}},
		{"length beyond the client's maximum", func(req encap.Packet) []byte {
			h := req.Header
			h.Session, h.Length = fakeSession, 0xFFFF
			return h.AppendTo(nil)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRawTarget(t, func(p *peer, pkt encap.Packet) {
				if pkt.Command == encap.CommandRegisterSession {
					p.sendRaw(c.build(pkt))
				}
			})
			if cl, err := Dial(ctxT(t), f.addr(), WithTimeout(time.Second), WithMaxPacket(1024)); err == nil {
				_ = cl.Close()
				t.Fatal("session accepted")
			} else if !errors.Is(err, ethernetip.ErrConnectFailed) {
				t.Fatalf("Dial = %v", err)
			}
		})
	}
}

// TestHostileReplyCut sends part of a reply and closes the connection:
// the request fails with connection lost at once, not at its timeout.
func TestHostileReplyCut(t *testing.T) {
	for _, keep := range []int{1, 12, encap.HeaderSize, encap.HeaderSize + 5} {
		f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
			req := decodeRR(t, pkt)
			b, _ := cip.Response{Service: req.Service, Data: make([]byte, 40)}.Encode()
			data, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: b}}}.Encode()
			out, _ := encap.Packet{Header: pkt.Header, Data: data}.Encode()
			p.sendRaw(out[:keep])
			_ = p.conn.Close()
		})
		c := dialT(t, f.addr(), WithTimeout(5*time.Second))
		start := time.Now()
		_, err := c.Identity(ctxT(t))
		if !errors.Is(err, ethernetip.ErrConnectionLost) {
			t.Fatalf("cut after %d octets: %v", keep, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("cut after %d octets: failed after %v", keep, d)
		}
		eventually(t, 2*time.Second, "disconnected", func() bool { return c.State() == ethernetip.StateDisconnected })
	}
}

// TestHostileReplyFlood answers each request after thousands of
// unsolicited packets: replies with unknown sender contexts, other
// sessions, unknown commands, connected data for unknown connections, and
// NOPs. The client drops them all and gets its answer.
func TestHostileReplyFlood(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		var flood bytes.Buffer
		for i := range 2000 {
			h := pkt.Header
			var data []byte
			switch i % 5 {
			case 0:
				binary.LittleEndian.PutUint64(h.Context[:], rng.Uint64())
			case 1:
				h.Session = rng.Uint32()
			case 2:
				h.Command = encap.Command(0x1000 + rng.Intn(100))
				binary.LittleEndian.PutUint64(h.Context[:], rng.Uint64())
			case 3:
				h.Command = encap.CommandSendUnitData
				data, _ = encap.RRData{Items: []encap.Item{encap.ConnectedAddress(rng.Uint32()), {Type: encap.ItemConnectedData, Data: []byte{1, 0, 0x8E, 0, 0, 0}}}}.Encode()
			default:
				h.Command = encap.CommandNOP
				data = make([]byte, rng.Intn(100))
			}
			b, _ := encap.Packet{Header: h, Data: data}.Encode()
			flood.Write(b)
		}
		p.sendRaw(flood.Bytes())
		req := decodeRR(t, pkt)
		rrReply(t, p, pkt, cip.Response{Service: req.Service, Data: []byte{7, 0}})
	})
	c := dialT(t, f.addr())
	for i := range 5 {
		b, err := c.GetAttributeSingle(ctxT(t), cip.ClassIdentity, 1, 1)
		if err != nil || !bytes.Equal(b, []byte{7, 0}) {
			t.Fatalf("request %d after the flood: %x %v", i, b, err)
		}
	}
}

// TestHostileCPFLengths answers with CPF items whose lengths disagree with
// the packet: each is a protocol error and the session survives.
func TestHostileCPFLengths(t *testing.T) {
	resp, _ := cip.Response{Service: cip.ServiceGetAttributesAll, Data: make([]byte, 30)}.Encode()
	item := func(typ encap.ItemType, length int, data []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(typ))
		b = binary.LittleEndian.AppendUint16(b, uint16(length))
		return append(b, data...)
	}
	rr := func(count int, items ...[]byte) []byte {
		b := binary.LittleEndian.AppendUint16(make([]byte, 6), uint16(count))
		for _, it := range items {
			b = append(b, it...)
		}
		return b
	}
	null := item(encap.ItemNullAddress, 0, nil)
	for _, data := range [][]byte{
		rr(2, null, item(encap.ItemUnconnectedData, 0xFFFF, resp)),
		rr(2, null, item(encap.ItemUnconnectedData, len(resp)+1, resp)),
		rr(0xFFFF, null, item(encap.ItemUnconnectedData, len(resp), resp)),
		rr(3, null, item(encap.ItemUnconnectedData, len(resp), resp)),
		append(rr(2, null, item(encap.ItemUnconnectedData, len(resp), resp)), 0xEE),
		rr(2, null, item(encap.ItemUnconnectedData, 0, nil)),
		rr(2, null, item(encap.ItemUnconnectedData, 1, []byte{0x81})),
	} {
		f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
			p.send(t, encap.Packet{Header: pkt.Header, Data: data})
		})
		c := dialT(t, f.addr())
		if _, err := c.GetAttributesAll(ctxT(t), cip.ClassIdentity, 1); !errors.Is(err, ethernetip.ErrProtocol) {
			t.Fatalf("CPF % X: %v", data, err)
		}
		if c.State() != ethernetip.StateConnected {
			t.Fatal("a malformed reply ended the session")
		}
	}
}

// TestHostileListIdentityUDP answers a unicast ListIdentity over UDP with
// garbage, an oversize datagram, a reply with an identity item of absurd
// lengths and a wrong context before the real reply: the real one is
// returned.
func TestHostileListIdentityUDP(t *testing.T) {
	addr := udpResponder(t, func(req encap.Packet) [][]byte {
		huge, _ := encap.Packet{Header: req.Header, Data: make([]byte, 9000)}.Encode()
		badItem := req.Header
		cpf := binary.LittleEndian.AppendUint16(nil, 1)
		cpf = binary.LittleEndian.AppendUint16(cpf, uint16(encap.ItemListIdentity))
		cpf = binary.LittleEndian.AppendUint16(cpf, 0xFFFF)
		cpf = append(cpf, make([]byte, 40)...)
		bad, _ := encap.Packet{Header: badItem, Data: cpf}.Encode()
		zeroItem := binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, 0xFFFF), uint16(encap.ItemListIdentity)), 0)
		many, _ := encap.Packet{Header: req.Header, Data: zeroItem}.Encode()
		wrong := req.Header
		wrong.Context[0] ^= 0xFF
		return [][]byte{
			nil,
			bytes.Repeat([]byte{0xFF}, 1499),
			huge,
			bad,
			many,
			identityReply(t, wrong, "wrong context"),
			identityReply(t, req.Header, "real"),
		}
	})
	d, err := ListIdentity(ctxT(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	if d.Identity.ProductName != "real" {
		t.Fatalf("identity %q", d.Identity.ProductName)
	}
}

// hostileUDPSink is a UDP socket nobody answers on.
func hostileUDPSink(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.LocalAddr().String()
}

// TestHostileListIdentitySilent: a device that never answers makes
// ListIdentity time out with the context.
func TestHostileListIdentitySilent(t *testing.T) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := ListIdentity(ctx, hostileUDPSink(t))
	if !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("silent device: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}
