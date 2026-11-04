// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// pipeDialer connects the client to serve over an in-memory connection.
type pipeDialer struct {
	serve func(c net.Conn)
}

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	near, far := net.Pipe()
	go d.serve(far)
	return near, nil
}

// FuzzClientReply plays a target that registers the session and answers
// the first request with fuzzed octets: as the data of a reply with the
// request's header (framed) or as the raw stream. The client must not
// panic, must return from the request without waiting for its timeout
// once the target closes the connection, and must close cleanly.
func FuzzClientReply(f *testing.F) {
	resp := func(r cip.Response, extra ...encap.Item) []byte {
		b, _ := r.Encode()
		items := append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: b}}, extra...)
		d, _ := encap.RRData{Items: items}.Encode()
		return d
	}
	id := cip.Identity{VendorID: 1, ProductName: "x"}
	idb, _ := id.AppendAttributes(nil)
	f.Add(resp(cip.Response{Service: cip.ServiceGetAttributesAll, Data: idb}), true, uint8(0))
	f.Add(resp(cip.Response{Service: cip.ServiceGetAttributesAll, Status: cip.StatusPartialTransfer, Data: idb}), true, uint8(0))
	msp, _ := cip.EncodeMultipleServiceResponse([]cip.Response{{Service: cip.ServiceGetAttributesAll, Data: idb}, {Service: cip.ServiceGetAttributeSingle, Data: []byte{1, 0}}})
	f.Add(resp(cip.Response{Service: cip.ServiceMultipleServicePacket, Data: msp}), true, uint8(1))
	f.Add(resp(cip.Response{Service: cip.ServiceGetAttributeList, Data: []byte{2, 0, 1, 0, 0, 0, 1, 0, 2, 0, 0, 0, 2, 0}}), true, uint8(2))
	f.Add(resp(cip.Response{Service: cip.ServiceGetAttributesAll}, encap.Item{Type: encap.ItemSockaddrTO, Data: make([]byte, 16)}), true, uint8(0))
	f.Add([]byte{0x6F, 0, 0xFF, 0xFF}, false, uint8(0))
	f.Add(make([]byte, 30), false, uint8(3))

	f.Fuzz(func(t *testing.T, in []byte, framed bool, op uint8) {
		if len(in) > 1<<16 {
			return
		}
		serve := func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			reg, _, err := encap.ReadPacket(c, nil, 0)
			if err != nil {
				return
			}
			h := reg.Header
			h.Session = fakeSession
			b, _ := encap.Packet{Header: h, Data: reg.Data}.Encode()
			if _, err := c.Write(b); err != nil {
				return
			}
			req, _, err := encap.ReadPacket(c, nil, 0)
			if err != nil {
				return
			}
			out := in
			if framed {
				h := req.Header
				h.Length = uint16(min(len(in), 0xFFFF))
				out = append(h.AppendTo(nil), in...)
			}
			_, _ = c.Write(out)
			// Then the target goes: a reply that did not complete or
			// match ends with the connection, not at the request's
			// deadline.
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := Dial(ctx, "fuzz:44818", WithDialer(pipeDialer{serve: serve}), WithTimeout(2*time.Second), WithMaxPacket(1<<16-1))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			rctx, rcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer rcancel()
			switch op % 4 {
			case 0:
				_, _ = c.Identity(rctx)
			case 1:
				_, _ = c.MultipleService(rctx, []cip.Request{
					{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)},
					{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
				})
			case 2:
				_, _ = c.GetAttributeList(rctx, cip.ClassIdentity, 1, []uint16{1, 2}, []int{2, 0})
			default:
				_, _ = c.ListIdentity(rctx)
			}
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("request did not return within 3 s of a 300 ms deadline")
		}
		closed := make(chan struct{})
		go func() { _ = c.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not return")
		}
	})
}
