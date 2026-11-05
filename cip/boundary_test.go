// SPDX-License-Identifier: MIT

package cip_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
)

// TestEncodeLengthBoundaries checks every length that an encoder writes in
// an 8- or 16-bit field: the largest value that fits encodes, one more is
// rejected instead of wrapping.
func TestEncodeLengthBoundaries(t *testing.T) {
	path := func(n int) cip.Path { return cip.Path{cip.DataSegment{Data: make([]byte, n)}} }
	enc := func(e interface{ Encode() ([]byte, error) }) error { _, err := e.Encode(); return err }
	// A request whose encoding is 2 octets of header, 4 of path and n of
	// data.
	req := func(n int) cip.Request {
		return cip.Request{Service: 0x10, Path: cip.MessageRouterPath(), Data: make([]byte, n)}
	}
	cases := []struct {
		name     string
		fits     error
		overflow error
		want     error
	}{
		{"port link",
			enc(cip.Path{cip.PortSegment{Port: 1, Link: make([]byte, 255)}}),
			enc(cip.Path{cip.PortSegment{Port: 1, Link: make([]byte, 256)}}), cip.ErrMalformed},
		{"symbol",
			enc(cip.Path{cip.SymbolSegment{Name: strings.Repeat("a", 255)}}),
			enc(cip.Path{cip.SymbolSegment{Name: strings.Repeat("a", 256)}}), cip.ErrMalformed},
		{"data segment", enc(path(510)), enc(path(512)), cip.ErrMalformed},
		{"network segment",
			enc(cip.Path{cip.NetworkSegment{Subtype: 0x10, Data: make([]byte, 510)}}),
			enc(cip.Path{cip.NetworkSegment{Subtype: 0x10, Data: make([]byte, 512)}}), cip.ErrMalformed},
		{"response extended status",
			enc(cip.Response{Extended: make([]uint16, 255)}),
			enc(cip.Response{Extended: make([]uint16, 256)}), cip.ErrTooLarge},
		{"forward open reply",
			enc(cip.ForwardOpenReply{AppReply: make([]byte, 510)}),
			enc(cip.ForwardOpenReply{AppReply: make([]byte, 512)}), cip.ErrMalformed},
		{"forward close reply",
			enc(cip.ForwardCloseReply{AppReply: make([]byte, 510)}),
			enc(cip.ForwardCloseReply{AppReply: make([]byte, 512)}), cip.ErrMalformed},
		{"forward open path",
			enc(cip.ForwardOpen{Path: path(508)}),
			enc(cip.ForwardOpen{Path: path(510)}), cip.ErrTooLarge},
		{"forward close path",
			enc(cip.ForwardClose{Path: path(508)}),
			enc(cip.ForwardClose{Path: path(510)}), cip.ErrTooLarge},
		{"unconnected send message",
			enc(cip.UnconnectedSend{Request: req(65529), Route: cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}}}),
			enc(cip.UnconnectedSend{Request: req(65530), Route: cip.Path{cip.PortSegment{Port: 1, Link: []byte{0}}}}), cip.ErrTooLarge},
		{"unconnected send route",
			enc(cip.UnconnectedSend{Request: req(0), Route: path(508)}),
			enc(cip.UnconnectedSend{Request: req(0), Route: path(510)}), cip.ErrTooLarge},
	}
	for _, c := range cases {
		if c.fits != nil {
			t.Errorf("%s: largest value: %v", c.name, c.fits)
		}
		if !errors.Is(c.overflow, c.want) {
			t.Errorf("%s: one more: %v, want %v", c.name, c.overflow, c.want)
		}
	}
}

func TestDecodeNetworkParams32Size(t *testing.T) {
	if p := cip.DecodeNetworkParams32(0x4201FFFF); p.Size != 0xFFFF {
		t.Errorf("Size = %d, want 65535", p.Size)
	}
	if p := cip.DecodeNetworkParams32(0x42010000); p.Size != 0 {
		t.Errorf("Size = %d, want 0", p.Size)
	}
}

func TestEncodeMultipleServiceResponseCount(t *testing.T) {
	if _, err := cip.EncodeMultipleServiceResponse(make([]cip.Response, 65536)); !errors.Is(err, cip.ErrTooLarge) {
		t.Errorf("65536 responses: %v", err)
	}
}
