// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// multicastAddresses is the number of multicast addresses the server
// allocates from its base (TCP/IP Interface attribute 9).
const multicastAddresses = 32

var netipZero = netip.IPv4Unspecified()

func validOr0(a netip.Addr) netip.Addr {
	if a.IsValid() && a.Is4() {
		return a
	}
	return netipZero
}

func secondsDuration(v uint16) time.Duration { return time.Duration(v) * time.Second }

// multicastBase returns the first multicast address of the server, by the
// CIP default allocation: 239.192.1.0 plus 32 addresses for each host ID
// below the server's (host ID = address & ^mask, mask /24 by default).
func (s *Server) multicastBase() netip.Addr {
	ip := s.localIP(s.Addr()).As4()
	mask := [4]byte{255, 255, 255, 0}
	if m := s.opts.iface.Mask; m.IsValid() && m.Is4() {
		mask = m.As4()
	}
	host := binary.BigEndian.Uint32(ip[:]) &^ binary.BigEndian.Uint32(mask[:])
	idx := (host - 1) & 0x3FF
	var base [4]byte
	binary.BigEndian.PutUint32(base[:], 0xEFC00100+idx*multicastAddresses)
	return netip.AddrFrom4(base)
}

// multicastGroup returns the n-th multicast address of the server.
func (s *Server) multicastGroup(n int) netip.Addr {
	b := s.multicastBase().As4()
	v := binary.BigEndian.Uint32(b[:]) + uint32(n%multicastAddresses)
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
