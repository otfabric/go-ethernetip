// SPDX-License-Identifier: MIT

//go:build unix

package implicit

import (
	"net"
	"net/netip"
	"syscall"
)

// membership joins (or leaves) group on the socket of c.
func membership(c *net.UDPConn, group, ifaddr netip.Addr, join bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	mreq := &syscall.IPMreq{Multiaddr: group.As4(), Interface: ifaddr.As4()}
	opt := syscall.IP_ADD_MEMBERSHIP
	if !join {
		opt = syscall.IP_DROP_MEMBERSHIP
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, opt, mreq)
	}); err != nil {
		return err
	}
	return serr
}
