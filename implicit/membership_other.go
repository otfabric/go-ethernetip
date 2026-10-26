// SPDX-License-Identifier: MIT

//go:build !unix && !windows

package implicit

import (
	"fmt"
	"net"
	"net/netip"

	ethernetip "github.com/otfabric/go-ethernetip"
)

// membership is not available on this platform.
func membership(*net.UDPConn, netip.Addr, netip.Addr, bool) error {
	return fmt.Errorf("%w: multicast membership on this platform", ethernetip.ErrUnsupported)
}

// multicastInterface is not available on this platform.
func multicastInterface(*net.UDPConn, netip.Addr) error {
	return fmt.Errorf("%w: multicast interface on this platform", ethernetip.ErrUnsupported)
}
