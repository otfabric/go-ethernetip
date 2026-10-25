// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
)

// Option configures a [Server].
type Option func(*options) error

// Interface describes the network interface the TCP/IP Interface and
// Ethernet Link objects report. It does not change how the server listens.
type Interface struct {
	IP         netip.Addr
	Mask       netip.Addr
	Gateway    netip.Addr
	NameServer netip.Addr
	DomainName string
	HostName   string
	MAC        [6]byte
	// SpeedMbps is the interface speed; zero means 100.
	SpeedMbps uint32
}

type options struct {
	identity          cip.Identity
	logger            ethernetip.Logger
	metrics           ethernetip.Metrics
	tls               *tls.Config
	maxSessions       int
	maxConnections    int
	maxPacket         int
	inactivity        time.Duration
	ioAddr            string
	slot              int
	iface             Interface
	minRPI, maxRPI    time.Duration
	discoveryDelayMax time.Duration
	runIdleOT         bool
	runIdleTO         bool
	onReset           func(resetType uint8) cip.GeneralStatus
}

// DefaultIdentity is the identity of a server built without WithIdentity:
// an unregistered vendor (0xFFFF), a communications adapter.
var DefaultIdentity = cip.Identity{
	VendorID:     0xFFFF,
	DeviceType:   cip.DeviceTypeCommunicationsAdapter,
	ProductCode:  1,
	Revision:     cip.Revision{Major: 1, Minor: 1},
	SerialNumber: 1,
	ProductName:  "OT Fabric EtherNet/IP adapter",
	State:        3,
}

func defaultOptions() options {
	return options{
		identity:       DefaultIdentity,
		maxSessions:    64,
		maxConnections: 128,
		maxPacket:      4096,
		inactivity:     120 * time.Second,
		slot:           0,
		minRPI:         time.Millisecond,
		maxRPI:         time.Hour,
		runIdleOT:      true,
	}
}

func invalidOption(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ethernetip.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithIdentity sets the identity the Identity object and ListIdentity
// report. The product name is at most 32 characters; State 0 is reported
// as 3 (operational).
func WithIdentity(id cip.Identity) Option {
	return func(o *options) error {
		if len(id.ProductName) > 32 {
			return invalidOption("product name of %d characters (at most 32)", len(id.ProductName))
		}
		if id.State == 0 {
			id.State = 3
		}
		o.identity = id
		return nil
	}
}

// WithLogger sets the logger. Logging is silent by default.
func WithLogger(l ethernetip.Logger) Option {
	return func(o *options) error { o.logger = l; return nil }
}

// WithMetrics sets the metrics callbacks; a value that also implements
// [ethernetip.ServerMetrics] or [ethernetip.IOMetrics] receives those
// events too.
func WithMetrics(m ethernetip.Metrics) Option {
	return func(o *options) error { o.metrics = m; return nil }
}

// WithTLS serves EtherNet/IP over TLS, the CIP Security transport of
// explicit messages (port 2221). The configuration is used as given;
// require client certificates with ClientAuth.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) error {
		if cfg == nil {
			return invalidOption("nil TLS configuration")
		}
		o.tls = cfg
		return nil
	}
}

// WithMaxSessions limits the registered sessions; RegisterSession beyond
// it is refused with insufficient memory. Default 64.
func WithMaxSessions(n int) Option {
	return func(o *options) error {
		if n < 1 {
			return invalidOption("max sessions %d", n)
		}
		o.maxSessions = n
		return nil
	}
}

// WithMaxConnections limits the open CIP connections (Class 0, 1 and 3);
// Forward_Open beyond it is refused with 0x01/0x0113. Default 128.
func WithMaxConnections(n int) Option {
	return func(o *options) error {
		if n < 1 {
			return invalidOption("max connections %d", n)
		}
		o.maxConnections = n
		return nil
	}
}

// WithMaxPacket sets the largest encapsulation data length accepted; a
// session that sends a larger packet is closed. Default 4096, at most
// 65535.
func WithMaxPacket(n int) Option {
	return func(o *options) error {
		if n < 512 || n > 65535 {
			return invalidOption("max packet %d", n)
		}
		o.maxPacket = n
		return nil
	}
}

// WithInactivityTimeout closes a TCP connection that sends nothing for d
// (the encapsulation inactivity timeout, TCP/IP Interface attribute 13).
// Zero disables it. Default 120 seconds.
func WithInactivityTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d < 0 || d > 3600*time.Second {
			return invalidOption("inactivity timeout %v", d)
		}
		o.inactivity = d
		return nil
	}
}

// WithIOAddress sets the UDP address of implicit messaging; the default is
// port 2222 on the host of the explicit address. ":0" picks a free port,
// which the server then announces in a Sockaddr Info item of its
// Forward_Open replies.
func WithIOAddress(addr string) Option {
	return func(o *options) error {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return invalidOption("I/O address %q: %v", addr, err)
		}
		o.ioAddr = addr
		return nil
	}
}

// WithSlot sets the backplane slot the server answers as: Unconnected_Send
// routes and connection paths that address port 1 with this link are
// local. Default 0.
func WithSlot(slot int) Option {
	return func(o *options) error {
		if slot < 0 || slot > 255 {
			return invalidOption("slot %d", slot)
		}
		o.slot = slot
		return nil
	}
}

// WithInterface sets what the TCP/IP Interface and Ethernet Link objects
// report, and the address in ListIdentity replies.
func WithInterface(i Interface) Option {
	return func(o *options) error {
		if i.IP.IsValid() && !i.IP.Is4() {
			return invalidOption("interface address %s is not IPv4", i.IP)
		}
		if len(i.HostName) > 64 || len(i.DomainName) > 48 {
			return invalidOption("host or domain name too long")
		}
		o.iface = i
		return nil
	}
}

// WithRPIRange sets the requested packet intervals Forward_Open accepts;
// others are refused with 0x01/0x0112. Default 1 ms to 1 hour.
func WithRPIRange(min, max time.Duration) Option {
	return func(o *options) error {
		if min <= 0 || max < min {
			return invalidOption("RPI range %v..%v", min, max)
		}
		o.minRPI, o.maxRPI = min, max
		return nil
	}
}

// WithDiscoveryDelay bounds the random delay before answering a
// ListIdentity received over UDP, which the request may ask for in its
// sender context. Zero (the default) answers immediately.
func WithDiscoveryDelay(max time.Duration) Option {
	return func(o *options) error {
		if max < 0 || max > 2*time.Second {
			return invalidOption("discovery delay %v", max)
		}
		o.discoveryDelayMax = max
		return nil
	}
}

// WithRunIdleHeader sets the real-time formats of I/O connections: whether
// consumed (O->T) data carries the 32-bit run/idle header (default true)
// and whether produced (T->O) data does (default false).
func WithRunIdleHeader(consumed, produced bool) Option {
	return func(o *options) error {
		o.runIdleOT, o.runIdleTO = consumed, produced
		return nil
	}
}

// WithResetHandler sets the function the Identity object's Reset service
// calls with the reset type (0: emulate a power cycle, 1: return to
// factory defaults). It returns the status of the reply; without a
// handler Reset answers success and does nothing.
func WithResetHandler(f func(resetType uint8) cip.GeneralStatus) Option {
	return func(o *options) error { o.onReset = f; return nil }
}
