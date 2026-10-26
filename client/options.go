// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
)

// Option configures a [Client].
type Option func(*options) error

// Dialer opens TCP connections; *net.Dialer satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type options struct {
	logger      ethernetip.Logger
	metrics     ethernetip.Metrics
	dialer      Dialer
	tls         *tls.Config
	timeout     time.Duration
	route       cip.Path
	maxPending  int
	maxPacket   int
	reconnect   bool
	vendorID    uint16
	origSerial  uint32
	stateChange func(ethernetip.State, error)
}

func defaultOptions() options {
	return options{
		dialer:     &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		timeout:    5 * time.Second,
		maxPending: 1,
		maxPacket:  65535,
		vendorID:   DefaultVendorID,
	}
}

// DefaultVendorID is the originator vendor ID the client puts in
// Forward_Open requests unless WithOriginator sets another. No ODVA vendor
// ID is assigned to this library: 0xFFFF marks the originator as
// unregistered. Products should use their own vendor ID.
const DefaultVendorID uint16 = 0xFFFF

func invalidOption(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ethernetip.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithLogger sets the logger. Logging is silent by default.
func WithLogger(l ethernetip.Logger) Option {
	return func(o *options) error { o.logger = l; return nil }
}

// WithMetrics sets the metrics callbacks; a value that also implements
// [ethernetip.RequestMetrics] receives every request.
func WithMetrics(m ethernetip.Metrics) Option {
	return func(o *options) error { o.metrics = m; return nil }
}

// WithDialer sets the dialer of the TCP connection.
func WithDialer(d Dialer) Option {
	return func(o *options) error {
		if d == nil {
			return invalidOption("nil dialer")
		}
		o.dialer = d
		return nil
	}
}

// WithTLS runs the session over TLS: EtherNet/IP over TLS as CIP Security
// defines the transport (port 2221 by default). The configuration is used
// as given; set ServerName or RootCAs to verify the target.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) error {
		if cfg == nil {
			return invalidOption("nil TLS configuration")
		}
		o.tls = cfg
		return nil
	}
}

// WithTimeout sets the time a request may take when its context has no
// earlier deadline: the wait for the reply, and for Connect the dial and
// RegisterSession. Default 5 seconds.
func WithTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalidOption("timeout %v", d)
		}
		o.timeout = d
		return nil
	}
}

// WithRoute routes every unconnected request through the target's
// Connection Manager with Unconnected_Send along route, and prefixes the
// connection path of every Forward_Open with it: for example
// cip.ParseRoute("1/0") reaches the controller in slot 0 of a ControlLogix
// chassis through its EtherNet/IP module.
func WithRoute(route cip.Path) Option {
	return func(o *options) error {
		for _, s := range route {
			if _, ok := s.(cip.PortSegment); !ok {
				return invalidOption("route segment %v is not a port segment", s)
			}
		}
		o.route = route
		return nil
	}
}

// WithMaxPending sets how many unconnected requests may be outstanding on
// the session at once. Further requests wait for their turn. The default, 1,
// suits every target; targets that process requests concurrently answer
// faster with more.
func WithMaxPending(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 1024 {
			return invalidOption("max pending %d", n)
		}
		o.maxPending = n
		return nil
	}
}

// WithMaxPacket sets the largest encapsulation data length the client
// accepts from the target; a larger packet closes the session. Default and
// maximum 65535.
func WithMaxPacket(n int) Option {
	return func(o *options) error {
		if n < 64 || n > 65535 {
			return invalidOption("max packet %d", n)
		}
		o.maxPacket = n
		return nil
	}
}

// WithAutoReconnect makes a request on a client whose session was lost
// reconnect first, instead of failing with ErrNotConnected. Connected
// (Class 3) connections are not reopened: they end with the session.
func WithAutoReconnect() Option {
	return func(o *options) error { o.reconnect = true; return nil }
}

// WithOriginator sets the originator vendor ID and serial number that
// identify the client's connections (the connection triad of
// Forward_Open). By default the vendor ID is [DefaultVendorID] and the
// serial number is random.
func WithOriginator(vendorID uint16, serial uint32) Option {
	return func(o *options) error {
		o.vendorID, o.origSerial = vendorID, serial
		return nil
	}
}

// WithStateHandler sets a function called when the session's state
// changes, with the error that caused a disconnection. It is called from
// the client's goroutines and must not block or call the client.
func WithStateHandler(f func(ethernetip.State, error)) Option {
	return func(o *options) error { o.stateChange = f; return nil }
}
