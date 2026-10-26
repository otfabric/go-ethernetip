// SPDX-License-Identifier: MIT

package ethernetip

import (
	"net"
	"net/netip"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Metrics is an optional callback interface for observing the sessions and
// the traffic of a client or a server. A nil Metrics disables collection.
//
// The methods are called synchronously on the protocol path, possibly from
// several goroutines at once; implementations must be safe for concurrent
// use and must not block (increment a counter, send on a buffered channel).
//
// Embed [NopMetrics] to implement only the callbacks you need and to stay
// compatible when methods are added.
type Metrics interface {
	// OnConnect is called when a TCP connection is established (client)
	// or accepted (server).
	OnConnect(remote net.Addr)

	// OnDisconnect is called when a TCP connection ends. err is nil when
	// the application closed it.
	OnDisconnect(remote net.Addr, err error)

	// OnPacketSent is called after an encapsulation packet was written.
	// size is its length on the wire in octets.
	OnPacketSent(remote net.Addr, cmd encap.Command, size int)

	// OnPacketReceived is called for every encapsulation packet read.
	OnPacketReceived(remote net.Addr, cmd encap.Command, size int)

	// OnDecodeError is called when a packet, a common packet format or a
	// CIP message could not be decoded and was dropped or refused.
	OnDecodeError(remote net.Addr, err error)
}

// NopMetrics is a [Metrics] that does nothing. Embed it in your own type.
type NopMetrics struct{}

// OnConnect does nothing.
func (NopMetrics) OnConnect(net.Addr) {}

// OnDisconnect does nothing.
func (NopMetrics) OnDisconnect(net.Addr, error) {}

// OnPacketSent does nothing.
func (NopMetrics) OnPacketSent(net.Addr, encap.Command, int) {}

// OnPacketReceived does nothing.
func (NopMetrics) OnPacketReceived(net.Addr, encap.Command, int) {}

// OnDecodeError does nothing.
func (NopMetrics) OnDecodeError(net.Addr, error) {}

// RequestMetrics is an optional extension of [Metrics] for a client. When
// the value given to client.WithMetrics also implements it, the client
// reports every explicit request.
type RequestMetrics interface {
	// OnRequest is called before a request is sent.
	OnRequest(remote net.Addr, service cip.Service)

	// OnRequestDone is called with the outcome. err is nil on success;
	// classify failures with errors.Is and errors.As (*CIPError,
	// ErrTimeout, ...).
	OnRequestDone(remote net.Addr, service cip.Service, duration time.Duration, err error)
}

// ServerMetrics is an optional extension of [Metrics] for a server. When
// the value given to server.WithMetrics also implements it, the server
// reports every request it handled and every connection it opened, closed
// or lost.
type ServerMetrics interface {
	// OnHandled is called after an explicit request was handled, with its
	// general status.
	OnHandled(remote net.Addr, service cip.Service, status cip.GeneralStatus, duration time.Duration)

	// OnConnectionOpened is called after a Forward_Open succeeded.
	OnConnectionOpened(remote net.Addr, info ConnectionInfo)

	// OnConnectionClosed is called when a connection ends: by Forward_Close
	// (err nil), by timeout (ErrTimeout), with its session, or on Close.
	OnConnectionClosed(remote net.Addr, info ConnectionInfo, err error)
}

// IOMetrics is an optional extension of [Metrics] for implicit (Class 0/1)
// traffic, for a scanner or a server.
type IOMetrics interface {
	// OnIOSent is called after an I/O datagram was sent.
	OnIOSent(connID uint32, size int)

	// OnIOReceived is called for every I/O datagram accepted for a
	// connection.
	OnIOReceived(connID uint32, size int)

	// OnIODropped is called for an I/O datagram that was dropped: unknown
	// connection ID, stale sequence number, wrong size, malformed.
	OnIODropped(remote net.Addr, reason string)
}

// ConnectionInfo describes a CIP connection for metrics and logs.
type ConnectionInfo struct {
	// Class is the transport class (0, 1 or 3).
	Class uint8
	// OTConnID and TOConnID are the network connection IDs.
	OTConnID, TOConnID uint32
	// Serial, VendorID and OriginatorSerial identify the connection (its
	// connection triad).
	Serial           uint16
	VendorID         uint16
	OriginatorSerial uint32
	// OTRPI and TORPI are the actual packet intervals.
	OTRPI, TORPI time.Duration
	// Path is the connection path.
	Path cip.Path
	// Group is the multicast address of the T->O data, when it is
	// multicast.
	Group netip.Addr
}
