// SPDX-License-Identifier: MIT

package ethernetip

import (
	"errors"
	"fmt"
	"strings"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Sentinel errors shared by the client, the scanner and the server. They are
// usually wrapped with detail; test with errors.Is.
var (
	// ErrClosed reports an operation on a client, connection or server that
	// was closed by the application.
	ErrClosed = errors.New("ethernetip: closed")

	// ErrNotConnected reports a request on a client that has no registered
	// session.
	ErrNotConnected = errors.New("ethernetip: not connected")

	// ErrConnectFailed reports that a client could not establish its
	// session: the dial, the TLS handshake or RegisterSession failed. The
	// underlying error is wrapped alongside it.
	ErrConnectFailed = errors.New("ethernetip: connect failed")

	// ErrConnectionLost reports that the peer closed the TCP connection or
	// the transport failed while a request was in progress.
	ErrConnectionLost = errors.New("ethernetip: connection lost")

	// ErrTimeout reports that the peer did not answer within the request
	// timeout, or that an I/O connection's consumed data stopped arriving
	// within its connection timeout.
	ErrTimeout = errors.New("ethernetip: timeout")

	// ErrProtocol reports a peer that violated the protocol: a malformed
	// encapsulation packet or CIP response, a reply to a service that was
	// not requested, an unexpected item in a common packet format.
	ErrProtocol = errors.New("ethernetip: protocol violation")

	// ErrSession reports an encapsulation level failure of the session: the
	// peer rejected the session handle, the protocol version or the
	// command. An *[EncapError] carries the status.
	ErrSession = errors.New("ethernetip: session error")

	// ErrBusy reports a request that cannot be issued because a limit was
	// reached: pending requests of a client, sessions or connections of a
	// server.
	ErrBusy = errors.New("ethernetip: resource limit reached")

	// ErrUnsupported reports that the peer does not support the service or
	// attribute (CIP general status 0x08 or 0x14), or that the operation is
	// not available on this transport.
	ErrUnsupported = errors.New("ethernetip: unsupported")

	// ErrInvalidOption reports an option or argument value a client, scanner
	// or server cannot be constructed or called with.
	ErrInvalidOption = errors.New("ethernetip: invalid option")
)

// CIPError reports a CIP response whose general status is not success. It
// keeps the service, the general status and the additional (extended)
// status words exactly as the peer sent them.
type CIPError struct {
	// Service is the service code of the request (without the reply bit).
	Service cip.Service
	// Path is the request path, for messages; it may be nil.
	Path cip.Path
	// Status is the general status code.
	Status cip.GeneralStatus
	// Extended is the additional status, in the order sent.
	Extended []uint16
	// Data is the response data that came with the error, if any. Some
	// services return data with an error (Forward_Open's remaining path
	// size, Multiple Service Packet's replies).
	Data []byte
}

// Error describes the failure, for example
// "ethernetip: Get_Attribute_Single @1/1/9: attribute not supported (0x14)".
func (e *CIPError) Error() string {
	var sb strings.Builder
	sb.WriteString("ethernetip: ")
	sb.WriteString(e.Service.String())
	if len(e.Path) > 0 {
		sb.WriteString(" ")
		sb.WriteString(e.Path.String())
	}
	fmt.Fprintf(&sb, ": %s (0x%02X)", e.Status, uint8(e.Status))
	if len(e.Extended) > 0 {
		sb.WriteString(", extended")
		for i, x := range e.Extended {
			if i == 0 && e.Status == cip.StatusConnectionFailure {
				fmt.Fprintf(&sb, " 0x%04X (%s)", x, cip.ConnectionStatus(x))
				continue
			}
			fmt.Fprintf(&sb, " 0x%04X", x)
		}
	}
	return sb.String()
}

// ExtendedStatus returns the first additional status word, and false when
// there is none.
func (e *CIPError) ExtendedStatus() (uint16, bool) {
	if len(e.Extended) == 0 {
		return 0, false
	}
	return e.Extended[0], true
}

// Is makes a CIPError with status 0x08 (service not supported) or 0x14
// (attribute not supported) match [ErrUnsupported].
func (e *CIPError) Is(target error) bool {
	return target == ErrUnsupported &&
		(e.Status == cip.StatusServiceNotSupported || e.Status == cip.StatusAttributeNotSupported)
}

// EncapError reports an encapsulation packet whose status is not success:
// the peer refused the command, the session handle or the length.
type EncapError struct {
	// Command is the encapsulation command of the reply.
	Command encap.Command
	// Status is the encapsulation status.
	Status encap.Status
}

// Error describes the failure, for example
// "ethernetip: SendRRData: invalid session handle (0x0064)".
func (e *EncapError) Error() string {
	return fmt.Sprintf("ethernetip: %s: %s (0x%04X)", e.Command, e.Status, uint32(e.Status))
}

// Is makes an EncapError match [ErrSession], and [ErrUnsupported] for an
// unsupported command.
func (e *EncapError) Is(target error) bool {
	switch target {
	case ErrSession:
		return true
	case ErrUnsupported:
		return e.Status == encap.StatusInvalidCommand
	}
	return false
}

// StatusOf returns the CIP general status of err when it is or wraps a
// *CIPError, and false otherwise.
func StatusOf(err error) (cip.GeneralStatus, bool) {
	var ce *CIPError
	if errors.As(err, &ce) {
		return ce.Status, true
	}
	return 0, false
}
