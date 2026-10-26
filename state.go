// SPDX-License-Identifier: MIT

package ethernetip

// State is the state of a client's session or of an I/O connection.
type State uint8

// Session and connection states.
const (
	// StateDisconnected means there is no TCP connection, or the I/O
	// connection is closed.
	StateDisconnected State = iota
	// StateConnecting means the client is dialing and registering the
	// session, or the scanner is opening the I/O connection.
	StateConnecting
	// StateConnected means the session is registered, or the I/O
	// connection exchanges data.
	StateConnected
	// StateTimedOut means an I/O connection's consumed data stopped
	// arriving within the connection timeout.
	StateTimedOut
)

// String returns "disconnected", "connecting", "connected" or "timed-out".
func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateTimedOut:
		return "timed-out"
	default:
		return "unknown"
	}
}
