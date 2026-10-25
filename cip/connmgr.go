// SPDX-License-Identifier: MIT

package cip

import (
	"fmt"
	"math"
	"time"
)

// ConnectionType is the connection type of network connection parameters.
type ConnectionType uint8

// Connection types.
const (
	ConnectionNull         ConnectionType = 0
	ConnectionMulticast    ConnectionType = 1
	ConnectionPointToPoint ConnectionType = 2
)

// String returns "null", "multicast" or "point-to-point".
func (t ConnectionType) String() string {
	switch t {
	case ConnectionNull:
		return "null"
	case ConnectionMulticast:
		return "multicast"
	case ConnectionPointToPoint:
		return "point-to-point"
	default:
		return fmt.Sprintf("connection-type-%d", uint8(t))
	}
}

// Priority is the priority of network connection parameters.
type Priority uint8

// Priorities.
const (
	PriorityLow       Priority = 0
	PriorityHigh      Priority = 1
	PriorityScheduled Priority = 2
	PriorityUrgent    Priority = 3
)

// String returns "low", "high", "scheduled" or "urgent".
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityHigh:
		return "high"
	case PriorityScheduled:
		return "scheduled"
	case PriorityUrgent:
		return "urgent"
	default:
		return fmt.Sprintf("priority-%d", uint8(p))
	}
}

// NetworkParams are the network connection parameters of one direction of
// a connection.
type NetworkParams struct {
	RedundantOwner bool
	Type           ConnectionType
	Priority       Priority
	// Variable marks a variable size connection; Size is then the maximum.
	Variable bool
	// Size is the connection size in octets: for Class 1 the application
	// data plus the 16-bit sequence count and, where the format has one,
	// the 32-bit run/idle header. At most 511 for Forward_Open, 65535 for
	// Large_Forward_Open.
	Size uint16
}

// String returns for example "point-to-point low fixed 38".
func (p NetworkParams) String() string {
	fv := "fixed"
	if p.Variable {
		fv = "variable"
	}
	ro := ""
	if p.RedundantOwner {
		ro = " redundant-owner"
	}
	return fmt.Sprintf("%s %s %s %d%s", p.Type, p.Priority, fv, p.Size, ro)
}

// Encode16 encodes the parameters for Forward_Open.
func (p NetworkParams) Encode16() (uint16, error) {
	if p.Size > 0x1FF {
		return 0, fmt.Errorf("%w: connection size %d needs Large_Forward_Open", ErrTooLarge, p.Size)
	}
	if p.Type > 3 || p.Priority > 3 {
		return 0, fmt.Errorf("%w: network parameters %s", ErrMalformed, p)
	}
	v := p.Size | uint16(p.Type)<<13 | uint16(p.Priority)<<10
	if p.RedundantOwner {
		v |= 1 << 15
	}
	if p.Variable {
		v |= 1 << 9
	}
	return v, nil
}

// Encode32 encodes the parameters for Large_Forward_Open.
func (p NetworkParams) Encode32() (uint32, error) {
	if p.Type > 3 || p.Priority > 3 {
		return 0, fmt.Errorf("%w: network parameters %s", ErrMalformed, p)
	}
	v := uint32(p.Size) | uint32(p.Type)<<29 | uint32(p.Priority)<<26
	if p.RedundantOwner {
		v |= 1 << 31
	}
	if p.Variable {
		v |= 1 << 25
	}
	return v, nil
}

// DecodeNetworkParams16 decodes the parameters of a Forward_Open.
func DecodeNetworkParams16(v uint16) NetworkParams {
	return NetworkParams{
		RedundantOwner: v&(1<<15) != 0,
		Type:           ConnectionType(v >> 13 & 3),
		Priority:       Priority(v >> 10 & 3),
		Variable:       v&(1<<9) != 0,
		Size:           v & 0x1FF,
	}
}

// DecodeNetworkParams32 decodes the parameters of a Large_Forward_Open.
func DecodeNetworkParams32(v uint32) NetworkParams {
	return NetworkParams{
		RedundantOwner: v&(1<<31) != 0,
		Type:           ConnectionType(v >> 29 & 3),
		Priority:       Priority(v >> 26 & 3),
		Variable:       v&(1<<25) != 0,
		Size:           uint16(v),
	}
}

// Trigger is the production trigger of a connection.
type Trigger uint8

// Production triggers.
const (
	TriggerCyclic        Trigger = 0
	TriggerChangeOfState Trigger = 1
	TriggerApplication   Trigger = 2
)

// String returns "cyclic", "change-of-state" or "application".
func (t Trigger) String() string {
	switch t {
	case TriggerCyclic:
		return "cyclic"
	case TriggerChangeOfState:
		return "change-of-state"
	case TriggerApplication:
		return "application"
	default:
		return fmt.Sprintf("trigger-%d", uint8(t))
	}
}

// TransportTrigger is the transport class and trigger octet of a
// Forward_Open: direction (bit 7), production trigger (bits 6..4) and
// transport class (bits 3..0).
type TransportTrigger uint8

// Common transport/trigger values.
const (
	// TransportClass1Cyclic is a Class 1 cyclic connection (0x01).
	TransportClass1Cyclic TransportTrigger = 0x01
	// TransportClass3Server is a Class 3 application-triggered connection
	// to a server (0xA3), the connection of connected explicit messaging.
	TransportClass3Server TransportTrigger = 0xA3
)

// NewTransportTrigger returns the octet for a transport class, a trigger
// and the direction (server: the target is the server of the connection).
func NewTransportTrigger(class uint8, t Trigger, server bool) TransportTrigger {
	v := TransportTrigger(class&0x0F) | TransportTrigger(t&7)<<4
	if server {
		v |= 0x80
	}
	return v
}

// Class returns the transport class.
func (t TransportTrigger) Class() uint8 { return uint8(t) & 0x0F }

// Trigger returns the production trigger.
func (t TransportTrigger) Trigger() Trigger { return Trigger(t >> 4 & 7) }

// Server reports whether the direction bit is set.
func (t TransportTrigger) Server() bool { return t&0x80 != 0 }

// String returns for example "class 1 cyclic" or "class 3 application server".
func (t TransportTrigger) String() string {
	s := fmt.Sprintf("class %d %s", t.Class(), t.Trigger())
	if t.Server() {
		s += " server"
	}
	return s
}

// Triad identifies a connection: connection serial number, originator
// vendor ID and originator serial number.
type Triad struct {
	Serial           uint16
	VendorID         uint16
	OriginatorSerial uint32
}

// String returns for example "serial 0x0001 vendor 1 originator 0x12345678".
func (t Triad) String() string {
	return fmt.Sprintf("serial 0x%04X vendor %d originator 0x%08X", t.Serial, t.VendorID, t.OriginatorSerial)
}

// TickTimeout converts the priority/time tick octet and the timeout ticks
// of a Connection Manager request to a duration: ticks × 2^tick ms.
func TickTimeout(priorityTick, ticks uint8) time.Duration {
	return time.Duration(ticks) * (time.Millisecond << (priorityTick & 0x0F))
}

// Ticks returns the priority/time tick octet and timeout ticks that
// represent d as closely as possible from above, at most 255 × 2^15 ms
// (about 2.3 hours).
func Ticks(d time.Duration) (priorityTick, ticks uint8) {
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	for tick := uint8(0); tick < 16; tick++ {
		n := (ms + (1<<tick - 1)) >> tick
		if n <= math.MaxUint8 {
			return tick, uint8(n)
		}
	}
	return 15, math.MaxUint8
}

// ForwardOpen is a Forward_Open (0x54) or Large_Forward_Open (0x5B)
// request to the Connection Manager.
type ForwardOpen struct {
	// Large selects Large_Forward_Open: 32-bit network parameters.
	Large bool
	// PriorityTick and TimeoutTicks bound the time the request may take
	// (see [TickTimeout]).
	PriorityTick uint8
	TimeoutTicks uint8
	// OTConnID is the O->T network connection ID; the target chooses it
	// for point-to-point connections and returns it in the reply.
	OTConnID uint32
	// TOConnID is the T->O network connection ID the originator chooses
	// for point-to-point connections.
	TOConnID uint32
	Triad
	// TimeoutMultiplier: the connection times out after RPI × 4 << n.
	TimeoutMultiplier uint8
	// OTRPI and TORPI are the requested packet intervals in microseconds.
	OTRPI    uint32
	OTParams NetworkParams
	TORPI    uint32
	TOParams NetworkParams
	// Transport is the transport class and trigger.
	Transport TransportTrigger
	// Path is the connection path: an electronic key, the application
	// paths (for I/O: configuration instance, consumed and produced
	// connection points) and optionally a data segment of configuration
	// data.
	Path Path
}

// Service returns ServiceForwardOpen or ServiceLargeForwardOpen.
func (f ForwardOpen) Service() Service {
	if f.Large {
		return ServiceLargeForwardOpen
	}
	return ServiceForwardOpen
}

// ConnectionTimeout returns the inactivity timeout of the consuming side
// of the direction with RPI rpi: rpi × 4 << multiplier.
func ConnectionTimeout(rpi time.Duration, multiplier uint8) time.Duration {
	if multiplier > 7 {
		multiplier = 7
	}
	return rpi * time.Duration(4<<multiplier)
}

// Encode returns the request data.
func (f ForwardOpen) Encode() ([]byte, error) {
	if f.TimeoutMultiplier > 7 {
		return nil, fmt.Errorf("%w: timeout multiplier %d", ErrMalformed, f.TimeoutMultiplier)
	}
	path, err := f.Path.Encode()
	if err != nil {
		return nil, fmt.Errorf("connection path: %w", err)
	}
	if len(path)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("%w: connection path of %d octets", ErrTooLarge, len(path))
	}
	b := make([]byte, 0, 46+len(path))
	b = append(b, f.PriorityTick, f.TimeoutTicks)
	b = AppendUint32(b, f.OTConnID)
	b = AppendUint32(b, f.TOConnID)
	b = AppendUint16(b, f.Serial)
	b = AppendUint16(b, f.VendorID)
	b = AppendUint32(b, f.OriginatorSerial)
	b = append(b, f.TimeoutMultiplier, 0, 0, 0)
	for _, d := range []struct {
		rpi uint32
		p   NetworkParams
	}{{f.OTRPI, f.OTParams}, {f.TORPI, f.TOParams}} {
		b = AppendUint32(b, d.rpi)
		if f.Large {
			v, err := d.p.Encode32()
			if err != nil {
				return nil, err
			}
			b = AppendUint32(b, v)
		} else {
			v, err := d.p.Encode16()
			if err != nil {
				return nil, err
			}
			b = AppendUint16(b, v)
		}
	}
	b = append(b, byte(f.Transport), byte(len(path)/2))
	return append(b, path...), nil
}

// DecodeForwardOpen decodes the data of a Forward_Open (large false) or
// Large_Forward_Open (large true) request.
func DecodeForwardOpen(data []byte, large bool) (ForwardOpen, error) {
	r := NewReader(data)
	f := ForwardOpen{Large: large}
	f.PriorityTick = r.Uint8()
	f.TimeoutTicks = r.Uint8()
	f.OTConnID = r.Uint32()
	f.TOConnID = r.Uint32()
	f.Serial = r.Uint16()
	f.VendorID = r.Uint16()
	f.OriginatorSerial = r.Uint32()
	f.TimeoutMultiplier = r.Uint8()
	r.Skip(3)
	f.OTRPI = r.Uint32()
	if large {
		f.OTParams = DecodeNetworkParams32(r.Uint32())
	} else {
		f.OTParams = DecodeNetworkParams16(r.Uint16())
	}
	f.TORPI = r.Uint32()
	if large {
		f.TOParams = DecodeNetworkParams32(r.Uint32())
	} else {
		f.TOParams = DecodeNetworkParams16(r.Uint16())
	}
	f.Transport = TransportTrigger(r.Uint8())
	words := int(r.Uint8())
	raw := r.Bytes(2 * words)
	if err := r.Err(); err != nil {
		return f, fmt.Errorf("forward open: %w", err)
	}
	p, err := DecodePath(raw)
	if err != nil {
		return f, fmt.Errorf("forward open connection path: %w", err)
	}
	f.Path = p
	return f, nil
}

// ForwardOpenReply is the data of a successful Forward_Open or
// Large_Forward_Open response.
type ForwardOpenReply struct {
	OTConnID uint32
	TOConnID uint32
	Triad
	// OTAPI and TOAPI are the actual packet intervals in microseconds.
	OTAPI uint32
	TOAPI uint32
	// AppReply is the application reply, an even number of octets.
	AppReply []byte
}

// Encode returns the response data.
func (f ForwardOpenReply) Encode() ([]byte, error) {
	if len(f.AppReply)%2 != 0 || len(f.AppReply)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("%w: application reply of %d octets", ErrMalformed, len(f.AppReply))
	}
	b := make([]byte, 0, 26+len(f.AppReply))
	b = AppendUint32(b, f.OTConnID)
	b = AppendUint32(b, f.TOConnID)
	b = AppendUint16(b, f.Serial)
	b = AppendUint16(b, f.VendorID)
	b = AppendUint32(b, f.OriginatorSerial)
	b = AppendUint32(b, f.OTAPI)
	b = AppendUint32(b, f.TOAPI)
	b = append(b, byte(len(f.AppReply)/2), 0)
	return append(b, f.AppReply...), nil
}

// DecodeForwardOpenReply decodes the data of a successful Forward_Open
// response.
func DecodeForwardOpenReply(data []byte) (ForwardOpenReply, error) {
	r := NewReader(data)
	var f ForwardOpenReply
	f.OTConnID = r.Uint32()
	f.TOConnID = r.Uint32()
	f.Serial = r.Uint16()
	f.VendorID = r.Uint16()
	f.OriginatorSerial = r.Uint32()
	f.OTAPI = r.Uint32()
	f.TOAPI = r.Uint32()
	n := int(r.Uint8())
	r.Skip(1)
	f.AppReply = copyBytes(r.Bytes(2 * n))
	if err := r.Err(); err != nil {
		return f, fmt.Errorf("forward open reply: %w", err)
	}
	return f, nil
}

// ConnectionFailure is the data of an unsuccessful Forward_Open,
// Large_Forward_Open or Forward_Close response: the triad and the size in
// words of the part of the path that was not processed (Forward_Open only).
type ConnectionFailure struct {
	Triad
	RemainingPathSize uint8
}

// Encode returns the response data.
func (f ConnectionFailure) Encode() []byte {
	b := make([]byte, 0, 10)
	b = AppendUint16(b, f.Serial)
	b = AppendUint16(b, f.VendorID)
	b = AppendUint32(b, f.OriginatorSerial)
	return append(b, f.RemainingPathSize, 0)
}

// DecodeConnectionFailure decodes the data of an unsuccessful
// Forward_Open or Forward_Close response. The remaining path size is
// optional (some targets omit it).
func DecodeConnectionFailure(data []byte) (ConnectionFailure, error) {
	r := NewReader(data)
	var f ConnectionFailure
	f.Serial = r.Uint16()
	f.VendorID = r.Uint16()
	f.OriginatorSerial = r.Uint32()
	if r.Len() > 0 {
		f.RemainingPathSize = r.Uint8()
	}
	if err := r.Err(); err != nil {
		return f, fmt.Errorf("connection failure: %w", err)
	}
	return f, nil
}

// ForwardClose is a Forward_Close (0x4E) request.
type ForwardClose struct {
	PriorityTick uint8
	TimeoutTicks uint8
	Triad
	// Path is the connection path of the Forward_Open.
	Path Path
}

// Encode returns the request data.
func (f ForwardClose) Encode() ([]byte, error) {
	path, err := f.Path.Encode()
	if err != nil {
		return nil, fmt.Errorf("connection path: %w", err)
	}
	if len(path)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("%w: connection path of %d octets", ErrTooLarge, len(path))
	}
	b := make([]byte, 0, 12+len(path))
	b = append(b, f.PriorityTick, f.TimeoutTicks)
	b = AppendUint16(b, f.Serial)
	b = AppendUint16(b, f.VendorID)
	b = AppendUint32(b, f.OriginatorSerial)
	b = append(b, byte(len(path)/2), 0)
	return append(b, path...), nil
}

// DecodeForwardClose decodes the data of a Forward_Close request.
func DecodeForwardClose(data []byte) (ForwardClose, error) {
	r := NewReader(data)
	var f ForwardClose
	f.PriorityTick = r.Uint8()
	f.TimeoutTicks = r.Uint8()
	f.Serial = r.Uint16()
	f.VendorID = r.Uint16()
	f.OriginatorSerial = r.Uint32()
	words := int(r.Uint8())
	r.Skip(1)
	raw := r.Bytes(2 * words)
	if err := r.Err(); err != nil {
		return f, fmt.Errorf("forward close: %w", err)
	}
	p, err := DecodePath(raw)
	if err != nil {
		return f, fmt.Errorf("forward close connection path: %w", err)
	}
	f.Path = p
	return f, nil
}

// ForwardCloseReply is the data of a successful Forward_Close response.
type ForwardCloseReply struct {
	Triad
	AppReply []byte
}

// Encode returns the response data.
func (f ForwardCloseReply) Encode() ([]byte, error) {
	if len(f.AppReply)%2 != 0 || len(f.AppReply)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("%w: application reply of %d octets", ErrMalformed, len(f.AppReply))
	}
	b := make([]byte, 0, 10+len(f.AppReply))
	b = AppendUint16(b, f.Serial)
	b = AppendUint16(b, f.VendorID)
	b = AppendUint32(b, f.OriginatorSerial)
	b = append(b, byte(len(f.AppReply)/2), 0)
	return append(b, f.AppReply...), nil
}

// DecodeForwardCloseReply decodes the data of a successful Forward_Close
// response.
func DecodeForwardCloseReply(data []byte) (ForwardCloseReply, error) {
	r := NewReader(data)
	var f ForwardCloseReply
	f.Serial = r.Uint16()
	f.VendorID = r.Uint16()
	f.OriginatorSerial = r.Uint32()
	n := int(r.Uint8())
	r.Skip(1)
	f.AppReply = copyBytes(r.Bytes(2 * n))
	if err := r.Err(); err != nil {
		return f, fmt.Errorf("forward close reply: %w", err)
	}
	return f, nil
}

// UnconnectedSend is an Unconnected_Send (0x52) request: an embedded
// request that the Connection Manager forwards along a route.
type UnconnectedSend struct {
	PriorityTick uint8
	TimeoutTicks uint8
	// Request is the embedded request.
	Request Request
	// Route is the route path: port segments to the target.
	Route Path
}

// Encode returns the request data.
func (u UnconnectedSend) Encode() ([]byte, error) {
	msg, err := u.Request.Encode()
	if err != nil {
		return nil, fmt.Errorf("embedded request: %w", err)
	}
	if len(msg) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: embedded request of %d octets", ErrTooLarge, len(msg))
	}
	route, err := u.Route.Encode()
	if err != nil {
		return nil, fmt.Errorf("route path: %w", err)
	}
	if len(route)/2 > math.MaxUint8 {
		return nil, fmt.Errorf("%w: route path of %d octets", ErrTooLarge, len(route))
	}
	b := make([]byte, 0, 8+len(msg)+len(route))
	b = append(b, u.PriorityTick, u.TimeoutTicks)
	b = AppendUint16(b, uint16(len(msg)))
	b = append(b, msg...)
	if len(msg)%2 != 0 {
		b = append(b, 0)
	}
	b = append(b, byte(len(route)/2), 0)
	return append(b, route...), nil
}

// DecodeUnconnectedSend decodes the data of an Unconnected_Send request.
func DecodeUnconnectedSend(data []byte) (UnconnectedSend, error) {
	r := NewReader(data)
	var u UnconnectedSend
	u.PriorityTick = r.Uint8()
	u.TimeoutTicks = r.Uint8()
	n := int(r.Uint16())
	msg := r.Bytes(n)
	if n%2 != 0 {
		r.Skip(1)
	}
	words := int(r.Uint8())
	r.Skip(1)
	raw := r.Bytes(2 * words)
	if err := r.Err(); err != nil {
		return u, fmt.Errorf("unconnected send: %w", err)
	}
	req, err := DecodeRequest(msg)
	if err != nil {
		return u, fmt.Errorf("unconnected send: embedded %w", err)
	}
	route, err := DecodePath(raw)
	if err != nil {
		return u, fmt.Errorf("unconnected send route: %w", err)
	}
	u.Request, u.Route = req, route
	return u, nil
}
