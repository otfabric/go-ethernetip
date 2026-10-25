// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// NewTriad returns a connection triad for a new connection: a fresh
// connection serial number and the client's originator vendor ID and
// serial number.
func (c *Client) NewTriad() cip.Triad {
	return cip.Triad{Serial: c.nextSerial(), VendorID: c.opts.vendorID, OriginatorSerial: c.opts.origSerial}
}

// NewConnectionID returns a random connection ID for the originator's side
// of a connection.
func NewConnectionID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:]) | 1
}

// ForwardOpen sends a Forward_Open (or, with fo.Large, a
// Large_Forward_Open) to the target's Connection Manager. The client's
// route, if any, is prefixed to the connection path. items are added to the
// request's common packet format (a Sockaddr Info T->O item tells the target
// where to send I/O data); the reply's other items (Sockaddr Info) are
// returned with the reply.
//
// A refusal is a *ethernetip.CIPError with general status 0x01 and the
// Connection Manager's extended status (cip.ConnectionStatus).
func (c *Client) ForwardOpen(ctx context.Context, fo cip.ForwardOpen, items ...encap.Item) (cip.ForwardOpenReply, []encap.Item, error) {
	if len(c.opts.route) > 0 {
		fo.Path = append(append(cip.Path{}, c.opts.route...), fo.Path...)
	}
	if fo.PriorityTick == 0 && fo.TimeoutTicks == 0 {
		fo.PriorityTick, fo.TimeoutTicks = cip.Ticks(c.opts.timeout)
	}
	data, err := fo.Encode()
	if err != nil {
		return cip.ForwardOpenReply{}, nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	req := cip.Request{Service: fo.Service(), Path: cip.ConnectionManagerPath(), Data: data}
	resp, rItems, err := c.do(ctx, req, items, nil)
	if err != nil {
		return cip.ForwardOpenReply{}, rItems, err
	}
	reply, err := cip.DecodeForwardOpenReply(resp.Data)
	if err != nil {
		return reply, rItems, c.protocolError("Forward_Open reply", err)
	}
	if reply.Triad != fo.Triad {
		return reply, rItems, fmt.Errorf("%w: Forward_Open reply for %s, requested %s", ethernetip.ErrProtocol, reply.Triad, fo.Triad)
	}
	var other []encap.Item
	for _, it := range rItems {
		if it.Type != encap.ItemNullAddress && it.Type != encap.ItemUnconnectedData {
			other = append(other, it)
		}
	}
	return reply, other, nil
}

// ForwardClose closes a connection with Forward_Close. The client's route,
// if any, is prefixed to the connection path.
func (c *Client) ForwardClose(ctx context.Context, fc cip.ForwardClose) error {
	if len(c.opts.route) > 0 {
		fc.Path = append(append(cip.Path{}, c.opts.route...), fc.Path...)
	}
	if fc.PriorityTick == 0 && fc.TimeoutTicks == 0 {
		fc.PriorityTick, fc.TimeoutTicks = cip.Ticks(c.opts.timeout)
	}
	data, err := fc.Encode()
	if err != nil {
		return fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	resp, _, err := c.do(ctx, cip.Request{Service: cip.ServiceForwardClose, Path: cip.ConnectionManagerPath(), Data: data}, nil, nil)
	if err != nil {
		return err
	}
	reply, err := cip.DecodeForwardCloseReply(resp.Data)
	if err != nil {
		return c.protocolError("Forward_Close reply", err)
	}
	if reply.Triad != fc.Triad {
		return fmt.Errorf("%w: Forward_Close reply for %s, requested %s", ethernetip.ErrProtocol, reply.Triad, fc.Triad)
	}
	return nil
}

// ConnectionOptions configures a connected (Class 3) explicit messaging
// connection.
type ConnectionOptions struct {
	// Timeout is how long the target keeps the connection without a
	// request: it times out after RPI × 4 << multiplier, which the client
	// derives from it. Zero means 60 seconds.
	Timeout time.Duration
	// Size is the connection size in octets, the largest request and
	// reply. Zero means 500, or 4000 with Large.
	Size uint16
	// Large opens the connection with Large_Forward_Open, for sizes above
	// 511 octets.
	Large bool
	// Path is the application path of the connection; nil means the
	// Message Router (@2/1).
	Path cip.Path
}

// Conn is a connected (Class 3) explicit messaging connection. Requests
// are sent with SendUnitData, one at a time, in the order they are made.
// A Conn is safe for concurrent use. It ends with Close, when the
// session is lost, or when the target times it out for inactivity.
type Conn struct {
	c    *Client
	s    *session
	info ethernetip.ConnectionInfo

	turn chan struct{} // one request at a time

	mu      sync.Mutex
	seq     uint16
	pending chan reply
	err     error
}

// OpenConnection opens a Class 3 connection to the target's Message
// Router (or opts.Path) with Forward_Open.
func (c *Client) OpenConnection(ctx context.Context, opts ConnectionOptions) (*Conn, error) {
	if opts.Timeout == 0 {
		opts.Timeout = time.Minute
	}
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("%w: timeout %v", ethernetip.ErrInvalidOption, opts.Timeout)
	}
	if opts.Size == 0 {
		opts.Size = 500
		if opts.Large {
			opts.Size = 4000
		}
	}
	if opts.Path == nil {
		opts.Path = cip.MessageRouterPath()
	}
	mult, rpi := classThreeTiming(opts.Timeout)
	triad := c.NewTriad()
	toID := NewConnectionID()
	params := cip.NetworkParams{Type: cip.ConnectionPointToPoint, Priority: cip.PriorityLow, Variable: true, Size: opts.Size}
	fo := cip.ForwardOpen{
		Large:             opts.Large,
		TOConnID:          toID,
		Triad:             triad,
		TimeoutMultiplier: mult,
		OTRPI:             rpi,
		OTParams:          params,
		TORPI:             rpi,
		TOParams:          params,
		Transport:         cip.TransportClass3Server,
		Path:              opts.Path,
	}
	reply, _, err := c.ForwardOpen(ctx, fo)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	if s == nil {
		return nil, ethernetip.ErrNotConnected
	}
	cn := &Conn{
		c: c,
		s: s,
		info: ethernetip.ConnectionInfo{
			Class: 3, OTConnID: reply.OTConnID, TOConnID: reply.TOConnID,
			Serial: triad.Serial, VendorID: triad.VendorID, OriginatorSerial: triad.OriginatorSerial,
			OTRPI: time.Duration(reply.OTAPI) * time.Microsecond, TORPI: time.Duration(reply.TOAPI) * time.Microsecond,
			Path: fo.Path,
		},
		turn: make(chan struct{}, 1),
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	// Replies are recognised by either ID: some targets (cpppo) answer with
	// the O->T ID.
	s.conns[reply.TOConnID] = cn
	s.conns[reply.OTConnID] = cn
	s.mu.Unlock()
	c.log.Info("connection opened", "class", 3, "ot", reply.OTConnID, "to", reply.TOConnID)
	return cn, nil
}

// classThreeTiming returns the timeout multiplier and the RPI in
// microseconds that make the target time a connection out after about d.
func classThreeTiming(d time.Duration) (uint8, uint32) {
	for mult := uint8(0); mult <= 7; mult++ {
		rpi := d / time.Duration(4<<mult)
		if rpi <= 10*time.Second {
			return mult, uint32(rpi / time.Microsecond)
		}
	}
	return 7, uint32(d / 512 / time.Microsecond)
}

// Info returns the connection's IDs, triad and intervals.
func (cn *Conn) Info() ethernetip.ConnectionInfo { return cn.info }

// Do sends a request over the connection and returns the response. A
// response whose status is not success is returned with a
// *ethernetip.CIPError.
func (cn *Conn) Do(ctx context.Context, req cip.Request) (cip.Response, error) {
	start := time.Now()
	cn.c.reportRequest(req.Service)
	resp, err := cn.do(ctx, req)
	cn.c.reportDone(req.Service, start, err)
	return resp, err
}

func (cn *Conn) do(ctx context.Context, req cip.Request) (cip.Response, error) {
	ctx, cancel := cn.c.deadline(ctx)
	defer cancel()
	select {
	case cn.turn <- struct{}{}:
	case <-ctx.Done():
		return cip.Response{}, ctxErr(ctx)
	}
	defer func() { <-cn.turn }()
	msg, err := req.Encode()
	if err != nil {
		return cip.Response{}, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	cn.mu.Lock()
	if cn.err != nil {
		err := cn.err
		cn.mu.Unlock()
		return cip.Response{}, err
	}
	// Sequence counts start at 1: some targets (OpENer) take a first
	// request with 0 for a repeat.
	cn.seq++
	if cn.seq == 0 {
		cn.seq = 1
	}
	seq := cn.seq
	ch := make(chan reply, 1)
	cn.pending = ch
	cn.mu.Unlock()

	payload := binary.LittleEndian.AppendUint16(make([]byte, 0, 2+len(msg)), seq)
	payload = append(payload, msg...)
	data, err := encap.RRData{Items: []encap.Item{
		encap.ConnectedAddress(cn.info.OTConnID),
		{Type: encap.ItemConnectedData, Data: payload},
	}}.Encode()
	if err != nil {
		return cip.Response{}, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		cn.s.wmu.Lock()
		_ = cn.s.conn.SetWriteDeadline(dl)
		cn.s.wmu.Unlock()
	}
	if err := cn.s.write(encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: cn.s.handle}, Data: data}); err != nil {
		cn.s.close(fmt.Errorf("%w: write: %w", ethernetip.ErrConnectionLost, err))
		r := <-ch
		return cip.Response{}, r.err
	}
	var r reply
	select {
	case r = <-ch:
	case <-ctx.Done():
		cn.mu.Lock()
		if cn.pending == ch {
			cn.pending = nil
		}
		cn.mu.Unlock()
		return cip.Response{}, ctxErr(ctx)
	}
	if r.err != nil {
		return cip.Response{}, r.err
	}
	resp, err := cip.DecodeResponse(r.pkt.Data)
	if err != nil {
		return cip.Response{}, cn.c.protocolError("SendUnitData reply", err)
	}
	resp, _, err = checkResponse(req, resp, false, nil)
	return resp, err
}

// dispatchConnected delivers a SendUnitData reply to its connection. The
// packet's data is replaced by the CIP response.
func (s *session) dispatchConnected(pkt encap.Packet) {
	rr, err := encap.DecodeRRData(pkt.Data)
	var id uint32
	var data []byte
	if err == nil {
		addr, ok1 := encap.Find(rr.Items, encap.ItemConnectedAddress)
		it, ok2 := encap.Find(rr.Items, encap.ItemConnectedData)
		switch {
		case !ok1 || !ok2:
			err = errors.New("connected address or data item missing")
		case len(it.Data) < 2:
			err = errors.New("connected data item without a sequence count")
		default:
			id, err = encap.DecodeConnectedAddress(addr)
			data = it.Data
		}
	}
	if err != nil {
		if m := s.c.opts.metrics; m != nil {
			m.OnDecodeError(s.remote, err)
		}
		s.c.log.Warn("SendUnitData dropped", "error", err)
		return
	}
	seq := binary.LittleEndian.Uint16(data)
	s.mu.Lock()
	cn := s.conns[id]
	s.mu.Unlock()
	if cn == nil {
		s.c.log.Debug("SendUnitData for an unknown connection dropped", "connection", id)
		return
	}
	cn.mu.Lock()
	ch := cn.pending
	if ch == nil || seq != cn.seq {
		cn.mu.Unlock()
		s.c.log.Debug("SendUnitData reply without a pending request dropped", "connection", id, "sequence", seq)
		return
	}
	cn.pending = nil
	cn.mu.Unlock()
	pkt.Data = append([]byte(nil), data[2:]...)
	ch <- reply{pkt: pkt}
}

// lost ends the connection with the session's error.
func (cn *Conn) lost(err error) {
	cn.mu.Lock()
	if cn.err == nil {
		cn.err = err
	}
	ch := cn.pending
	cn.pending = nil
	cn.mu.Unlock()
	if ch != nil {
		ch <- reply{err: err}
	}
}

// Close closes the connection with Forward_Close. The connection is
// unusable afterwards even when Forward_Close fails (the target then times
// it out). Close is idempotent.
func (cn *Conn) Close(ctx context.Context) error {
	cn.mu.Lock()
	if cn.err != nil {
		cn.mu.Unlock()
		return nil
	}
	cn.err = ethernetip.ErrClosed
	cn.mu.Unlock()
	cn.s.mu.Lock()
	delete(cn.s.conns, cn.info.OTConnID)
	delete(cn.s.conns, cn.info.TOConnID)
	cn.s.mu.Unlock()
	return cn.c.ForwardClose(ctx, cip.ForwardClose{
		Triad: cip.Triad{Serial: cn.info.Serial, VendorID: cn.info.VendorID, OriginatorSerial: cn.info.OriginatorSerial},
		Path:  cn.info.Path,
	})
}

// GetAttributeSingle reads one attribute over the connection.
func (cn *Conn) GetAttributeSingle(ctx context.Context, class cip.Class, instance uint32, attribute uint16) ([]byte, error) {
	return getAttributeSingle(ctx, cn, class, instance, attribute)
}

// SetAttributeSingle writes one attribute over the connection.
func (cn *Conn) SetAttributeSingle(ctx context.Context, class cip.Class, instance uint32, attribute uint16, value []byte) error {
	return setAttributeSingle(ctx, cn, class, instance, attribute, value)
}

// GetAttributesAll reads the attributes of an instance over the
// connection.
func (cn *Conn) GetAttributesAll(ctx context.Context, class cip.Class, instance uint32) ([]byte, error) {
	return getAttributesAll(ctx, cn, class, instance)
}

// Identity reads the Identity object over the connection.
func (cn *Conn) Identity(ctx context.Context) (cip.Identity, error) { return identity(ctx, cn) }

// MultipleService sends a Multiple Service Packet over the connection.
func (cn *Conn) MultipleService(ctx context.Context, reqs []cip.Request) ([]cip.Response, error) {
	return multipleService(ctx, cn, reqs)
}
