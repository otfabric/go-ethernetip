// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// session is one TCP connection of an originator, with its registered
// session handle. Its goroutine reads the packets and handles them in
// order.
type session struct {
	s      *Server
	conn   net.Conn
	remote net.Addr
	local  net.Addr

	handle uint32 // owned by the session goroutine; 0 until registered

	wmu sync.Mutex

	once sync.Once
}

// exchange is what a request handler needs of the encapsulation that
// carried its request: the CPF items besides the message, and the items to
// add to the reply. It travels in the context.
type exchange struct {
	sess     *session
	items    []encap.Item
	addItems []encap.Item
	// maxReply is the reply data a Class 3 connection carries: its T->O
	// size less the sequence count and the reply header; 0 off a
	// connection.
	maxReply int
}

type exchangeKey struct{}

func exchangeOf(ctx context.Context) *exchange {
	e, _ := ctx.Value(exchangeKey{}).(*exchange)
	return e
}

func (s *Server) serveConn(c net.Conn) {
	defer s.wg.Done()
	ss := &session{s: s, conn: c, remote: c.RemoteAddr(), local: c.LocalAddr()}
	s.mu.Lock()
	if s.closed || len(s.conns) >= s.maxTCPConns() {
		closed := s.closed
		s.mu.Unlock()
		_ = c.Close()
		if !closed {
			s.log.Warn("too many TCP connections: connection closed", "remote", ss.remote.String(), "limit", s.maxTCPConns())
		}
		return
	}
	s.conns[ss] = true
	s.mu.Unlock()
	if m := s.opts.metrics; m != nil {
		m.OnConnect(ss.remote)
	}
	if tc, ok := c.(*tls.Conn); ok {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(s.ctx); err != nil {
			s.log.Warn("TLS handshake failed", "remote", ss.remote.String(), "error", err)
			_ = c.Close()
			if m := s.opts.metrics; m != nil {
				m.OnDisconnect(ss.remote, err)
			}
			return
		}
		_ = tc.SetDeadline(time.Time{})
	}
	s.log.Debug("connection accepted", "remote", ss.remote.String())
	err := ss.serve()
	ss.close()
	if m := s.opts.metrics; m != nil {
		if errors.Is(err, io.EOF) || s.ctx.Err() != nil {
			err = nil
		}
		m.OnDisconnect(ss.remote, err)
	}
}

// close ends the session: it is unregistered, its Class 3 connections are
// closed and the TCP connection is closed.
func (ss *session) close() {
	ss.once.Do(func() {
		_ = ss.conn.Close()
		ss.s.mu.Lock()
		delete(ss.s.conns, ss)
		for h, x := range ss.s.sessions {
			if x == ss {
				delete(ss.s.sessions, h)
			}
		}
		ss.s.mu.Unlock()
		ss.s.cm.sessionClosed(ss)
	})
}

func (ss *session) serve() error {
	var buf []byte
	for {
		if d := ss.s.inactivityTimeout(); d > 0 {
			_ = ss.conn.SetReadDeadline(time.Now().Add(d))
		}
		pkt, nb, err := encap.ReadPacket(ss.conn, buf, ss.s.opts.maxPacket)
		buf = nb
		if err != nil {
			if errors.Is(err, encap.ErrTooLarge) {
				ss.reply(pkt.Header, encap.StatusInvalidLength, nil)
				ss.s.log.Warn("packet too large: session closed", "remote", ss.remote.String(), "length", pkt.Length)
			}
			return err
		}
		if m := ss.s.opts.metrics; m != nil {
			m.OnPacketReceived(ss.remote, pkt.Command, encap.HeaderSize+len(pkt.Data))
		}
		if pkt.Options != 0 {
			// Encapsulation packets with options set are discarded.
			ss.s.log.Debug("packet with options discarded", "command", pkt.Command)
			continue
		}
		if !ss.handle0(pkt) {
			return nil
		}
	}
}

func (s *Server) inactivityTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inactivity
}

// handle0 handles one packet; false ends the session.
func (ss *session) handle0(pkt encap.Packet) bool {
	switch pkt.Command {
	case encap.CommandNOP:
		return true
	case encap.CommandRegisterSession:
		ss.register(pkt)
		return true
	case encap.CommandUnRegisterSession:
		if pkt.Session == ss.handle && ss.handle != 0 {
			return false
		}
		ss.reply(pkt.Header, encap.StatusInvalidSessionHandle, nil)
		return true
	case encap.CommandListIdentity:
		ss.replyData(pkt.Header, ss.s.listIdentity(ss.local))
		return true
	case encap.CommandListServices:
		ss.replyData(pkt.Header, listServices())
		return true
	case encap.CommandListInterfaces:
		ss.replyData(pkt.Header, []byte{0, 0})
		return true
	case encap.CommandSendRRData:
		if !ss.checkSession(pkt) {
			return true
		}
		ss.sendRRData(pkt)
		return true
	case encap.CommandSendUnitData:
		if !ss.checkSession(pkt) {
			return true
		}
		ss.sendUnitData(pkt)
		return true
	default:
		ss.reply(pkt.Header, encap.StatusInvalidCommand, nil)
		return true
	}
}

func (ss *session) checkSession(pkt encap.Packet) bool {
	if ss.handle == 0 || pkt.Session != ss.handle {
		ss.reply(pkt.Header, encap.StatusInvalidSessionHandle, nil)
		return false
	}
	return true
}

func (ss *session) register(pkt encap.Packet) {
	r, err := encap.DecodeRegister(pkt.Data)
	if err != nil || len(pkt.Data) != 4 {
		ss.reply(pkt.Header, encap.StatusInvalidLength, nil)
		return
	}
	if r.ProtocolVersion != encap.ProtocolVersion || r.Options != 0 {
		ss.reply(pkt.Header, encap.StatusUnsupportedProtocol,
			encap.Register{ProtocolVersion: encap.ProtocolVersion}.Encode())
		return
	}
	if ss.handle != 0 {
		ss.reply(pkt.Header, encap.StatusInvalidCommand, pkt.Data)
		return
	}
	s := ss.s
	s.mu.Lock()
	if s.closed || len(s.sessions) >= s.opts.maxSessions {
		s.mu.Unlock()
		ss.reply(pkt.Header, encap.StatusInsufficientMemory, pkt.Data)
		return
	}
	var h uint32
	for h == 0 || s.sessions[h] != nil {
		var b [4]byte
		_, _ = rand.Read(b[:])
		h = binary.LittleEndian.Uint32(b[:])
	}
	s.sessions[h] = ss
	s.mu.Unlock()
	ss.handle = h
	hd := pkt.Header
	hd.Session = h
	ss.reply(hd, encap.StatusSuccess, pkt.Data)
	s.log.Debug("session registered", "remote", ss.remote.String(), "session", h)
}

// reply writes a reply to the request with header h.
func (ss *session) reply(h encap.Header, st encap.Status, data []byte) {
	h.Status = st
	h.Options = 0
	b, err := encap.Packet{Header: h, Data: data}.AppendTo(make([]byte, 0, encap.HeaderSize+len(data)))
	if err != nil {
		ss.s.log.Warn("reply not encoded", "command", h.Command, "error", err)
		return
	}
	ss.wmu.Lock()
	_ = ss.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = ss.conn.Write(b)
	ss.wmu.Unlock()
	if err != nil {
		ss.s.log.Debug("reply not written", "remote", ss.remote.String(), "error", err)
		_ = ss.conn.Close()
		return
	}
	if m := ss.s.opts.metrics; m != nil {
		m.OnPacketSent(ss.remote, h.Command, len(b))
	}
}

func (ss *session) replyData(h encap.Header, data []byte) { ss.reply(h, encap.StatusSuccess, data) }

func (ss *session) decodeError(err error) {
	if m := ss.s.opts.metrics; m != nil {
		m.OnDecodeError(ss.remote, err)
	}
}

func (ss *session) sendRRData(pkt encap.Packet) {
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		ss.decodeError(err)
		ss.reply(pkt.Header, encap.StatusIncorrectData, nil)
		return
	}
	null, ok1 := encap.Find(rr.Items, encap.ItemNullAddress)
	msg, ok2 := encap.Find(rr.Items, encap.ItemUnconnectedData)
	if rr.InterfaceHandle != 0 || !ok1 || !ok2 || len(null.Data) != 0 {
		ss.reply(pkt.Header, encap.StatusIncorrectData, nil)
		return
	}
	ex := &exchange{sess: ss, items: rr.Items}
	ctx := context.WithValue(ss.s.ctx, exchangeKey{}, ex)
	resp := ss.s.handleMessage(ctx, msg.Data, ss.remote, false)
	b, err := resp.Encode()
	if err == nil {
		items := append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: b}}, ex.addItems...)
		var data []byte
		if data, err = (encap.RRData{Items: items}).Encode(); err == nil && len(data) <= encap.MaxData {
			ss.replyData(pkt.Header, data)
			return
		}
	}
	// The reply does not fit an encapsulation packet: the originator is
	// told so rather than left to time out.
	ss.s.log.Warn("reply too large", "error", err, "octets", len(b))
	b, _ = tooLarge(resp.Service).Encode()
	data, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: b}}}.Encode()
	ss.replyData(pkt.Header, data)
}

// tooLarge is the response of service svc whose reply does not fit.
func tooLarge(svc cip.Service) cip.Response {
	return cip.Response{Service: svc, Status: cip.StatusReplyDataTooLarge}
}

// handleMessage decodes and dispatches a message; a message that does not
// decode is answered with an error status.
func (s *Server) handleMessage(ctx context.Context, b []byte, remote net.Addr, connected bool) cip.Response {
	req, err := cip.DecodeRequest(b)
	if err != nil {
		if m := s.opts.metrics; m != nil {
			m.OnDecodeError(remote, err)
		}
		var svc cip.Service
		if len(b) > 0 {
			svc = cip.Service(b[0]) &^ cip.ReplyBit
		}
		st := cip.StatusPathSegmentError
		if errors.Is(err, cip.ErrTruncated) && len(b) < 2 {
			st = cip.StatusNotEnoughData
		} else if errors.Is(err, cip.ErrTruncated) {
			st = cip.StatusPathSizeInvalid
		}
		return cip.Response{Service: svc, Status: st}
	}
	return s.dispatch(ctx, req, remote, connected)
}

// maxConnectedReply is the largest reply a SendUnitData carries: the
// encapsulation data less the interface handle (4), timeout (2), item
// count (2), the connected address item (4 + 4), the data item header (4)
// and the sequence count (2).
const maxConnectedReply = encap.MaxData - 4 - 2 - 2 - 8 - 4 - 2

func (ss *session) sendUnitData(pkt encap.Packet) {
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		ss.decodeError(err)
		ss.reply(pkt.Header, encap.StatusIncorrectData, nil)
		return
	}
	addr, ok1 := encap.Find(rr.Items, encap.ItemConnectedAddress)
	data, ok2 := encap.Find(rr.Items, encap.ItemConnectedData)
	id, err := encap.DecodeConnectedAddress(addr)
	if !ok1 || !ok2 || err != nil || len(data.Data) < 2 {
		ss.reply(pkt.Header, encap.StatusIncorrectData, nil)
		return
	}
	cn := ss.s.cm.explicitConn(id, ss)
	if cn == nil {
		// No reply: the connection is unknown (closed or timed out); the
		// originator times out and reopens it.
		ss.s.log.Debug("SendUnitData for an unknown connection", "connection", id)
		return
	}
	seq := binary.LittleEndian.Uint16(data.Data)
	resp, ok := cn.request(seq, func() []byte {
		ctx := context.WithValue(ss.s.ctx, exchangeKey{}, &exchange{sess: ss, items: rr.Items, maxReply: max(cn.toSize-6, 0)})
		r := ss.s.handleMessage(ctx, data.Data[2:], ss.remote, true)
		b, err := r.Encode()
		// The T->O connection size bounds what the target sends on the
		// connection, sequence count included: a reply beyond it is
		// answered with 0x11 (reply data too large), which always fits
		// (Forward_Open accepts no smaller size).
		if err == nil && len(b) <= min(cn.toSize-2, maxConnectedReply) {
			return b
		}
		ss.s.log.Warn("response not sent", "error", err, "octets", len(b), "connection size", cn.toSize)
		b, _ = tooLarge(r.Service).Encode()
		return b
	})
	if !ok {
		return
	}
	payload := binary.LittleEndian.AppendUint16(make([]byte, 0, 2+len(resp)), seq)
	payload = append(payload, resp...)
	out, err := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(cn.info.TOConnID), {Type: encap.ItemConnectedData, Data: payload}}}.Encode()
	if err != nil {
		return
	}
	ss.replyData(pkt.Header, out)
}

// listIdentity returns the data of a ListIdentity reply; local is the
// address the request arrived on.
func (s *Server) listIdentity(local net.Addr) []byte {
	id := s.identity.get()
	port := uint16(encap.TCPPort)
	s.mu.Lock()
	if s.tcp != nil {
		if ta, ok := s.tcp.Addr().(*net.TCPAddr); ok {
			port = ta.AddrPort().Port()
		}
	}
	s.mu.Unlock()
	item := encap.IdentityItem{
		ProtocolVersion: encap.ProtocolVersion,
		Socket:          encap.SockaddrOf(netip.AddrPortFrom(s.localIP(local), port)),
		Identity:        id,
	}
	b, err := item.Encode()
	if err != nil {
		s.log.Warn("identity item not encoded", "error", err)
		b = nil
	}
	out, _ := encap.AppendCPF(nil, []encap.Item{{Type: encap.ItemListIdentity, Data: b}})
	return out
}

func listServices() []byte {
	b, _ := encap.ServiceItem{Version: 1, Capabilities: encap.CapabilityTCP | encap.CapabilityUDP, Name: "Communications"}.Encode()
	out, _ := encap.AppendCPF(nil, []encap.Item{{Type: encap.ItemListServices, Data: b}})
	return out
}

func (s *Server) serveUDP(c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt, err := encap.Decode(buf[:n])
		if err != nil || pkt.Options != 0 {
			continue
		}
		var data []byte
		switch pkt.Command {
		case encap.CommandListIdentity:
			data = s.listIdentity(replyAddr(c, from))
		case encap.CommandListServices:
			data = listServices()
		case encap.CommandListInterfaces:
			data = []byte{0, 0}
		default:
			continue
		}
		h := pkt.Header
		h.Status, h.Session = encap.StatusSuccess, 0
		out, err := encap.Packet{Header: h, Data: data}.Encode()
		if err != nil {
			continue
		}
		delay := s.discoveryDelay(pkt)
		if delay == 0 {
			_, _ = c.WriteToUDPAddrPort(out, from)
			continue
		}
		// Delayed replies wait in timers: a flood of requests asking for
		// a delay is bounded by dropping those beyond maxPendingDiscovery.
		if s.pendingDiscovery.Add(1) > maxPendingDiscovery {
			s.pendingDiscovery.Add(-1)
			continue
		}
		time.AfterFunc(delay, func() { s.sendDelayed(c, out, from) })
	}
}

// sendDelayed sends a delayed discovery reply and releases its slot.
func (s *Server) sendDelayed(c *net.UDPConn, out []byte, to netip.AddrPort) {
	defer s.pendingDiscovery.Add(-1)
	_, _ = c.WriteToUDPAddrPort(out, to)
}

// maxPendingDiscovery bounds the delayed UDP ListIdentity replies waiting
// to be sent; requests beyond it are not answered.
const maxPendingDiscovery = 256

// discoveryDelay returns the random delay before a UDP ListIdentity reply:
// up to the maximum the request asks for in the first two octets of its
// sender context, bounded by WithDiscoveryDelay.
func (s *Server) discoveryDelay(pkt encap.Packet) time.Duration {
	if pkt.Command != encap.CommandListIdentity || s.opts.discoveryDelayMax <= 0 {
		return 0
	}
	maxD := time.Duration(binary.LittleEndian.Uint16(pkt.Context[:])) * time.Millisecond
	if maxD == 0 || maxD > s.opts.discoveryDelayMax {
		maxD = s.opts.discoveryDelayMax
	}
	us := int64(maxD / time.Microsecond)
	if us <= 0 || us > math.MaxUint32 {
		return 0
	}
	return time.Duration(uint32(s.jitter()&0xFFFFFFFF)%uint32(us)) * time.Microsecond
}

// jitter returns the next value of a splitmix64 sequence whose state is
// seeded from crypto/rand when the server is made. Spreading discovery
// replies needs no unpredictability, only no seed shared between devices,
// and no allocation per reply (crypto/rand.Read allocates on Linux).
func (s *Server) jitter() uint64 {
	z := s.jitterState.Add(0x9E3779B97F4A7C15)
	z = (z ^ z>>30) * 0xBF58476D1CE4E5B9
	z = (z ^ z>>27) * 0x94D049BB133111EB
	return z ^ z>>31
}

// replyAddr returns the local address of a UDP socket as seen by from: a
// socket bound to all interfaces reports the address of the interface
// that routes to from, as found by connecting a UDP socket (which sends
// nothing).
func replyAddr(c *net.UDPConn, from netip.AddrPort) net.Addr {
	local := c.LocalAddr()
	if ua, ok := local.(*net.UDPAddr); ok && !ua.IP.IsUnspecified() {
		return local
	}
	probe, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(from))
	if err != nil {
		return local
	}
	defer func() { _ = probe.Close() }()
	return probe.LocalAddr()
}
