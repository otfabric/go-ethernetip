// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
)

// pipeListener hands the server the far ends of in-memory connections.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 44818} }

// dial returns the near end of a new connection to the server.
func (l *pipeListener) dial() (net.Conn, error) {
	near, far := net.Pipe()
	select {
	case l.conns <- far:
		return near, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-time.After(5 * time.Second):
		return nil, errors.New("server does not accept")
	}
}

// fuzzStreamSeeds are octet streams an originator sends: a session, explicit
// requests, a Class 3 connection, Multiple Service Packets, malformed
// encapsulation.
func fuzzStreamSeeds(f *testing.F) [][]byte {
	pkt := func(cmd encap.Command, session uint32, data []byte) []byte {
		b, err := encap.Packet{Header: encap.Header{Command: cmd, Session: session}, Data: data}.Encode()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	rr := func(req cip.Request) []byte {
		msg, err := req.Encode()
		if err != nil {
			f.Fatal(err)
		}
		d, _ := encap.RRData{Items: []encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}}.Encode()
		return d
	}
	reg := pkt(encap.CommandRegisterSession, 0, encap.Register{ProtocolVersion: 1}.Encode())
	// The session handle is random: the fuzzer's SendRRData use handle 0,
	// which the server refuses, unless it finds that a wrong handle is
	// handled as well as a right one. The seeds also cover the commands
	// that need no session.
	msp, _ := cip.EncodeMultipleService([]cip.Request{
		{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassTCPIPInterface, 1, 13)},
	})
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fod, _ := fo.Encode()
	cat := func(bs ...[]byte) []byte {
		var out []byte
		for _, b := range bs {
			out = append(out, b...)
		}
		return out
	}
	return [][]byte{
		reg,
		cat(reg, pkt(encap.CommandListIdentity, 0, nil), pkt(encap.CommandListServices, 0, nil), pkt(encap.CommandListInterfaces, 0, nil)),
		cat(reg, pkt(encap.CommandSendRRData, 0, rr(cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassIdentity, 1)}))),
		cat(reg, pkt(encap.CommandSendRRData, 0, rr(cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: msp}))),
		cat(reg, pkt(encap.CommandSendRRData, 0, rr(cip.Request{Service: cip.ServiceForwardOpen, Path: cip.ConnectionManagerPath(), Data: fod}))),
		cat(reg, pkt(encap.CommandUnRegisterSession, 0, nil)),
		pkt(encap.CommandNOP, 0, make([]byte, 30)),
		pkt(0x7777, 0, []byte{1, 2, 3}),
		encap.Header{Command: encap.CommandSendRRData, Length: 0xFFFF}.AppendTo(nil),
		reg[:13],
	}
}

// FuzzServerStream feeds arbitrary octet streams to a server over an
// in-memory connection, as a hostile originator would send them. The
// server must not panic, must answer with a bounded amount of data, must
// release the connection when the originator goes, and must keep serving
// other originators.
func FuzzServerStream(f *testing.F) {
	for _, s := range fuzzStreamSeeds(f) {
		f.Add(s, false)
		f.Add(s, true)
	}
	s, err := New(WithMaxPacket(4096), WithInactivityTimeout(time.Second))
	if err != nil {
		f.Fatal(err)
	}
	addAssemblies(f, s)
	ep, err := implicit.Listen("127.0.0.1:0")
	if err != nil {
		f.Fatal(err)
	}
	l := newPipeListener()
	if err := s.UseListeners(l, nil, ep); err != nil {
		f.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	f.Cleanup(func() {
		_ = s.Close()
		if err := <-served; !errors.Is(err, ethernetip.ErrClosed) {
			f.Errorf("Serve: %v", err)
		}
		_ = ep.Close()
	})

	// The server writes at most this much in reply to one stream: every
	// packet (at least 24 octets in) is answered with at most one reply
	// of at most 64 KiB.
	const maxReply = 64 << 10

	f.Fuzz(func(t *testing.T, in []byte, patch bool) {
		if len(in) > 64<<10 {
			return
		}
		began := time.Now()
		defer func() {
			if d := time.Since(began); d > 3*time.Second && !t.Failed() {
				buf := make([]byte, 1<<20)
				t.Fatalf("one stream of %d octets took %v\n%s", len(in), d, buf[:runtime.Stack(buf, true)])
			}
		}()
		c, err := l.dial()
		if err != nil {
			buf := make([]byte, 1<<20)
			t.Fatalf("%v\n%s", err, buf[:runtime.Stack(buf, true)])
		}
		defer func() { _ = c.Close() }()
		var got, replies int
		var handle uint32
		var hmu sync.Mutex
		readDone := make(chan error, 1)
		go func() {
			var buf []byte
			for {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				pkt, nb, err := encap.ReadPacket(c, buf, 0)
				buf = nb
				if err != nil {
					readDone <- err
					return
				}
				hmu.Lock()
				got += encap.HeaderSize + len(pkt.Data)
				replies++
				if pkt.Command == encap.CommandRegisterSession && pkt.Status == encap.StatusSuccess {
					handle = pkt.Session
				}
				hmu.Unlock()
			}
		}()
		// With patch, the session handle of each packet after the
		// registration is set to the one the server assigned, so that the
		// fuzzer reaches the session's commands.
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		rest := in
		for len(rest) > 0 {
			if patch && len(rest) >= encap.HeaderSize {
				n := encap.HeaderSize + int(binary.LittleEndian.Uint16(rest[2:]))
				n = min(n, len(rest))
				chunk := append([]byte(nil), rest[:n]...)
				hmu.Lock()
				h, seen := handle, replies
				hmu.Unlock()
				if h != 0 {
					binary.LittleEndian.PutUint32(chunk[4:], h)
				}
				if _, err := c.Write(chunk); err != nil {
					break
				}
				rest = rest[n:]
				if h == 0 && len(chunk) == n && binary.LittleEndian.Uint16(chunk) == uint16(encap.CommandRegisterSession) &&
					binary.LittleEndian.Uint32(chunk[20:]) == 0 {
					// Wait for the reply (and its handle) before the next
					// packet.
					deadline := time.Now().Add(200 * time.Millisecond)
					for time.Now().Before(deadline) {
						hmu.Lock()
						more := replies > seen
						hmu.Unlock()
						if more {
							break
						}
						time.Sleep(50 * time.Microsecond)
					}
				}
				continue
			}
			if _, err := c.Write(rest); err != nil {
				break
			}
			rest = nil
		}
		// A fence: when the stream ended on a packet boundary the fence is
		// answered; either way the connection is then closed by us.
		fence, _ := encap.Packet{Header: encap.Header{Command: encap.CommandNOP}}.Encode()
		_, _ = c.Write(fence)
		_ = c.Close()
		select {
		case err := <-readDone:
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("server neither answered nor closed within 5 s")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("reader stuck")
		}
		hmu.Lock()
		total := got
		hmu.Unlock()
		packets := len(in)/encap.HeaderSize + 1
		if total > packets*maxReply {
			t.Fatalf("%d octets in reply to %d octets", total, len(in))
		}
		// The server lets go of the connection.
		deadline := time.Now().Add(5 * time.Second)
		for s.Sessions() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%d sessions left after the originator went", s.Sessions())
			}
			time.Sleep(100 * time.Microsecond)
		}
		if n := len(s.Connections()); n > 0 {
			// Class 3 connections end with their session; I/O ones the
			// stream may have opened time out, and are closed here so
			// that they do not pile up.
			s.cm.closeAll(nil)
		}
	})
}
