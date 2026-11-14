// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/implicit"
	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// The application's code that does not return normally: the server logs
// it with its stack at Error level, answers a request whose handler it was
// with general status 0x10 (device state conflict), and goes on.

// stopAbnormally ends the application's code that calls it without a
// normal return.
func stopAbnormally() { panic(errors.New("stopped by test")) }

// recLogger records the entries of a server.
type recLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLogger) add(level, f string, a []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(f, a...))
}
func (l *recLogger) Debugf(f string, a ...any) { l.add("DEBUG", f, a) }
func (l *recLogger) Infof(f string, a ...any)  { l.add("INFO", f, a) }
func (l *recLogger) Warnf(f string, a ...any)  { l.add("WARN", f, a) }
func (l *recLogger) Errorf(f string, a ...any) { l.add("ERROR", f, a) }

// failed returns the number of Error entries, with their stack, of the
// application's code named name that did not return normally.
func (l *recLogger) failed(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.lines {
		if strings.HasPrefix(e, "ERROR ") && strings.Contains(e, "application code did not return normally callback="+name+" ") &&
			strings.Contains(e, "value=stopped by test") && strings.Contains(e, "stopAbnormally") {
			n++
		}
	}
	return n
}

// stoppingObject is an application Object whose ServeCIP does not return
// normally.
type stoppingObject struct{}

func (stoppingObject) Class() cip.Class { return 0x66 }
func (stoppingObject) ServeCIP(context.Context, *Request) cip.Response {
	stopAbnormally()
	return cip.Response{}
}

// TestHandlerDoesNotReturnNormally: for each kind of request handler, the
// request is answered with 0x10, the failure is logged under the name of
// the call site, and the session answers its next request.
func TestHandlerDoesNotReturnNormally(t *testing.T) {
	stopping := func(context.Context, *Request) cip.Response { stopAbnormally(); return cip.Response{} }
	for _, tc := range []struct {
		name  string
		setup func(*Server)
		req   cip.Request
		site  string
	}{
		{"ServiceFunc", func(s *Server) {
			o := NewObject(0x65, 1)
			o.AddInstance(1)
			o.HandleService(0x4B, stopping)
			s.RegisterObject(o)
		}, cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)}, "Object.ServeCIP"},
		{"Attribute.Get", func(s *Server) {
			o := NewObject(0x65, 1)
			o.AddInstance(1).SetAttribute(1, Attribute{Get: func() []byte { stopAbnormally(); return nil }})
			s.RegisterObject(o)
		}, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(0x65, 1, 1)}, "Object.ServeCIP"},
		{"Attribute.Set", func(s *Server) {
			o := NewObject(0x65, 1)
			o.AddInstance(1).SetAttribute(1, Attribute{Get: func() []byte { return []byte{0} },
				Set: func([]byte) cip.GeneralStatus { stopAbnormally(); return 0 }})
			s.RegisterObject(o)
		}, cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(0x65, 1, 1), Data: []byte{1}}, "Object.ServeCIP"},
		{"Object.ServeCIP", func(s *Server) { s.RegisterObject(stoppingObject{}) },
			cip.Request{Service: 0x4B, Path: cip.ObjectPath(0x66, 1)}, "Object.ServeCIP"},
		{"SymbolHandler", func(s *Server) { s.HandleSymbols(symbolFunc(stopping)) },
			cip.Request{Service: 0x4C, Path: cip.Path{cip.SymbolSegment{Name: "tag"}}}, "SymbolHandler.ServeSymbol"},
		{"Assembly.OnWrite", func(s *Server) { s.Assembly(asmOut).OnWrite(func([]byte, bool) { stopAbnormally() }) },
			cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(cip.ClassAssembly, asmOut, 3), Data: make([]byte, asmSize)}, "Assembly.OnWrite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &recLogger{}
			s := startIOServer(t, WithLogger(log))
			tc.setup(s)
			p := dialPeer(t, s)
			p.register()
			if r := p.do(tc.req); r.Status != cip.StatusDeviceStateConflict || r.Service != tc.req.Service {
				t.Errorf("answer %s for service %v, want 0x10 for %v", r.Status, r.Service, tc.req.Service)
			}
			if n := log.failed(tc.site); n != 1 {
				t.Errorf("%d Error entries for %s, want 1", n, tc.site)
			}
			// The session goes on.
			if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
				t.Errorf("next request: %s", r.Status)
			}
		})
	}
}

// TestResetHandlerDoesNotReturnNormally: a Reset whose handler does not
// return normally is answered with 0x10.
func TestResetHandlerDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	s := startServer(t, WithLogger(log), WithResetHandler(func(uint8) cip.GeneralStatus { stopAbnormally(); return 0 }))
	p := dialPeer(t, s)
	p.register()
	if r := p.do(cip.Request{Service: cip.ServiceReset, Path: cip.ObjectPath(cip.ClassIdentity, 1)}); r.Status != cip.StatusDeviceStateConflict {
		t.Errorf("Reset: %s, want 0x10", r.Status)
	}
	if n := log.failed("Object.ServeCIP"); n != 1 {
		t.Errorf("%d Error entries, want 1", n)
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Errorf("next request: %s", r.Status)
	}
}

// TestMultipleServiceHandlerDoesNotReturnNormally: within a Multiple
// Service Packet, the service whose handler does not return normally is
// answered with 0x10 and the other services are carried out.
func TestMultipleServiceHandlerDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	s := startServer(t, WithLogger(log))
	o := NewObject(0x65, 1)
	o.AddInstance(1)
	o.HandleService(0x4B, func(context.Context, *Request) cip.Response { stopAbnormally(); return cip.Response{} })
	s.RegisterObject(o)
	p := dialPeer(t, s)
	p.register()
	data, err := cip.EncodeMultipleService([]cip.Request{
		{Service: 0x4B, Path: cip.ObjectPath(0x65, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := p.do(cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: data})
	if r.Status != cip.StatusEmbeddedServiceError {
		t.Fatalf("Multiple Service Packet: %s, want an embedded service error", r.Status)
	}
	parts, err := cip.SplitMultiple(r.Data)
	if err != nil || len(parts) != 2 {
		t.Fatalf("%d replies, %v", len(parts), err)
	}
	first, err1 := cip.DecodeResponse(parts[0])
	second, err2 := cip.DecodeResponse(parts[1])
	if err1 != nil || err2 != nil || first.Status != cip.StatusDeviceStateConflict || !second.OK() {
		t.Errorf("replies %s (%v), %s (%v); want 0x10 and success", first.Status, err1, second.Status, err2)
	}
	if n := log.failed("Object.ServeCIP"); n != 1 {
		t.Errorf("%d Error entries, want 1", n)
	}
}

// TestConfigurationOnWriteDoesNotReturnNormally: a Forward_Open whose
// configuration data's OnWrite does not return normally is refused with
// 0x10, no connection is left, and the data stays written; the next
// Forward_Open succeeds.
func TestConfigurationOnWriteDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	m := newRecMetrics()
	s := startIOServer(t, WithLogger(log), WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	cfg := s.Assembly(asmCfg)
	cfg.OnWrite(func([]byte, bool) { stopAbnormally() })
	sock := newIOSocket(t)
	fo := fwdOpen(1, cip.TriggerCyclic, append(ioPath(asmCfg, asmOut, asmIn), cip.DataSegment{Data: []byte{1, 2, 3, 4}}))
	if r, _ := p.open(fo, sock.sockaddrTO()); r.Status != cip.StatusDeviceStateConflict {
		t.Fatalf("Forward_Open: %s %x, want 0x10", r.Status, r.Extended)
	}
	if n := log.failed("Assembly.OnWrite"); n != 1 {
		t.Errorf("%d Error entries, want 1", n)
	}
	if n := len(s.Connections()); n != 0 {
		t.Errorf("%d connections after the refused Forward_Open", n)
	}
	if !bytes.Equal(cfg.Data(), []byte{1, 2, 3, 4}) {
		t.Errorf("configuration data = %x", cfg.Data())
	}
	if !m.with(func(m *recMetrics) bool { return len(m.opened) == 0 }) {
		t.Error("the refused connection was reported opened")
	}
	cfg.OnWrite(nil)
	p.mustOpen(fwdOpen(1, cip.TriggerCyclic, append(ioPath(asmCfg, asmOut, asmIn), cip.DataSegment{Data: []byte{5, 6, 7, 8}})), sock.sockaddrTO())
}

// TestIOOnWriteDoesNotReturnNormally: the output assembly's OnWrite that
// does not return normally for I/O data is logged, and the connection goes
// on: the next datagram is written too.
func TestIOOnWriteDoesNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	s := startIOServer(t, WithLogger(log))
	p := dialPeer(t, s)
	p.register()
	out := s.Assembly(asmOut)
	writes := make(chan byte, 16)
	out.OnWrite(func(data []byte, _ bool) {
		writes <- data[0]
		if data[0] == 1 {
			stopAbnormally()
		}
	})
	sock := newIOSocket(t)
	reply, _ := p.mustOpen(fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn)), sock.sockaddrTO())
	for seq := uint32(1); seq <= 2; seq++ {
		payload := implicit.AppendPayload(nil, 1, implicit.FormatHeader32,
			implicit.Payload{SeqCount: uint16(seq), Header: implicit.RunBit, Data: []byte{byte(seq), 0, 0, 0, 0, 0, 0, 0}})
		sock.sendIO(s, reply.OTConnID, seq, payload)
	}
	for want := byte(1); want <= 2; want++ {
		select {
		case b := <-writes:
			if b != want {
				t.Fatalf("OnWrite with %d, want %d", b, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("OnWrite not called for datagram %d", want)
		}
	}
	if n := log.failed("Assembly.OnWrite"); n != 1 {
		t.Errorf("%d Error entries, want 1", n)
	}
	if n := len(s.Connections()); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

// stoppingMetrics implements every metrics interface of the server; each
// method records its call and does not return normally.
type stoppingMetrics struct {
	mu    sync.Mutex
	calls map[string]int
}

func (m *stoppingMetrics) stop(name string) {
	m.mu.Lock()
	m.calls[name]++
	m.mu.Unlock()
	stopAbnormally()
}

func (m *stoppingMetrics) called(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[name]
}

func (m *stoppingMetrics) OnConnect(net.Addr)                        { m.stop("Metrics.OnConnect") }
func (m *stoppingMetrics) OnDisconnect(net.Addr, error)              { m.stop("Metrics.OnDisconnect") }
func (m *stoppingMetrics) OnPacketSent(net.Addr, encap.Command, int) { m.stop("Metrics.OnPacketSent") }
func (m *stoppingMetrics) OnPacketReceived(net.Addr, encap.Command, int) {
	m.stop("Metrics.OnPacketReceived")
}
func (m *stoppingMetrics) OnDecodeError(net.Addr, error) { m.stop("Metrics.OnDecodeError") }
func (m *stoppingMetrics) OnHandled(net.Addr, cip.Service, cip.GeneralStatus, time.Duration) {
	m.stop("ServerMetrics.OnHandled")
}
func (m *stoppingMetrics) OnConnectionOpened(net.Addr, ethernetip.ConnectionInfo) {
	m.stop("ServerMetrics.OnConnectionOpened")
}
func (m *stoppingMetrics) OnConnectionClosed(net.Addr, ethernetip.ConnectionInfo, error) {
	m.stop("ServerMetrics.OnConnectionClosed")
}
func (m *stoppingMetrics) OnIOSent(uint32, int)         { m.stop("IOMetrics.OnIOSent") }
func (m *stoppingMetrics) OnIOReceived(uint32, int)     { m.stop("IOMetrics.OnIOReceived") }
func (m *stoppingMetrics) OnIODropped(net.Addr, string) { m.stop("IOMetrics.OnIODropped") }

// TestMetricsDoNotReturnNormally: every metrics hook of the server that
// does not return normally is logged, and the server answers as without
// metrics: requests, a malformed request, an I/O connection opened, used
// and closed, and the end of the session.
func TestMetricsDoNotReturnNormally(t *testing.T) {
	log := &recLogger{}
	m := &stoppingMetrics{calls: map[string]int{}}
	s := startIOServer(t, WithLogger(log), WithMetrics(m))
	p := dialPeer(t, s)
	p.register()
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Errorf("request: %s", r.Status)
	}
	// A request too short to decode: answered, and a decode error.
	if r, _ := p.rrData(nil); r.Status != cip.StatusNotEnoughData {
		t.Errorf("empty message: %s", r.Status)
	}
	sock := newIOSocket(t)
	fo := fwdOpen(1, cip.TriggerCyclic, ioPath(0, asmOut, asmIn))
	reply, _ := p.mustOpen(fo, sock.sockaddrTO())
	sock.recv(reply.TOConnID, nil)
	writes := make(chan struct{}, 16)
	s.Assembly(asmOut).OnWrite(func([]byte, bool) { writes <- struct{}{} })
	// A datagram for no connection, then one for the connection: dropped,
	// then received.
	sock.sendIO(s, 0x7FFF_FFFF, 1, []byte{0, 0})
	sock.sendIO(s, reply.OTConnID, 1, implicit.AppendPayload(nil, 1, implicit.FormatHeader32,
		implicit.Payload{SeqCount: 1, Header: implicit.RunBit, Data: make([]byte, asmSize)}))
	select {
	case <-writes:
	case <-time.After(5 * time.Second):
		t.Fatal("I/O data not written")
	}
	if r := p.close(fo.Triad, fo.Path); !r.OK() {
		t.Errorf("Forward_Close: %s", r.Status)
	}
	// The originator ends the session.
	_ = p.c.Close()
	waitFor(t, "the end of the session", func() bool { return s.Sessions() == 0 })
	// OnDisconnect is the session goroutine's last call, logged before the
	// goroutine ends: every hook of the session has been called and logged
	// once it has ended.
	testenv.NoGoroutine(t, "server.(*Server).serveConn")
	for _, name := range []string{
		"Metrics.OnConnect", "Metrics.OnPacketReceived", "Metrics.OnPacketSent", "Metrics.OnDecodeError",
		"Metrics.OnDisconnect", "ServerMetrics.OnHandled", "ServerMetrics.OnConnectionOpened",
		"ServerMetrics.OnConnectionClosed", "IOMetrics.OnIOSent", "IOMetrics.OnIOReceived", "IOMetrics.OnIODropped",
	} {
		called, logged := m.called(name), log.failed(name)
		if called == 0 || logged != called {
			t.Errorf("%s: called %d times, %d Error entries", name, called, logged)
		}
	}
}
