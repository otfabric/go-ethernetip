// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/server"
)

func TestOptionValidation(t *testing.T) {
	cases := map[string]Option{
		"nil dialer":       WithDialer(nil),
		"nil tls":          WithTLS(nil),
		"zero timeout":     WithTimeout(0),
		"route segment":    WithRoute(cip.Path{cip.ClassSegment(1)}),
		"max pending 0":    WithMaxPending(0),
		"max pending 1025": WithMaxPending(1025),
		"max packet 63":    WithMaxPacket(63),
		"max packet big":   WithMaxPacket(65536),
	}
	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New("127.0.0.1", opt); !errors.Is(err, ethernetip.ErrInvalidOption) {
				t.Fatalf("New = %v, want ErrInvalidOption", err)
			}
			if _, err := Dial(context.Background(), "127.0.0.1", opt); !errors.Is(err, ethernetip.ErrInvalidOption) {
				t.Fatalf("Dial = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c, err := New("192.0.2.1", WithLogger(ethernetip.NopLogger()), WithOriginator(0x1234, 0xABCD))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr() != "192.0.2.1:44818" {
		t.Errorf("Addr = %q", c.Addr())
	}
	tr := c.NewTriad()
	if tr.VendorID != 0x1234 || tr.OriginatorSerial != 0xABCD {
		t.Errorf("triad %v", tr)
	}
	if c.NewTriad().Serial != tr.Serial+1 {
		t.Error("connection serial numbers are not consecutive")
	}
	if c.State() != ethernetip.StateDisconnected || c.Session() != 0 || c.RemoteAddr() != nil || c.LocalAddr() != nil {
		t.Error("an unconnected client reports a session")
	}
	ct, err := New("192.0.2.1", WithTLS(&tls.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	if ct.Addr() != "192.0.2.1:2221" {
		t.Errorf("TLS Addr = %q", ct.Addr())
	}
	d, _ := New("192.0.2.1")
	if d.opts.vendorID != DefaultVendorID || d.opts.origSerial&1 == 0 {
		t.Errorf("default originator %#x/%#x", d.opts.vendorID, d.opts.origSerial)
	}
	if id := NewConnectionID(); id&1 == 0 {
		t.Errorf("connection ID %#x is even", id)
	}
}

func TestLifecycleAgainstServer(t *testing.T) {
	var resets []uint8
	var rmu sync.Mutex
	srv, addr := startServer(t, server.WithResetHandler(func(rt uint8) cip.GeneralStatus {
		rmu.Lock()
		resets = append(resets, rt)
		rmu.Unlock()
		return cip.StatusSuccess
	}))
	var states []ethernetip.State
	var smu sync.Mutex
	m := &recMetrics{}
	c, err := Dial(ctxT(t), addr, WithMetrics(m), WithStateHandler(func(s ethernetip.State, _ error) {
		smu.Lock()
		states = append(states, s)
		smu.Unlock()
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := ctxT(t)
	if c.State() != ethernetip.StateConnected || c.Session() == 0 || c.RemoteAddr() == nil || c.LocalAddr() == nil {
		t.Fatal("connected client reports no session")
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect when connected: %v", err)
	}
	id, err := c.Identity(ctx)
	if err != nil || id.VendorID != server.DefaultIdentity.VendorID || id.ProductName != server.DefaultIdentity.ProductName {
		t.Fatalf("Identity = %+v, %v", id, err)
	}
	all, err := c.GetAttributesAll(ctx, cip.ClassIdentity, 1)
	if err != nil || len(all) == 0 {
		t.Fatalf("GetAttributesAll = %x, %v", all, err)
	}
	if err := c.SetAttributesAll(ctx, cip.ClassIdentity, 1, []byte{1}); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Errorf("SetAttributesAll = %v, want ErrUnsupported", err)
	}
	if err := c.Reset(ctx, cip.ClassIdentity, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.Reset(ctx, cip.ClassIdentity, 1, -1); err != nil {
		t.Fatal(err)
	}
	rmu.Lock()
	if len(resets) != 2 || resets[0] != 1 || resets[1] != 0 {
		t.Errorf("reset types %v, want [1 0]", resets)
	}
	rmu.Unlock()
	vals, err := c.GetAttributeList(ctx, cip.ClassIdentity, 1, []uint16{1, 99, 7}, []int{2, 2, 0})
	if st, _ := ethernetip.StatusOf(err); st != cip.StatusAttributeListError {
		t.Fatalf("GetAttributeList status = %v", st)
	}
	if len(vals) != 3 || !bytes.Equal(vals[0].Value, cip.AppendUint16(nil, 0xFFFF)) ||
		vals[1].Status != cip.StatusAttributeNotSupported || vals[2].ID != 7 || len(vals[2].Value) == 0 {
		t.Fatalf("GetAttributeList = %+v", vals)
	}
	li, err := c.ListIdentity(ctx)
	if err != nil || li.ProductName != server.DefaultIdentity.ProductName {
		t.Fatalf("ListIdentity = %+v, %v", li, err)
	}
	svcs, err := c.ListServices(ctx)
	if err != nil || len(svcs) != 1 || svcs[0].Name != "Communications" {
		t.Fatalf("ListServices = %+v, %v", svcs, err)
	}
	ifs, err := c.ListInterfaces(ctx)
	if err != nil || len(ifs) != 0 {
		t.Fatalf("ListInterfaces = %v, %v", ifs, err)
	}
	if srv.Sessions() != 1 {
		t.Errorf("server sessions = %d", srv.Sessions())
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("request after Close = %v, want ErrClosed", err)
	}
	if err := c.Connect(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("Connect after Close = %v, want ErrClosed", err)
	}
	if c.State() != ethernetip.StateDisconnected || c.Session() != 0 {
		t.Error("closed client reports a session")
	}
	eventually(t, 2*time.Second, "server unregisters the session", func() bool { return srv.Sessions() == 0 })

	smu.Lock()
	want := []ethernetip.State{ethernetip.StateConnecting, ethernetip.StateConnected, ethernetip.StateDisconnected}
	if len(states) != 3 || states[0] != want[0] || states[1] != want[1] || states[2] != want[2] {
		t.Errorf("states %v, want %v", states, want)
	}
	smu.Unlock()
	s := m.snapshot()
	if s.connects != 1 || len(s.disconnects) != 1 || s.disconnects[0] != nil {
		t.Errorf("connects %d disconnects %v", s.connects, s.disconnects)
	}
	if s.sent == 0 || s.recv == 0 || len(s.requests) != len(s.done) || len(s.requests) < 6 {
		t.Errorf("metrics %+v", s)
	}
}

func TestTLS(t *testing.T) {
	cfg, pool := selfSigned(t)
	_, addr := startServer(t, server.WithTLS(cfg))
	c := dialT(t, addr, WithTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))
	if _, err := c.Identity(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.sess.conn.(*tls.Conn); !ok {
		t.Error("session is not over TLS")
	}
	// A client that does not trust the certificate fails the handshake.
	_, err := Dial(ctxT(t), addr, WithTLS(&tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))
	if !errors.Is(err, ethernetip.ErrConnectFailed) {
		t.Fatalf("untrusted TLS = %v, want ErrConnectFailed", err)
	}
}

func TestDialFailures(t *testing.T) {
	_, err := Dial(ctxT(t), "127.0.0.1:1", WithDialer(errDialer{errDial}))
	if !errors.Is(err, ethernetip.ErrConnectFailed) || !errors.Is(err, errDial) {
		t.Fatalf("dial error = %v", err)
	}

	type tc struct {
		name  string
		reply func(p *peer, pkt encap.Packet)
		want  error
	}
	cases := []tc{
		{"refused", func(p *peer, pkt encap.Packet) {
			h := pkt.Header
			h.Status = encap.StatusUnsupportedProtocol
			p.send(t, encap.Packet{Header: h, Data: pkt.Data})
		}, ethernetip.ErrSession},
		{"wrong command", func(p *peer, pkt encap.Packet) {
			h := pkt.Header
			h.Command, h.Session = encap.CommandListServices, 5
			p.send(t, encap.Packet{Header: h})
		}, ethernetip.ErrProtocol},
		{"no handle", func(p *peer, pkt encap.Packet) {
			p.send(t, encap.Packet{Header: pkt.Header, Data: pkt.Data})
		}, ethernetip.ErrProtocol},
		{"closed", func(p *peer, _ encap.Packet) { _ = p.conn.Close() }, ethernetip.ErrConnectFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRawTarget(t, c.reply)
			m := &recMetrics{}
			var last error
			_, err := Dial(ctxT(t), f.addr(), WithMetrics(m), WithStateHandler(func(s ethernetip.State, err error) {
				if s == ethernetip.StateDisconnected {
					last = err
				}
			}))
			if !errors.Is(err, ethernetip.ErrConnectFailed) || !errors.Is(err, c.want) {
				t.Fatalf("Dial = %v, want ErrConnectFailed and %v", err, c.want)
			}
			if last == nil {
				t.Error("state handler did not report the failure")
			}
		})
	}

	t.Run("silent", func(t *testing.T) {
		f := newRawTarget(t, nil)
		_, err := Dial(ctxT(t), f.addr(), WithTimeout(50*time.Millisecond))
		if !errors.Is(err, ethernetip.ErrConnectFailed) || !errors.Is(err, ethernetip.ErrTimeout) {
			t.Fatalf("Dial = %v, want ErrConnectFailed and ErrTimeout", err)
		}
	})
}

func TestRoute(t *testing.T) {
	_, addr := startServer(t, server.WithSlot(2))
	route, err := cip.ParseRoute("1/2")
	if err != nil {
		t.Fatal(err)
	}
	c := dialT(t, addr, WithRoute(route))
	ctx := ctxT(t)
	if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
		t.Fatalf("routed request: %v", err)
	}
	if _, err := c.DoRoute(ctx, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}, nil); err != nil {
		t.Fatalf("direct request: %v", err)
	}
	bad, _ := cip.ParseRoute("1/5")
	_, err = c.DoRoute(ctx, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}, bad)
	var ce *ethernetip.CIPError
	if !errors.As(err, &ce) || ce.Service != cip.ServiceUnconnectedSend || ce.Status != cip.StatusConnectionFailure {
		t.Fatalf("misrouted request = %v, want an Unconnected_Send CIPError", err)
	}
	if ext, ok := ce.ExtendedStatus(); !ok || cip.ConnectionStatus(ext) != cip.ConnStatusPortNotAvailable {
		t.Errorf("extended status %#x", ext)
	}
	// Class 3 connections are routed too.
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMaxPendingCorrelation(t *testing.T) {
	const n = 4
	var mu sync.Mutex
	var got []encap.Packet
	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		mu.Lock()
		got = append(got, pkt)
		if len(got) < n {
			mu.Unlock()
			return
		}
		all := got
		got = nil
		mu.Unlock()
		// Answer in reverse order: each reply carries its attribute ID.
		for i := len(all) - 1; i >= 0; i-- {
			req := decodeRR(t, all[i])
			a, _ := req.Path.Attribute()
			rrReply(t, p, all[i], cip.Response{Service: req.Service, Data: cip.AppendUint16(nil, a)})
		}
	})
	c := dialT(t, f.addr(), WithMaxPending(n))
	ctx := ctxT(t)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(a uint16) {
			defer wg.Done()
			b, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, a)
			if err == nil && !bytes.Equal(b, cip.AppendUint16(nil, a)) {
				err = errors.New("attribute " + strconv.Itoa(int(a)) + " got the reply of another request")
			}
			errs <- err
		}(uint16(i))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestReconnect(t *testing.T) {
	srv, addr := startServer(t)
	plain := dialT(t, addr)
	auto := dialT(t, addr, WithAutoReconnect())
	ctx := ctxT(t)
	_ = srv.Close()
	eventually(t, 5*time.Second, "sessions lost", func() bool {
		return plain.State() == ethernetip.StateDisconnected && auto.State() == ethernetip.StateDisconnected
	})
	_, err := plain.Identity(ctx)
	if !errors.Is(err, ethernetip.ErrNotConnected) || !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("request without session = %v, want ErrNotConnected wrapping ErrConnectionLost", err)
	}
	// While the target is down, reconnecting fails.
	if _, err := auto.Identity(ctx); !errors.Is(err, ethernetip.ErrConnectFailed) {
		t.Fatalf("reconnect to a stopped server = %v", err)
	}
	srv2, err := server.New(server.WithIOAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Listen(addr); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv2.Serve() }()
	t.Cleanup(func() { _ = srv2.Close() })
	if _, err := auto.Identity(ctx); err != nil {
		t.Fatalf("request after restart with auto-reconnect: %v", err)
	}
	if auto.State() != ethernetip.StateConnected {
		t.Error("auto-reconnected client not connected")
	}
	if _, err := plain.Identity(ctx); !errors.Is(err, ethernetip.ErrNotConnected) {
		t.Errorf("client without auto-reconnect = %v", err)
	}
	if err := plain.Connect(ctx); err != nil {
		t.Fatalf("explicit Connect: %v", err)
	}
	if _, err := plain.Identity(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	f := newFakeTarget(t, nil) // registers, then never answers
	c := dialT(t, f.addr(), WithTimeout(50*time.Millisecond))
	_, err := c.Identity(context.Background())
	if !errors.Is(err, ethernetip.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent target = %v, want ErrTimeout", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	c2 := dialT(t, f.addr(), WithTimeout(10*time.Second))
	_, err = c2.Identity(ctx)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("canceled request = %v, want context.Canceled", err)
	}
	// A request waiting for its turn times out too.
	c3 := dialT(t, f.addr(), WithTimeout(10*time.Second))
	first := make(chan error, 1)
	long, cancelLong := context.WithCancel(context.Background())
	defer cancelLong()
	go func() { _, err := c3.Identity(long); first <- err }()
	eventually(t, 2*time.Second, "first request pending", func() bool { return len(c3.turn) == 1 })
	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if _, err := c3.Identity(short); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("queued request = %v, want ErrTimeout", err)
	}
	cancelLong()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first request = %v", err)
	}
}

func TestConnectionLost(t *testing.T) {
	f := newFakeTarget(t, func(p *peer, _ encap.Packet) { _ = p.conn.Close() })
	m := &recMetrics{}
	lost := make(chan error, 4)
	c := dialT(t, f.addr(), WithMetrics(m), WithStateHandler(func(s ethernetip.State, err error) {
		if s == ethernetip.StateDisconnected {
			lost <- err
		}
	}))
	_, err := c.Identity(ctxT(t))
	if !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("request = %v, want ErrConnectionLost", err)
	}
	if err := <-lost; !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Errorf("state handler error = %v", err)
	}
	eventually(t, 2*time.Second, "disconnect metric", func() bool { return len(m.snapshot().disconnects) == 1 })
	if d := m.snapshot().disconnects[0]; !errors.Is(d, ethernetip.ErrConnectionLost) {
		t.Errorf("OnDisconnect error = %v", d)
	}
}

// failConn is a net.Conn whose writes fail once armed.
type failConn struct {
	net.Conn
	fail *atomic.Bool
}

func (c failConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("write failed by test")
	}
	return c.Conn.Write(b)
}

type failDialer struct{ fail *atomic.Bool }

func (d failDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return failConn{Conn: c, fail: d.fail}, nil
}

func TestWriteFailure(t *testing.T) {
	_, addr := startServer(t)
	fail := &atomic.Bool{}
	c := dialT(t, addr, WithDialer(failDialer{fail}))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("connected write failure = %v", err)
	}

	c2 := dialT(t, addr, WithDialer(failDialer{&atomic.Bool{}}))
	c2.sess.conn.(failConn).fail.Store(true)
	if _, err := c2.Identity(ctx); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("unconnected write failure = %v", err)
	}
}

// replyWith returns a handler that answers each SendRRData with the
// packet build returns.
func replyWith(t *testing.T, build func(req encap.Packet) encap.Packet) func(*peer, encap.Packet) {
	return func(p *peer, pkt encap.Packet) { p.send(t, build(pkt)) }
}

func TestMalformedReplies(t *testing.T) {
	rr := func(items ...encap.Item) []byte {
		b, err := encap.RRData{Items: items}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	resp := func(r cip.Response) []byte { b, _ := r.Encode(); return b }
	cases := []struct {
		name  string
		build func(req encap.Packet) encap.Packet
		want  error
	}{
		{"encap status", func(req encap.Packet) encap.Packet {
			h := req.Header
			h.Status = encap.StatusInvalidSessionHandle
			return encap.Packet{Header: h}
		}, ethernetip.ErrSession},
		{"unsupported command", func(req encap.Packet) encap.Packet {
			h := req.Header
			h.Status = encap.StatusInvalidCommand
			return encap.Packet{Header: h}
		}, ethernetip.ErrUnsupported},
		{"wrong command", func(req encap.Packet) encap.Packet {
			h := req.Header
			h.Command = encap.CommandListServices
			return encap.Packet{Header: h}
		}, ethernetip.ErrProtocol},
		{"bad RR data", func(req encap.Packet) encap.Packet {
			return encap.Packet{Header: req.Header, Data: []byte{1, 2}}
		}, ethernetip.ErrProtocol},
		{"no unconnected item", func(req encap.Packet) encap.Packet {
			return encap.Packet{Header: req.Header, Data: rr(encap.Item{Type: encap.ItemNullAddress})}
		}, ethernetip.ErrProtocol},
		{"bad CIP response", func(req encap.Packet) encap.Packet {
			return encap.Packet{Header: req.Header, Data: rr(encap.Item{Type: encap.ItemNullAddress}, encap.Item{Type: encap.ItemUnconnectedData, Data: []byte{0x0E}})}
		}, ethernetip.ErrProtocol},
		{"other service", func(req encap.Packet) encap.Packet {
			return encap.Packet{Header: req.Header, Data: rr(encap.Item{Type: encap.ItemNullAddress},
				encap.Item{Type: encap.ItemUnconnectedData, Data: resp(cip.Response{Service: cip.ServiceGetAttributeSingle})})}
		}, ethernetip.ErrProtocol},
		{"identity too short", func(req encap.Packet) encap.Packet {
			return encap.Packet{Header: req.Header, Data: rr(encap.Item{Type: encap.ItemNullAddress},
				encap.Item{Type: encap.ItemUnconnectedData, Data: resp(cip.Response{Service: cip.ServiceGetAttributesAll, Data: []byte{1}})})}
		}, ethernetip.ErrProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTarget(t, replyWith(t, tc.build))
			m := &recMetrics{}
			c := dialT(t, f.addr(), WithMetrics(m))
			if _, err := c.Identity(ctxT(t)); !errors.Is(err, tc.want) {
				t.Fatalf("Identity = %v, want %v", err, tc.want)
			}
			if c.State() != ethernetip.StateConnected {
				t.Error("a bad reply ended the session")
			}
		})
	}
}

func TestDroppedPackets(t *testing.T) {
	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		// A NOP, a packet of another session, a reply with an unknown
		// sender context, then the reply.
		p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandNOP, Session: fakeSession}})
		other := pkt.Header
		other.Session = 999
		p.send(t, encap.Packet{Header: other, Data: []byte{0xFF}})
		unknown := pkt.Header
		unknown.Context[7] ^= 0xFF
		p.send(t, encap.Packet{Header: unknown, Data: []byte{0xFF}})
		req := decodeRR(t, pkt)
		rrReply(t, p, pkt, cip.Response{Service: req.Service, Data: []byte{42, 0}})
	})
	c := dialT(t, f.addr())
	b, err := c.GetAttributeSingle(ctxT(t), cip.ClassIdentity, 1, 1)
	if err != nil || !bytes.Equal(b, []byte{42, 0}) {
		t.Fatalf("GetAttributeSingle = %x, %v", b, err)
	}
}

func TestOversizePacket(t *testing.T) {
	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		p.send(t, encap.Packet{Header: pkt.Header, Data: make([]byte, 100)})
	})
	c := dialT(t, f.addr(), WithMaxPacket(64))
	if _, err := c.Identity(ctxT(t)); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("oversize reply = %v, want ErrProtocol", err)
	}
	eventually(t, 2*time.Second, "session closed", func() bool { return c.State() == ethernetip.StateDisconnected })
}

func TestInvalidRequests(t *testing.T) {
	_, addr := startServer(t)
	c := dialT(t, addr)
	ctx := ctxT(t)
	bad := cip.Request{Service: 0x8E, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}
	if _, err := c.Do(ctx, bad); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("reply-bit request = %v", err)
	}
	route, _ := cip.ParseRoute("1/0")
	if _, err := c.DoRoute(ctx, bad, route); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("routed reply-bit request = %v", err)
	}
	if _, err := c.MultipleService(ctx, nil); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("empty MultipleService = %v", err)
	}
	if _, err := c.GetAttributeList(ctx, cip.ClassIdentity, 1, nil, nil); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("empty GetAttributeList = %v", err)
	}
	if _, err := c.GetAttributeList(ctx, cip.ClassIdentity, 1, []uint16{1}, []int{2, 2}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("mismatched GetAttributeList = %v", err)
	}
	// An error without data is returned as such.
	if _, err := c.GetAttributeList(ctx, cip.ClassIdentity, 9, []uint16{1}, []int{2}); err == nil {
		t.Error("GetAttributeList on a missing instance succeeded")
	} else if st, _ := ethernetip.StatusOf(err); st != cip.StatusPathDestinationUnknown {
		t.Errorf("GetAttributeList on a missing instance = %v", err)
	}
	if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 99); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Errorf("missing attribute = %v", err)
	}
	if _, err := c.GetAttributesAll(ctx, cip.Class(0x99), 1); err == nil {
		t.Error("GetAttributesAll of a missing class succeeded")
	}
	if _, err := c.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	resps, err := c.MultipleService(ctx, []cip.Request{
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)},
	})
	if err != nil || len(resps) != 2 || !resps[0].OK() || resps[1].Status != cip.StatusAttributeNotSupported {
		t.Fatalf("MultipleService = %+v, %v", resps, err)
	}
	req := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 99)}
	if ResponseError(req, resps[0]) != nil {
		t.Error("ResponseError of a success")
	}
	var ce *ethernetip.CIPError
	if err := ResponseError(req, resps[1]); !errors.As(err, &ce) || ce.Status != cip.StatusAttributeNotSupported || ce.Service != req.Service {
		t.Errorf("ResponseError = %v", err)
	}
}

func TestMultipleServiceReplyErrors(t *testing.T) {
	reqs := []cip.Request{
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
		{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 2)},
	}
	enc := func(parts ...[]byte) []byte {
		b := cip.AppendUint16(nil, uint16(len(parts)))
		off := 2 + 2*len(parts)
		for _, p := range parts {
			b = cip.AppendUint16(b, uint16(off))
			off += len(p)
		}
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	ok, _ := cip.Response{Service: cip.ServiceGetAttributeSingle}.Encode()
	wrong, _ := cip.Response{Service: cip.ServiceSetAttributeSingle}.Encode()
	cases := map[string][]byte{
		"split":   {5},
		"count":   enc(ok),
		"decode":  enc(ok, []byte{0x8E}),
		"service": enc(ok, wrong),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
				rrReply(t, p, pkt, cip.Response{Service: cip.ServiceMultipleServicePacket, Data: data})
			})
			c := dialT(t, f.addr())
			if _, err := c.MultipleService(ctxT(t), reqs); !errors.Is(err, ethernetip.ErrProtocol) {
				t.Fatalf("MultipleService = %v, want ErrProtocol", err)
			}
		})
	}
	t.Run("packet error", func(t *testing.T) {
		f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
			rrReply(t, p, pkt, cip.Response{Service: cip.ServiceMultipleServicePacket, Status: cip.StatusServiceNotSupported})
		})
		c := dialT(t, f.addr())
		if _, err := c.MultipleService(ctxT(t), reqs); !errors.Is(err, ethernetip.ErrUnsupported) {
			t.Fatalf("MultipleService = %v, want ErrUnsupported", err)
		}
	})
}

func TestGetAttributeListDecoding(t *testing.T) {
	vals, err := decodeAttributeList([]byte{2, 0, 1, 0, 0, 0, 0xAA, 0xBB, 3, 0, 0, 0, 1, 2, 3}, []int{2, 0})
	if err != nil || len(vals) != 2 || !bytes.Equal(vals[0].Value, []byte{0xAA, 0xBB}) || !bytes.Equal(vals[1].Value, []byte{1, 2, 3}) {
		t.Fatalf("decode = %+v, %v", vals, err)
	}
	if _, err := decodeAttributeList([]byte{1, 0}, []int{2, 2}); err == nil {
		t.Error("count mismatch accepted")
	}
	if _, err := decodeAttributeList([]byte{1, 0, 1, 0, 0, 0, 0xAA}, []int{2}); err == nil {
		t.Error("truncated value accepted")
	}
	if _, err := decodeAttributeList([]byte{1}, []int{2}); err == nil {
		t.Error("truncated count accepted")
	}

	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		rrReply(t, p, pkt, cip.Response{Service: cip.ServiceGetAttributeList, Data: []byte{9, 0}})
	})
	m := &recMetrics{}
	c := dialT(t, f.addr(), WithMetrics(m))
	if _, err := c.GetAttributeList(ctxT(t), cip.ClassIdentity, 1, []uint16{1}, []int{2}); !errors.Is(err, ethernetip.ErrProtocol) {
		t.Fatalf("bad list reply = %v", err)
	}
	if m.snapshot().decodeErrs != 1 {
		t.Error("decode error not reported")
	}
}

func TestListReplyErrors(t *testing.T) {
	cpf := func(items ...encap.Item) []byte { b, _ := encap.AppendCPF(nil, items); return b }
	cases := []struct {
		name string
		data []byte
		call func(c *Client) error
	}{
		{"identity cpf", []byte{1}, func(c *Client) error { _, err := c.ListIdentity(ctxT(t)); return err }},
		{"identity item missing", cpf(), func(c *Client) error { _, err := c.ListIdentity(ctxT(t)); return err }},
		{"identity item bad", cpf(encap.Item{Type: encap.ItemListIdentity, Data: []byte{1}}), func(c *Client) error { _, err := c.ListIdentity(ctxT(t)); return err }},
		{"services cpf", []byte{1}, func(c *Client) error { _, err := c.ListServices(ctxT(t)); return err }},
		{"services item bad", cpf(encap.Item{Type: encap.ItemNullAddress}, encap.Item{Type: encap.ItemListServices, Data: []byte{1}}), func(c *Client) error { _, err := c.ListServices(ctxT(t)); return err }},
		{"interfaces cpf", []byte{1}, func(c *Client) error { _, err := c.ListInterfaces(ctxT(t)); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
				p.send(t, encap.Packet{Header: pkt.Header, Data: tc.data})
			})
			c := dialT(t, f.addr())
			if err := tc.call(c); !errors.Is(err, ethernetip.ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}
	// The list commands fail without a session like any request.
	c, _ := New("127.0.0.1:1")
	for _, call := range []func() error{
		func() error { _, err := c.ListIdentity(context.Background()); return err },
		func() error { _, err := c.ListServices(context.Background()); return err },
		func() error { _, err := c.ListInterfaces(context.Background()); return err },
	} {
		if err := call(); !errors.Is(err, ethernetip.ErrNotConnected) {
			t.Errorf("unconnected list = %v", err)
		}
	}
}

func TestCloseWhileConnecting(t *testing.T) {
	gate := make(chan struct{})
	f := newRawTarget(t, func(p *peer, pkt encap.Packet) {
		<-gate
		h := pkt.Header
		h.Session = fakeSession
		p.send(t, encap.Packet{Header: h, Data: pkt.Data})
	})
	c, err := New(f.addr())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Connect(ctxT(t)) }()
	eventually(t, 2*time.Second, "connecting", func() bool { return c.State() == ethernetip.StateConnecting })
	// Close does not wait for Connect; Connect then sees it.
	_ = c.Close()
	close(gate)
	if err := <-done; !errors.Is(err, ethernetip.ErrClosed) {
		t.Fatalf("Connect = %v, want ErrClosed", err)
	}
}

// timeoutErr is a write timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "write timed out by test" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// recordConn fails writes with a timeout while armed, and records the
// last write deadline.
type recordConn struct {
	net.Conn
	fail *atomic.Bool
	dl   *atomic.Int64 // unix nanoseconds of the last write deadline
}

func (c recordConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, timeoutErr{}
	}
	return c.Conn.Write(b)
}

func (c recordConn) SetWriteDeadline(t time.Time) error {
	c.dl.Store(t.UnixNano())
	return c.Conn.SetWriteDeadline(t)
}

type recordDialer struct {
	fail *atomic.Bool
	dl   *atomic.Int64
}

func (d recordDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return recordConn{Conn: c, fail: d.fail, dl: d.dl}, nil
}

// TestWriteDeadlineIsClientTimeout checks that the write deadline comes
// from the client's timeout, not from the request's context, and that a
// write that fails ends the session.
func TestWriteDeadlineIsClientTimeout(t *testing.T) {
	_, addr := startServer(t)
	fail, dl := &atomic.Bool{}, &atomic.Int64{}
	c := dialT(t, addr, WithDialer(recordDialer{fail, dl}), WithTimeout(3*time.Second))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	before := time.Now()
	if _, err := c.Identity(short); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(0, dl.Load()); got.Before(before.Add(2 * time.Second)) {
		t.Fatalf("unconnected write deadline %v after the request, want the client timeout of 3s", got.Sub(before))
	}
	dl.Store(0)
	before = time.Now()
	if _, err := cn.Identity(short); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(0, dl.Load()); got.Before(before.Add(2 * time.Second)) {
		t.Fatalf("connected write deadline %v after the request, want the client timeout of 3s", got.Sub(before))
	}

	// A request whose context has already ended sends nothing.
	expired, cancel2 := context.WithCancel(ctx)
	cancel2()
	if _, err := c.Identity(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("request with a canceled context = %v", err)
	}
	if _, err := cn.Identity(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("connected request with a canceled context = %v", err)
	}
	if c.State() != ethernetip.StateConnected {
		t.Fatal("a canceled request ended the session")
	}

	// A write that fails means the peer stopped reading: the session ends.
	fail.Store(true)
	if _, err := cn.Identity(ctx); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("connected write failure = %v, want ErrConnectionLost", err)
	}
	if _, err := c.Identity(ctx); !errors.Is(err, ethernetip.ErrNotConnected) && !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("request after the session ended = %v", err)
	}
}

func (c *Client) handleForTest() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return 0
	}
	return c.sess.handle
}

// TestConcurrentDeadlines checks that requests whose context expires at
// any point leave the shared session intact: afterwards a request with a
// normal context succeeds on the same session.
func TestConcurrentDeadlines(t *testing.T) {
	_, addr := startServer(t)
	c := dialT(t, addr, WithMaxPending(4))
	ctx := ctxT(t)
	handle := c.handleForTest()
	if handle == 0 {
		t.Fatal("no session")
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			short, cancel := context.WithTimeout(ctx, time.Duration(i*4)*time.Microsecond)
			defer cancel()
			_, _ = c.GetAttributeSingle(short, cip.ClassIdentity, 1, 1)
		}(i)
	}
	wg.Wait()
	if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
		t.Fatalf("request after the expired ones: %v", err)
	}
	if c.State() != ethernetip.StateConnected || c.handleForTest() != handle {
		t.Fatal("the session was lost or replaced")
	}

	// Healthy requests alongside expiring ones all succeed.
	errs := make(chan error, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				short, cancel := context.WithTimeout(ctx, time.Duration(i%7)*time.Microsecond)
				defer cancel()
				_, _ = c.GetAttributeSingle(short, cip.ClassIdentity, 1, 1)
				return
			}
			if _, err := c.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("healthy request failed: %v", err)
		break
	}
	if c.handleForTest() != handle {
		t.Error("session replaced")
	}
}
