// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
	"github.com/otfabric/go-ethernetip/server"
)

func TestConnAgainstServer(t *testing.T) {
	srv, addr := startServer(t)
	m := &recMetrics{}
	c := dialT(t, addr, WithMetrics(m))
	ctx := ctxT(t)
	if _, err := c.OpenConnection(ctx, ConnectionOptions{Timeout: -time.Second}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("negative timeout = %v", err)
	}
	cn, err := c.OpenConnection(ctx, ConnectionOptions{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	info := cn.Info()
	if info.Class != 3 || info.OTConnID == 0 || info.TOConnID == 0 {
		t.Fatalf("Info = %+v", info)
	}
	if len(srv.Connections()) != 1 {
		t.Fatalf("server connections = %d", len(srv.Connections()))
	}
	id, err := cn.Identity(ctx)
	if err != nil || id.VendorID != server.DefaultIdentity.VendorID {
		t.Fatalf("Identity = %+v, %v", id, err)
	}
	if all, err := cn.GetAttributesAll(ctx, cip.ClassIdentity, 1); err != nil || len(all) == 0 {
		t.Fatalf("GetAttributesAll = %x, %v", all, err)
	}
	// TCP/IP Interface attribute 13, the encapsulation inactivity timeout.
	if err := cn.SetAttributeSingle(ctx, cip.ClassTCPIPInterface, 1, 13, cip.AppendUint16(nil, 300)); err != nil {
		t.Fatal(err)
	}
	if v, err := cn.GetAttributeSingle(ctx, cip.ClassTCPIPInterface, 1, 13); err != nil || !bytes.Equal(v, cip.AppendUint16(nil, 300)) {
		t.Fatalf("attribute 13 = %x, %v", v, err)
	}
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 99); !errors.Is(err, ethernetip.ErrUnsupported) {
		t.Errorf("missing attribute = %v", err)
	}
	resps, err := cn.MultipleService(ctx, []cip.Request{{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)}})
	if err != nil || len(resps) != 1 || !resps[0].OK() {
		t.Fatalf("MultipleService = %+v, %v", resps, err)
	}
	// The sequence count wraps from 0xFFFF to 1, skipping 0.
	cn.mu.Lock()
	cn.seq = 0xFFFF
	cn.mu.Unlock()
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); err != nil {
		t.Fatal(err)
	}
	cn.mu.Lock()
	seq := cn.seq
	cn.mu.Unlock()
	if seq != 1 {
		t.Errorf("sequence after wrap = %d, want 1", seq)
	}
	if _, err := cn.Do(ctx, cip.Request{Service: 0x8E, Path: cip.MessageRouterPath()}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Errorf("reply-bit request = %v", err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := cn.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("request after Close = %v", err)
	}
	if len(srv.Connections()) != 0 {
		t.Error("Forward_Close left the connection open")
	}
	md := m.snapshot()
	if len(md.requests) != len(md.done) {
		t.Errorf("requests %d, done %d", len(md.requests), len(md.done))
	}

	large, err := c.OpenConnection(ctx, ConnectionOptions{Large: true})
	if err != nil {
		t.Fatalf("Large_Forward_Open: %v", err)
	}
	if _, err := large.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	// Closing the client ends the connection.
	_ = c.Close()
	if _, err := large.Identity(ctx); !errors.Is(err, ethernetip.ErrClosed) {
		t.Errorf("connection after client Close = %v", err)
	}
	if err := large.Close(ctx); err != nil {
		t.Errorf("Close of a lost connection = %v", err)
	}
}

func TestClassThreeTiming(t *testing.T) {
	for _, d := range []time.Duration{time.Second, time.Minute, time.Hour, 1000 * time.Hour} {
		mult, rpi := classThreeTiming(d)
		got := cip.ConnectionTimeout(time.Duration(rpi)*time.Microsecond, mult)
		want := min(d, time.Duration(math.MaxUint32)*time.Microsecond*512)
		if mult > 7 || got < want*99/100 || got > want*101/100 {
			t.Errorf("classThreeTiming(%v) = %d, %d µs: timeout %v", d, mult, rpi, got)
		}
		if d <= 5120*time.Second && time.Duration(rpi)*time.Microsecond > 10*time.Second {
			t.Errorf("classThreeTiming(%v): RPI %d µs above 10 s", d, rpi)
		}
	}
}

// fakeConnTarget answers Forward_Open and Forward_Close, and passes
// SendUnitData to unit. otID is the O->T ID it assigns.
const fakeOTID = 0x0BADF00D

func fakeConnTarget(t *testing.T, mangle func(*cip.ForwardOpenReply), unit func(p *peer, pkt encap.Packet, toID uint32, seq uint16, req cip.Request)) *fakeTarget {
	var toID uint32
	return newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		if pkt.Command == encap.CommandSendUnitData {
			rr, err := encap.DecodeRRData(pkt.Data)
			if err != nil {
				t.Error(err)
				return
			}
			it, _ := encap.Find(rr.Items, encap.ItemConnectedData)
			req, err := cip.DecodeRequest(it.Data[2:])
			if err != nil {
				t.Error(err)
			}
			unit(p, pkt, toID, binary.LittleEndian.Uint16(it.Data), req)
			return
		}
		req := decodeRR(t, pkt)
		switch req.Service {
		case cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen:
			fo, err := cip.DecodeForwardOpen(req.Data, req.Service == cip.ServiceLargeForwardOpen)
			if err != nil {
				t.Error(err)
				return
			}
			toID = fo.TOConnID
			r := cip.ForwardOpenReply{OTConnID: fakeOTID, TOConnID: fo.TOConnID, Triad: fo.Triad, OTAPI: fo.OTRPI, TOAPI: fo.TORPI}
			if mangle != nil {
				mangle(&r)
			}
			b, _ := r.Encode()
			rrReply(t, p, pkt, cip.Response{Service: req.Service, Data: b})
		case cip.ServiceForwardClose:
			fc, err := cip.DecodeForwardClose(req.Data)
			if err != nil {
				t.Error(err)
				return
			}
			b := cip.ForwardCloseReply{Triad: fc.Triad}
			enc, _ := b.Encode()
			rrReply(t, p, pkt, cip.Response{Service: req.Service, Data: enc})
		default:
			// Other services do not occur in this test.
		}
	})
}

// unitReply sends a SendUnitData reply on connection id.
func unitReply(t *testing.T, p *peer, req encap.Packet, id uint32, seq uint16, resp []byte) {
	payload := binary.LittleEndian.AppendUint16(nil, seq)
	payload = append(payload, resp...)
	data, err := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(id), {Type: encap.ItemConnectedData, Data: payload}}}.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: req.Session}, Data: data})
}

func TestConnDroppedReplies(t *testing.T) {
	f := fakeConnTarget(t, nil, func(p *peer, pkt encap.Packet, toID uint32, seq uint16, req cip.Request) {
		ok, _ := cip.Response{Service: req.Service, Data: []byte{7, 0}}.Encode()
		bad, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(toID)}}.Encode()
		p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: pkt.Session}, Data: bad})
		short, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(toID), {Type: encap.ItemConnectedData, Data: []byte{1}}}}.Encode()
		p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: pkt.Session}, Data: short})
		p.send(t, encap.Packet{Header: encap.Header{Command: encap.CommandSendUnitData, Session: pkt.Session}, Data: []byte{1}})
		unitReply(t, p, pkt, 0x12345, seq, ok)  // unknown connection
		unitReply(t, p, pkt, toID, seq+7, ok)   // stale sequence count
		unitReply(t, p, pkt, fakeOTID, seq, ok) // the O->T ID is accepted too
	})
	m := &recMetrics{}
	c := dialT(t, f.addr(), WithMetrics(m))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cn.Info().OTConnID != fakeOTID {
		t.Fatalf("O->T ID %#x", cn.Info().OTConnID)
	}
	v, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1)
	if err != nil || !bytes.Equal(v, []byte{7, 0}) {
		t.Fatalf("GetAttributeSingle = %x, %v", v, err)
	}
	if n := m.snapshot().decodeErrs; n != 3 {
		t.Errorf("decode errors = %d, want 3", n)
	}
	if err := cn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConnBadReplies(t *testing.T) {
	cases := map[string]func(p *peer, pkt encap.Packet, toID uint32, seq uint16, req cip.Request){
		"bad response": func(p *peer, pkt encap.Packet, toID uint32, seq uint16, _ cip.Request) {
			unitReply(t, p, pkt, toID, seq, []byte{0x0E})
		},
		"other service": func(p *peer, pkt encap.Packet, toID uint32, seq uint16, _ cip.Request) {
			b, _ := cip.Response{Service: cip.ServiceReset}.Encode()
			unitReply(t, p, pkt, toID, seq, b)
		},
	}
	for name, unit := range cases {
		t.Run(name, func(t *testing.T) {
			f := fakeConnTarget(t, nil, unit)
			c := dialT(t, f.addr())
			cn, err := c.OpenConnection(ctxT(t), ConnectionOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cn.GetAttributeSingle(ctxT(t), cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}
}

func TestConnTimeoutAndLoss(t *testing.T) {
	mode := make(chan string, 4)
	f := fakeConnTarget(t, nil, func(p *peer, pkt encap.Packet, toID uint32, seq uint16, req cip.Request) {
		switch <-mode {
		case "silent":
		case "close":
			_ = p.conn.Close()
		}
	})
	c := dialT(t, f.addr(), WithTimeout(10*time.Second))
	ctx := ctxT(t)
	cn, err := c.OpenConnection(ctx, ConnectionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A request that is never answered times out.
	mode <- "silent"
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := cn.GetAttributeSingle(short, cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("silent target = %v, want ErrTimeout", err)
	}
	cn.mu.Lock()
	pending := cn.pending
	cn.mu.Unlock()
	if pending != nil {
		t.Error("timed-out request left pending")
	}
	// A request waiting for its turn times out too.
	mode <- "silent"
	first := make(chan error, 1)
	long, cancelLong := context.WithCancel(ctx)
	go func() { _, err := cn.GetAttributeSingle(long, cip.ClassIdentity, 1, 1); first <- err }()
	eventually(t, 2*time.Second, "first request pending", func() bool { return len(cn.turn) == 1 })
	short2, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()
	if _, err := cn.GetAttributeSingle(short2, cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrTimeout) {
		t.Fatalf("queued request = %v", err)
	}
	cancelLong()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request = %v", err)
	}

	// The session ends while a request is pending: it fails, and so do
	// later requests on the connection.
	mode <- "close"
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("lost session = %v, want ErrConnectionLost", err)
	}
	if _, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 1); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("request after loss = %v, want ErrConnectionLost", err)
	}
}

func TestForwardOpenReplyChecks(t *testing.T) {
	mangles := map[string]func(*cip.ForwardOpenReply){
		"triad": func(r *cip.ForwardOpenReply) { r.Serial++ },
	}
	for name, mg := range mangles {
		t.Run(name, func(t *testing.T) {
			f := fakeConnTarget(t, mg, nil)
			c := dialT(t, f.addr())
			if _, err := c.OpenConnection(ctxT(t), ConnectionOptions{}); !errors.Is(err, ethernetip.ErrProtocol) {
				t.Fatalf("OpenConnection = %v, want ErrProtocol", err)
			}
		})
	}
	reply := func(data []byte, svcStatus cip.GeneralStatus) func(*peer, encap.Packet) {
		return func(p *peer, pkt encap.Packet) {
			req := decodeRR(t, pkt)
			rrReply(t, p, pkt, cip.Response{Service: req.Service, Status: svcStatus, Data: data})
		}
	}
	t.Run("short reply", func(t *testing.T) {
		f := newFakeTarget(t, reply([]byte{1, 2, 3}, 0))
		c := dialT(t, f.addr())
		if _, err := c.OpenConnection(ctxT(t), ConnectionOptions{}); !errors.Is(err, ethernetip.ErrProtocol) {
			t.Fatalf("OpenConnection = %v, want ErrProtocol", err)
		}
		if err := c.ForwardClose(ctxT(t), cip.ForwardClose{Triad: c.NewTriad(), Path: cip.MessageRouterPath()}); !errors.Is(err, ethernetip.ErrProtocol) {
			t.Fatalf("ForwardClose = %v, want ErrProtocol", err)
		}
	})
	t.Run("close triad", func(t *testing.T) {
		enc, _ := cip.ForwardCloseReply{Triad: cip.Triad{Serial: 1, VendorID: 2, OriginatorSerial: 3}}.Encode()
		f := newFakeTarget(t, reply(enc, 0))
		c := dialT(t, f.addr())
		if err := c.ForwardClose(ctxT(t), cip.ForwardClose{Triad: cip.Triad{Serial: 9}, Path: cip.MessageRouterPath()}); !errors.Is(err, ethernetip.ErrProtocol) {
			t.Fatalf("ForwardClose = %v, want ErrProtocol", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
			req := decodeRR(t, pkt)
			rrReply(t, p, pkt, cip.Response{Service: req.Service, Status: cip.StatusConnectionFailure,
				Extended: []uint16{uint16(cip.ConnStatusOutOfConnections)}})
		})
		c := dialT(t, f.addr())
		_, err := c.OpenConnection(ctxT(t), ConnectionOptions{})
		var ce *ethernetip.CIPError
		if !errors.As(err, &ce) || ce.Status != cip.StatusConnectionFailure {
			t.Fatalf("OpenConnection = %v", err)
		}
		if err := c.ForwardClose(ctxT(t), cip.ForwardClose{Triad: c.NewTriad()}); !errors.As(err, &ce) {
			t.Fatalf("ForwardClose = %v", err)
		}
	})
	t.Run("encode errors", func(t *testing.T) {
		_, addr := startServer(t)
		c := dialT(t, addr)
		if _, _, err := c.ForwardOpen(ctxT(t), cip.ForwardOpen{TimeoutMultiplier: 9}); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("ForwardOpen = %v", err)
		}
		long := make(cip.Path, 300)
		for i := range long {
			long[i] = cip.ClassSegment(1)
		}
		if err := c.ForwardClose(ctxT(t), cip.ForwardClose{Path: long}); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("ForwardClose = %v", err)
		}
	})
}

func TestForwardOpenItems(t *testing.T) {
	sock := encap.Item{Type: encap.ItemSockaddrOT, Data: make([]byte, 16)}
	f := newFakeTarget(t, func(p *peer, pkt encap.Packet) {
		req := decodeRR(t, pkt)
		fo, err := cip.DecodeForwardOpen(req.Data, false)
		if err != nil {
			t.Error(err)
			return
		}
		b, _ := cip.ForwardOpenReply{OTConnID: 1, TOConnID: fo.TOConnID, Triad: fo.Triad}.Encode()
		rrReply(t, p, pkt, cip.Response{Service: req.Service, Data: b}, sock)
	})
	route, _ := cip.ParseRoute("1/0")
	c := dialT(t, f.addr(), WithRoute(route))
	fo := cip.ForwardOpen{Triad: c.NewTriad(), TOConnID: 5, OTRPI: 1000, TORPI: 1000,
		OTParams:  cip.NetworkParams{Type: cip.ConnectionPointToPoint, Size: 10},
		TOParams:  cip.NetworkParams{Type: cip.ConnectionPointToPoint, Size: 10},
		Transport: cip.TransportClass3Server, Path: cip.MessageRouterPath()}
	_, items, err := c.ForwardOpen(ctxT(t), fo)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Type != encap.ItemSockaddrOT {
		t.Fatalf("items %+v, want the Sockaddr item only", items)
	}
}
