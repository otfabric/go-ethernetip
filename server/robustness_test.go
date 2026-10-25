// SPDX-License-Identifier: MIT

package server

import (
	"math/rand"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// TestRandomMessages sends random explicit messages, valid encapsulation
// carrying random CIP, to every object of a server with assemblies. The
// server must answer each one (a panic would end the test binary) and keep
// serving.
func TestRandomMessages(t *testing.T) {
	s := startIOServer(t)
	p := dialPeer(t, s)
	p.register()
	rng := rand.New(rand.NewSource(1))
	classes := s.Classes()
	services := []cip.Service{
		cip.ServiceGetAttributesAll, cip.ServiceGetAttributeList, cip.ServiceReset,
		cip.ServiceMultipleServicePacket, cip.ServiceGetAttributeSingle, cip.ServiceSetAttributeSingle,
		cip.ServiceForwardClose, cip.ServiceUnconnectedSend, cip.ServiceForwardOpen, cip.ServiceLargeForwardOpen,
	}
	n := 3000
	if testing.Short() {
		n = 300
	}
	for i := 0; i < n; i++ {
		svc := services[rng.Intn(len(services))]
		path := cip.Path{cip.ClassSegment(classes[rng.Intn(len(classes))]), cip.InstanceSegment(uint32(rng.Intn(3)))}
		if rng.Intn(2) == 0 {
			path = append(path, cip.AttributeSegment(uint16(rng.Intn(20))))
		}
		data := make([]byte, rng.Intn(64))
		rng.Read(data)
		if svc == cip.ServiceForwardOpen && rng.Intn(2) == 0 {
			// A valid header with a random path tail.
			fo := fwdOpen(uint8(rng.Intn(4)), cip.Trigger(rng.Intn(3)), ioPath(uint32(rng.Intn(3))*asmCfg, asmOut, asmIn))
			b, err1 := fo.Encode()
			pb, err2 := fo.Path.Encode()
			if err1 == nil && err2 == nil {
				head := append([]byte(nil), b[:len(b)-len(pb)]...)
				tail := append(pb[:len(pb)-2:len(pb)-2], data[:len(data)&^1]...)
				head[len(head)-1] = byte(len(tail) / 2)
				data = append(head, tail...)
			}
		}
		msg, err := cip.Request{Service: svc, Path: path, Data: data}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		r, _ := p.rrData(msg)
		if r.Service != svc && svc != cip.ServiceUnconnectedSend {
			t.Fatalf("reply service %v to %v", r.Service, svc)
		}
	}
	// Random octets as the message.
	for i := 0; i < n; i++ {
		b := make([]byte, rng.Intn(40))
		rng.Read(b)
		p.rrData(b)
	}
	// Random encapsulation data for every command.
	for i := 0; i < n/10; i++ {
		cmds := []encap.Command{encap.CommandSendRRData, encap.CommandSendUnitData, encap.CommandRegisterSession, encap.CommandListIdentity}
		b := make([]byte, rng.Intn(80))
		rng.Read(b)
		cmd := cmds[rng.Intn(len(cmds))]
		p.send(cmd, p.handle, b)
		// A ListServices fence: every packet before its reply answers
		// the random one (SendUnitData may also go unanswered).
		fence := p.send(encap.CommandListServices, 0, nil)
		replies := 0
		for {
			r, err := p.tryRecv(5 * time.Second)
			if err != nil {
				t.Fatalf("%s with random data: %v", cmd, err)
			}
			if r.Context == fence.Context {
				break
			}
			replies++
		}
		if replies > 1 || replies == 0 && cmd != encap.CommandSendUnitData {
			t.Fatalf("%s with random data answered %d times", cmd, replies)
		}
	}
	// Random connected messages on a Class 3 connection.
	fo := fwdOpen(3, cip.TriggerApplication, explicitPath)
	fo.OTRPI = 10_000_000
	reply, _ := p.mustOpen(fo)
	for i := 0; i < n/10; i++ {
		b := make([]byte, rng.Intn(40))
		rng.Read(b)
		payload := append([]byte{byte(i), byte(i >> 8)}, b...)
		data, _ := encap.RRData{Items: []encap.Item{encap.ConnectedAddress(reply.OTConnID), {Type: encap.ItemConnectedData, Data: payload}}}.Encode()
		p.send(encap.CommandSendUnitData, p.handle, data)
		r := p.recv()
		if r.Command != encap.CommandSendUnitData || r.Status != encap.StatusSuccess {
			t.Fatalf("connected random message: %s %s", r.Command, r.Status)
		}
	}
	if r := p.get(cip.ClassIdentity, 1, 1); !r.OK() {
		t.Fatalf("server not serving after random input: %s", r.Status)
	}
}
