// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/otfabric/go-ethernetip/cip"
)

// identityObject is the Identity object (class 0x01), instance 1.
type identityObject struct {
	*StandardObject
	s *Server

	mu sync.Mutex
	id cip.Identity
}

func newIdentityObject(s *Server) *identityObject {
	o := &identityObject{StandardObject: NewObject(cip.ClassIdentity, 1), s: s, id: s.opts.identity}
	in := o.AddInstance(1)
	field := func(f func(id cip.Identity) []byte) Attribute {
		return Attribute{Get: func() []byte { return f(o.get()) }, InGetAll: true}
	}
	in.SetAttribute(1, field(func(id cip.Identity) []byte { return cip.AppendUint16(nil, id.VendorID) }))
	in.SetAttribute(2, field(func(id cip.Identity) []byte { return cip.AppendUint16(nil, uint16(id.DeviceType)) }))
	in.SetAttribute(3, field(func(id cip.Identity) []byte { return cip.AppendUint16(nil, id.ProductCode) }))
	in.SetAttribute(4, field(func(id cip.Identity) []byte { return []byte{id.Revision.Major, id.Revision.Minor} }))
	in.SetAttribute(5, field(func(id cip.Identity) []byte { return cip.AppendUint16(nil, uint16(id.Status)) }))
	in.SetAttribute(6, field(func(id cip.Identity) []byte { return cip.AppendUint32(nil, id.SerialNumber) }))
	in.SetAttribute(7, field(func(id cip.Identity) []byte {
		b, _ := cip.AppendShortString(nil, id.ProductName)
		return b
	}))
	// State is not part of Get_Attributes_All: attributes 1 to 7 are what
	// originators decode (EIPScanner, pycomm3 and others stop there).
	in.SetAttribute(8, Attribute{Get: func() []byte { return []byte{o.get().State} }})
	o.HandleService(cip.ServiceReset, o.reset)
	return o
}

func (o *identityObject) get() cip.Identity {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.id
}

func (o *identityObject) setStatus(st cip.IdentityStatus) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.id.Status = st
}

func (o *identityObject) reset(_ context.Context, r *Request) cip.Response {
	if r.Instance != 1 {
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
	var t uint8
	switch len(r.Data) {
	case 0:
	case 1:
		t = r.Data[0]
	default:
		return cip.Response{Status: cip.StatusTooMuchData}
	}
	if t > 1 {
		return cip.Response{Status: cip.StatusInvalidParameter}
	}
	if f := o.s.opts.onReset; f != nil {
		return cip.Response{Status: f(t)}
	}
	return cip.Response{}
}

// newMessageRouter returns the Message Router (class 0x02), instance 1:
// attribute 1 is the list of classes, 2 the connections supported, 3 the
// connections open. It handles Multiple Service Packet.
func newMessageRouter(s *Server) *StandardObject {
	o := NewObject(cip.ClassMessageRouter, 1)
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte {
		cs := s.Classes()
		b := cip.AppendUint16(nil, uint16(len(cs)))
		for _, c := range cs {
			b = cip.AppendUint16(b, uint16(c))
		}
		return b
	}, InGetAll: true})
	in.SetAttribute(2, Attribute{Get: func() []byte { return cip.AppendUint16(nil, uint16(s.opts.maxConnections)) }, InGetAll: true})
	in.SetAttribute(3, Attribute{Get: func() []byte { return cip.AppendUint16(nil, uint16(len(s.cm.list()))) }, InGetAll: true})
	o.HandleService(cip.ServiceMultipleServicePacket, func(ctx context.Context, r *Request) cip.Response {
		if r.Instance != 1 {
			return cip.Response{Status: cip.StatusServiceNotSupported}
		}
		return s.multipleService(ctx, r)
	})
	return o
}

// maxEmbedded bounds the services of one Multiple Service Packet.
const maxEmbedded = 200

func (s *Server) multipleService(ctx context.Context, r *Request) cip.Response {
	parts, err := cip.SplitMultiple(r.Data)
	if err != nil || len(parts) == 0 {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	if len(parts) > maxEmbedded {
		return cip.Response{Status: cip.StatusResourceUnavailable}
	}
	resps := make([]cip.Response, len(parts))
	failed := false
	for i, p := range parts {
		if len(p) > 0 && cip.Service(p[0]) == cip.ServiceMultipleServicePacket {
			// Nesting is not allowed.
			resps[i] = cip.Response{Service: cip.ServiceMultipleServicePacket, Status: cip.StatusServiceNotSupported}
		} else {
			resps[i] = s.handleMessage(ctx, p, r.Remote, r.Connected)
		}
		failed = failed || !resps[i].OK()
	}
	data, err := cip.EncodeMultipleServiceResponse(resps)
	if err != nil {
		return cip.Response{Status: cip.StatusReplyDataTooLarge}
	}
	st := cip.StatusSuccess
	if failed {
		st = cip.StatusEmbeddedServiceError
	}
	return cip.Response{Status: st, Data: data}
}

// newPortObject returns the Port object (class 0xF4) with instance 1, the
// EtherNet/IP port, numbered 2 as on Logix communication modules (port 1 is
// the backplane routes address).
func newPortObject(s *Server) *StandardObject {
	o := NewObject(cip.ClassPort, 2)
	o.SetClassAttribute(8, Attribute{Get: func() []byte { return cip.AppendUint16(nil, 1) }, InGetAll: true})
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte { return cip.AppendUint16(nil, 4) }, InGetAll: true}) // TCP/IP
	in.SetAttribute(2, Attribute{Get: func() []byte { return cip.AppendUint16(nil, 2) }, InGetAll: true})
	in.SetAttribute(3, Attribute{Get: func() []byte {
		p, _ := cip.ObjectPath(cip.ClassTCPIPInterface, 1).Encode()
		return append(cip.AppendUint16(nil, uint16(len(p)/2)), p...)
	}, InGetAll: true})
	in.SetAttribute(4, Attribute{Get: func() []byte {
		b, _ := cip.AppendShortString(nil, "EtherNet/IP")
		return b
	}, InGetAll: true})
	in.SetAttribute(7, Attribute{Get: func() []byte {
		ip := s.localIP(s.Addr())
		b, _ := cip.AppendShortString(nil, ip.String())
		return b
	}, InGetAll: true})
	return o
}

// appendPaddedString appends a STRING padded to an even length, as the
// TCP/IP Interface object encodes its strings.
func appendPaddedString(b []byte, s string) []byte {
	b, _ = cip.AppendString(b, s)
	if len(s)%2 != 0 {
		b = append(b, 0)
	}
	return b
}

func ipUDINT(a interface{ As4() [4]byte }) uint32 {
	v := a.As4()
	return binary.BigEndian.Uint32(v[:])
}

// newTCPIPObject returns the TCP/IP Interface object (class 0xF5),
// instance 1, revision 4.
func newTCPIPObject(s *Server) *StandardObject {
	o := NewObject(cip.ClassTCPIPInterface, 4)
	in := o.AddInstance(1)
	in.SetAttribute(1, Attribute{Get: func() []byte { return cip.AppendUint32(nil, 1) }, InGetAll: true})    // configuration valid
	in.SetAttribute(2, Attribute{Get: func() []byte { return cip.AppendUint32(nil, 0x20) }, InGetAll: true}) // settable
	in.SetAttribute(3, Attribute{Get: func() []byte { return cip.AppendUint32(nil, 0) }, InGetAll: true})    // static
	in.SetAttribute(4, Attribute{Get: func() []byte {
		p, _ := cip.ObjectPath(cip.ClassEthernetLink, 1).Encode()
		return append(cip.AppendUint16(nil, uint16(len(p)/2)), p...)
	}, InGetAll: true})
	in.SetAttribute(5, Attribute{Get: func() []byte {
		i := s.opts.iface
		ip := s.localIP(s.Addr())
		b := cip.AppendUint32(nil, ipUDINT(ip))
		for _, a := range []interface{ As4() [4]byte }{validOr0(i.Mask), validOr0(i.Gateway), validOr0(i.NameServer), validOr0(netipZero)} {
			b = cip.AppendUint32(b, ipUDINT(a))
		}
		return appendPaddedString(b, i.DomainName)
	}, InGetAll: true})
	in.SetAttribute(6, Attribute{Get: func() []byte { return appendPaddedString(nil, s.opts.iface.HostName) }, InGetAll: true})
	in.SetAttribute(8, Attribute{Get: func() []byte {
		s.mu.Lock()
		defer s.mu.Unlock()
		return []byte{s.ttl}
	}, Set: func(d []byte) cip.GeneralStatus {
		if st := fixedSize(d, 1); st != cip.StatusSuccess {
			return st
		}
		if d[0] == 0 {
			return cip.StatusInvalidAttributeValue
		}
		s.mu.Lock()
		s.ttl = d[0]
		s.mu.Unlock()
		return cip.StatusSuccess
	}, InGetAll: true})
	in.SetAttribute(9, Attribute{Get: func() []byte {
		b := []byte{0, 0}
		b = cip.AppendUint16(b, multicastAddresses)
		return cip.AppendUint32(b, ipUDINT(s.multicastBase()))
	}, InGetAll: true})
	in.SetAttribute(13, Attribute{Get: func() []byte {
		return cip.AppendUint16(nil, uint16(s.inactivityTimeout().Seconds()))
	}, Set: func(d []byte) cip.GeneralStatus {
		if st := fixedSize(d, 2); st != cip.StatusSuccess {
			return st
		}
		v := binary.LittleEndian.Uint16(d)
		if v > 3600 {
			return cip.StatusInvalidAttributeValue
		}
		s.mu.Lock()
		s.inactivity = secondsDuration(v)
		s.mu.Unlock()
		return cip.StatusSuccess
	}, InGetAll: true})
	return o
}

// newEthernetLinkObject returns the Ethernet Link object (class 0xF6),
// instance 1.
func newEthernetLinkObject(s *Server) *StandardObject {
	o := NewObject(cip.ClassEthernetLink, 4)
	in := o.AddInstance(1)
	speed := s.opts.iface.SpeedMbps
	if speed == 0 {
		speed = 100
	}
	in.SetAttribute(1, Attribute{Get: func() []byte { return cip.AppendUint32(nil, speed) }, InGetAll: true})
	// Link active, full duplex, negotiation successful.
	in.SetAttribute(2, Attribute{Get: func() []byte { return cip.AppendUint32(nil, 0x0D) }, InGetAll: true})
	in.SetAttribute(3, Attribute{Get: func() []byte { return append([]byte(nil), s.opts.iface.MAC[:]...) }, InGetAll: true})
	in.SetAttribute(7, Attribute{Get: func() []byte { return []byte{2} }}) // twisted pair
	in.SetAttribute(8, Attribute{Get: func() []byte { return []byte{1} }}) // enabled
	in.SetAttribute(9, Attribute{Get: func() []byte { return []byte{1} }}) // admin enabled
	in.SetAttribute(10, Attribute{Get: func() []byte {
		b, _ := cip.AppendShortString(nil, "port1")
		return b
	}})
	return o
}

// fixedSize checks the length of the data of a Set_Attribute_Single.
func fixedSize(d []byte, n int) cip.GeneralStatus {
	switch {
	case len(d) < n:
		return cip.StatusNotEnoughData
	case len(d) > n:
		return cip.StatusTooMuchData
	}
	return cip.StatusSuccess
}
