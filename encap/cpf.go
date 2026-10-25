// SPDX-License-Identifier: MIT

package encap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"github.com/otfabric/go-ethernetip/cip"
)

// ItemType is the type ID of a common packet format item.
type ItemType uint16

// Common packet format item types.
const (
	ItemNullAddress      ItemType = 0x0000
	ItemListIdentity     ItemType = 0x000C
	ItemConnectedAddress ItemType = 0x00A1
	ItemConnectedData    ItemType = 0x00B1
	ItemUnconnectedData  ItemType = 0x00B2
	ItemListServices     ItemType = 0x0100
	ItemSockaddrOT       ItemType = 0x8000
	ItemSockaddrTO       ItemType = 0x8001
	ItemSequencedAddress ItemType = 0x8002
)

// String returns the name of the item type, for example "Connected Data".
func (t ItemType) String() string {
	switch t {
	case ItemNullAddress:
		return "Null Address"
	case ItemListIdentity:
		return "CIP Identity"
	case ItemConnectedAddress:
		return "Connected Address"
	case ItemConnectedData:
		return "Connected Data"
	case ItemUnconnectedData:
		return "Unconnected Data"
	case ItemListServices:
		return "ListServices Response"
	case ItemSockaddrOT:
		return "Sockaddr Info O->T"
	case ItemSockaddrTO:
		return "Sockaddr Info T->O"
	case ItemSequencedAddress:
		return "Sequenced Address"
	default:
		return fmt.Sprintf("item 0x%04X", uint16(t))
	}
}

// Item is one item of a common packet format.
type Item struct {
	Type ItemType
	Data []byte
}

// MaxItems bounds the items [DecodeCPF] accepts.
const MaxItems = 64

// AppendCPF appends a common packet format: the item count and the items.
func AppendCPF(b []byte, items []Item) ([]byte, error) {
	if len(items) > MaxItems {
		return b, fmt.Errorf("%w: %d items", ErrTooLarge, len(items))
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(items)))
	for _, it := range items {
		if len(it.Data) > math.MaxUint16 {
			return b, fmt.Errorf("%w: %s item of %d octets", ErrTooLarge, it.Type, len(it.Data))
		}
		b = binary.LittleEndian.AppendUint16(b, uint16(it.Type))
		b = binary.LittleEndian.AppendUint16(b, uint16(len(it.Data)))
		b = append(b, it.Data...)
	}
	return b, nil
}

// DecodeCPF decodes a common packet format that fills b exactly. The items'
// data alias b.
func DecodeCPF(b []byte) ([]Item, error) {
	items, rest, err := decodeCPF(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d octets after the items", ErrMalformed, len(rest))
	}
	return items, nil
}

func decodeCPF(b []byte) ([]Item, []byte, error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("%w: item count", ErrTruncated)
	}
	n := int(binary.LittleEndian.Uint16(b))
	if n > MaxItems {
		return nil, nil, fmt.Errorf("%w: %d items", ErrMalformed, n)
	}
	b = b[2:]
	items := make([]Item, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 4 {
			return nil, nil, fmt.Errorf("%w: item %d header", ErrTruncated, i)
		}
		t := ItemType(binary.LittleEndian.Uint16(b))
		l := int(binary.LittleEndian.Uint16(b[2:]))
		if len(b)-4 < l {
			return nil, nil, fmt.Errorf("%w: %s item of %d octets, %d left", ErrTruncated, t, l, len(b)-4)
		}
		items = append(items, Item{Type: t, Data: b[4 : 4+l : 4+l]})
		b = b[4+l:]
	}
	return items, b, nil
}

// Find returns the first item of type t.
func Find(items []Item, t ItemType) (Item, bool) {
	for _, it := range items {
		if it.Type == t {
			return it, true
		}
	}
	return Item{}, false
}

// RRData is the data of SendRRData and SendUnitData: the interface handle
// (0 for CIP), a timeout in seconds (SendRRData; 0 in SendUnitData) and the
// common packet format.
type RRData struct {
	InterfaceHandle uint32
	Timeout         uint16
	Items           []Item
}

// Encode returns the data.
func (d RRData) Encode() ([]byte, error) {
	size := 8
	for _, it := range d.Items {
		size += 4 + len(it.Data)
	}
	b := make([]byte, 0, size)
	b = binary.LittleEndian.AppendUint32(b, d.InterfaceHandle)
	b = binary.LittleEndian.AppendUint16(b, d.Timeout)
	return AppendCPF(b, d.Items)
}

// DecodeRRData decodes the data of SendRRData or SendUnitData. The items'
// data alias b.
func DecodeRRData(b []byte) (RRData, error) {
	if len(b) < 6 {
		return RRData{}, fmt.Errorf("%w: interface handle and timeout", ErrTruncated)
	}
	d := RRData{InterfaceHandle: binary.LittleEndian.Uint32(b), Timeout: binary.LittleEndian.Uint16(b[4:])}
	items, err := DecodeCPF(b[6:])
	if err != nil {
		return d, err
	}
	d.Items = items
	return d, nil
}

// Sockaddr is the socket address of a Sockaddr Info item or of a
// ListIdentity reply: sin_family, sin_port and sin_addr in network byte
// order, and 8 octets of zero.
type Sockaddr struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
}

// AFInet is the address family of IPv4.
const AFInet = 2

// SockaddrOf returns the Sockaddr of an IPv4 address and port.
func SockaddrOf(ap netip.AddrPort) Sockaddr {
	return Sockaddr{Family: AFInet, Port: ap.Port(), Addr: ap.Addr().Unmap().As4()}
}

// AddrPort returns the address and port.
func (s Sockaddr) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(s.Addr), s.Port)
}

// Encode returns the 16 octets.
func (s Sockaddr) Encode() []byte { return s.AppendTo(make([]byte, 0, 16)) }

// AppendTo appends the 16 octets.
func (s Sockaddr) AppendTo(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, s.Family)
	b = binary.BigEndian.AppendUint16(b, s.Port)
	b = append(b, s.Addr[:]...)
	return append(b, 0, 0, 0, 0, 0, 0, 0, 0)
}

// DecodeSockaddr decodes the 16 octets at the start of b.
func DecodeSockaddr(b []byte) (Sockaddr, error) {
	if len(b) < 16 {
		return Sockaddr{}, fmt.Errorf("%w: sockaddr of %d octets", ErrTruncated, len(b))
	}
	var s Sockaddr
	s.Family = binary.BigEndian.Uint16(b)
	s.Port = binary.BigEndian.Uint16(b[2:])
	copy(s.Addr[:], b[4:8])
	return s, nil
}

// IdentityItem is the CIP Identity item of a ListIdentity reply.
type IdentityItem struct {
	// ProtocolVersion is the encapsulation protocol version (1).
	ProtocolVersion uint16
	// Socket is the address of the device's TCP port.
	Socket Sockaddr
	cip.Identity
}

// Encode returns the item data.
func (it IdentityItem) Encode() ([]byte, error) {
	b := binary.LittleEndian.AppendUint16(make([]byte, 0, 64), it.ProtocolVersion)
	b = it.Socket.AppendTo(b)
	b, err := it.Identity.AppendAttributes(b)
	if err != nil {
		return nil, err
	}
	return append(b, it.State), nil
}

// DecodeIdentityItem decodes the data of a CIP Identity item.
func DecodeIdentityItem(b []byte) (IdentityItem, error) {
	var it IdentityItem
	if len(b) < 2 {
		return it, fmt.Errorf("%w: identity item", ErrTruncated)
	}
	it.ProtocolVersion = binary.LittleEndian.Uint16(b)
	s, err := DecodeSockaddr(b[2:])
	if err != nil {
		return it, err
	}
	it.Socket = s
	id, err := cip.DecodeIdentity(b[18:])
	if err != nil {
		return it, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	it.Identity = id
	return it, nil
}

// Service capability flags of a ListServices reply.
const (
	// CapabilityTCP is set when the device supports CIP encapsulation over
	// TCP (explicit messaging).
	CapabilityTCP uint16 = 0x0020
	// CapabilityUDP is set when the device supports CIP Class 0 and 1
	// messaging over UDP (implicit messaging).
	CapabilityUDP uint16 = 0x0100
)

// ServiceItem is the item of a ListServices reply.
type ServiceItem struct {
	Version      uint16
	Capabilities uint16
	// Name is the service name, at most 16 octets ("Communications").
	Name string
}

// Encode returns the item data.
func (it ServiceItem) Encode() ([]byte, error) {
	if len(it.Name) > 16 {
		return nil, fmt.Errorf("%w: service name of %d octets", ErrTooLarge, len(it.Name))
	}
	b := binary.LittleEndian.AppendUint16(make([]byte, 0, 20), it.Version)
	b = binary.LittleEndian.AppendUint16(b, it.Capabilities)
	var name [16]byte
	copy(name[:], it.Name)
	return append(b, name[:]...), nil
}

// DecodeServiceItem decodes the data of a ListServices item.
func DecodeServiceItem(b []byte) (ServiceItem, error) {
	if len(b) < 20 {
		return ServiceItem{}, fmt.Errorf("%w: service item of %d octets", ErrTruncated, len(b))
	}
	name := b[4:20]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	return ServiceItem{
		Version:      binary.LittleEndian.Uint16(b),
		Capabilities: binary.LittleEndian.Uint16(b[2:]),
		Name:         string(name),
	}, nil
}

// SequencedAddress is the data of a Sequenced Address item: the
// connection ID and the encapsulation sequence number of an I/O message.
type SequencedAddress struct {
	ConnID   uint32
	Sequence uint32
}

// Encode returns the 8 octets.
func (a SequencedAddress) Encode() []byte {
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, 8), a.ConnID)
	return binary.LittleEndian.AppendUint32(b, a.Sequence)
}

// DecodeSequencedAddress decodes the data of a Sequenced Address item.
func DecodeSequencedAddress(b []byte) (SequencedAddress, error) {
	if len(b) != 8 {
		return SequencedAddress{}, fmt.Errorf("%w: sequenced address of %d octets", ErrMalformed, len(b))
	}
	return SequencedAddress{binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])}, nil
}

// ConnectedAddress returns a Connected Address item for a connection ID.
func ConnectedAddress(connID uint32) Item {
	return Item{Type: ItemConnectedAddress, Data: binary.LittleEndian.AppendUint32(nil, connID)}
}

// DecodeConnectedAddress returns the connection ID of a Connected Address
// item.
func DecodeConnectedAddress(it Item) (uint32, error) {
	if it.Type != ItemConnectedAddress || len(it.Data) != 4 {
		return 0, fmt.Errorf("%w: connected address item %s of %d octets", ErrMalformed, it.Type, len(it.Data))
	}
	return binary.LittleEndian.Uint32(it.Data), nil
}
