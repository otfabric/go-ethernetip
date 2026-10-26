// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Doer sends an explicit request and returns the response. *[Client]
// (unconnected messaging) and *[Conn] (connected messaging) implement it,
// so that code such as the logix package works over either.
type Doer interface {
	Do(ctx context.Context, req cip.Request) (cip.Response, error)
}

// Do sends an unconnected explicit request (SendRRData), through
// Unconnected_Send when the client has a route, and returns the response.
//
// A response whose general status is not success is returned together with
// a *ethernetip.CIPError, so that its data (some services return data with
// an error, and partial transfers carry a fragment) is not lost.
func (c *Client) Do(ctx context.Context, req cip.Request) (cip.Response, error) {
	resp, _, err := c.do(ctx, req, nil, c.opts.route)
	return resp, err
}

// DoRoute is Do with route in place of the client's route: nil sends the
// request to the target itself.
func (c *Client) DoRoute(ctx context.Context, req cip.Request, route cip.Path) (cip.Response, error) {
	resp, _, err := c.do(ctx, req, nil, route)
	return resp, err
}

// do sends req with extra CPF items and returns the response and the
// reply's other items.
func (c *Client) do(ctx context.Context, req cip.Request, extra []encap.Item, route cip.Path) (cip.Response, []encap.Item, error) {
	start := time.Now()
	c.reportRequest(req.Service)
	resp, items, err := c.doUnreported(ctx, req, extra, route)
	c.reportDone(req.Service, start, err)
	return resp, items, err
}

func (c *Client) doUnreported(ctx context.Context, req cip.Request, extra []encap.Item, route cip.Path) (cip.Response, []encap.Item, error) {
	sent := req
	if len(route) > 0 {
		pt, ticks := cip.Ticks(c.opts.timeout)
		us := cip.UnconnectedSend{PriorityTick: pt, TimeoutTicks: ticks, Request: req, Route: route}
		data, err := us.Encode()
		if err != nil {
			return cip.Response{}, nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
		}
		sent = cip.Request{Service: cip.ServiceUnconnectedSend, Path: cip.ConnectionManagerPath(), Data: data}
	}
	msg, err := sent.Encode()
	if err != nil {
		return cip.Response{}, nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	items := append([]encap.Item{{Type: encap.ItemNullAddress}, {Type: encap.ItemUnconnectedData, Data: msg}}, extra...)
	timeout := uint16(c.opts.timeout / time.Second)
	data, err := encap.RRData{Timeout: timeout, Items: items}.Encode()
	if err != nil {
		return cip.Response{}, nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	pkt, err := c.roundTrip(ctx, encap.CommandSendRRData, data)
	if err != nil {
		return cip.Response{}, nil, err
	}
	rr, err := encap.DecodeRRData(pkt.Data)
	if err != nil {
		return cip.Response{}, nil, c.protocolError("SendRRData reply", err)
	}
	it, ok := encap.Find(rr.Items, encap.ItemUnconnectedData)
	if !ok {
		return cip.Response{}, rr.Items, c.protocolError("SendRRData reply", errors.New("no unconnected data item"))
	}
	resp, err := cip.DecodeResponse(it.Data)
	if err != nil {
		return cip.Response{}, rr.Items, c.protocolError("SendRRData reply", err)
	}
	return checkResponse(req, resp, len(route) > 0, rr.Items)
}

// checkResponse matches a response with its request and turns an error
// status into a *CIPError. routed requests may be answered by the
// Connection Manager with an Unconnected_Send error instead.
func checkResponse(req cip.Request, resp cip.Response, routed bool, items []encap.Item) (cip.Response, []encap.Item, error) {
	if resp.Service != req.Service {
		if routed && resp.Service == cip.ServiceUnconnectedSend && !resp.OK() {
			return resp, items, &ethernetip.CIPError{Service: cip.ServiceUnconnectedSend, Path: cip.ConnectionManagerPath(),
				Status: resp.Status, Extended: resp.Extended, Data: resp.Data}
		}
		return resp, items, fmt.Errorf("%w: reply to service 0x%02X for request 0x%02X", ethernetip.ErrProtocol, uint8(resp.Service), uint8(req.Service))
	}
	if !resp.OK() {
		return resp, items, &ethernetip.CIPError{Service: req.Service, Path: req.Path, Status: resp.Status, Extended: resp.Extended, Data: resp.Data}
	}
	return resp, items, nil
}

func (c *Client) protocolError(what string, err error) error {
	if m := c.opts.metrics; m != nil {
		m.OnDecodeError(nil, err)
	}
	return fmt.Errorf("%w: %s: %w", ethernetip.ErrProtocol, what, err)
}

func (c *Client) reportRequest(s cip.Service) {
	if c.rm != nil {
		c.rm.OnRequest(c.remote(), s)
	}
}

func (c *Client) reportDone(s cip.Service, start time.Time, err error) {
	if c.rm != nil {
		c.rm.OnRequestDone(c.remote(), s, time.Since(start), err)
	}
}

func (c *Client) remote() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return nil
	}
	return c.sess.remote
}

// GetAttributeSingle reads one attribute (service 0x0E) and returns its
// value as the target encodes it.
func (c *Client) GetAttributeSingle(ctx context.Context, class cip.Class, instance uint32, attribute uint16) ([]byte, error) {
	return getAttributeSingle(ctx, c, class, instance, attribute)
}

// SetAttributeSingle writes one attribute (service 0x10).
func (c *Client) SetAttributeSingle(ctx context.Context, class cip.Class, instance uint32, attribute uint16, value []byte) error {
	return setAttributeSingle(ctx, c, class, instance, attribute, value)
}

// GetAttributesAll reads the attributes of an instance, or of the class
// with instance 0, with service 0x01. The layout of the data is defined by
// the object.
func (c *Client) GetAttributesAll(ctx context.Context, class cip.Class, instance uint32) ([]byte, error) {
	return getAttributesAll(ctx, c, class, instance)
}

// SetAttributesAll writes the settable attributes of an instance with
// service 0x02, where the object defines it.
func (c *Client) SetAttributesAll(ctx context.Context, class cip.Class, instance uint32, data []byte) error {
	_, err := c.Do(ctx, cip.Request{Service: cip.ServiceSetAttributesAll, Path: cip.ObjectPath(class, instance), Data: data})
	return err
}

// Reset sends service 0x05 to an instance; resetType is the object's reset
// parameter (for the Identity object 0: power cycle, 1: return to factory
// defaults) and is omitted when negative.
func (c *Client) Reset(ctx context.Context, class cip.Class, instance uint32, resetType int) error {
	var data []byte
	if resetType >= 0 {
		data = []byte{byte(resetType)}
	}
	_, err := c.Do(ctx, cip.Request{Service: cip.ServiceReset, Path: cip.ObjectPath(class, instance), Data: data})
	return err
}

// AttributeValue is one attribute of a Get_Attribute_List reply.
type AttributeValue struct {
	ID     uint16
	Status cip.GeneralStatus
	Value  []byte
}

// GetAttributeList reads several attributes with service 0x03. sizes gives
// the encoded size of each attribute's value, which the reply does not
// carry; a size of 0 takes the rest of the reply (the last attribute
// only). The reply's status may be 0x0A (attribute list error) with values
// for the attributes that were read: the result is returned together with
// the error.
func (c *Client) GetAttributeList(ctx context.Context, class cip.Class, instance uint32, ids []uint16, sizes []int) ([]AttributeValue, error) {
	if len(ids) == 0 || len(ids) != len(sizes) {
		return nil, fmt.Errorf("%w: %d attributes with %d sizes", ethernetip.ErrInvalidOption, len(ids), len(sizes))
	}
	data := cip.AppendUint16(nil, uint16(len(ids)))
	for _, id := range ids {
		data = cip.AppendUint16(data, id)
	}
	resp, err := c.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeList, Path: cip.ObjectPath(class, instance), Data: data})
	if err != nil && (resp.Status != cip.StatusAttributeListError || resp.Data == nil) {
		return nil, err
	}
	vals, derr := decodeAttributeList(resp.Data, sizes)
	if derr != nil {
		return nil, c.protocolError("Get_Attribute_List reply", derr)
	}
	return vals, err
}

func decodeAttributeList(b []byte, sizes []int) ([]AttributeValue, error) {
	r := cip.NewReader(b)
	n := int(r.Uint16())
	if r.Err() == nil && n != len(sizes) {
		return nil, fmt.Errorf("%d attributes in reply to %d", n, len(sizes))
	}
	out := make([]AttributeValue, 0, n)
	for i := 0; i < n && r.Err() == nil; i++ {
		v := AttributeValue{ID: r.Uint16(), Status: cip.GeneralStatus(r.Uint16())}
		if v.Status == cip.StatusSuccess {
			size := sizes[i]
			if size == 0 {
				size = r.Len()
			}
			v.Value = append([]byte(nil), r.Bytes(size)...)
		}
		out = append(out, v)
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Identity reads the Identity object instance 1 with Get_Attributes_All.
func (c *Client) Identity(ctx context.Context) (cip.Identity, error) {
	return identity(ctx, c)
}

// MultipleService sends reqs in one Multiple Service Packet (0x0A) to the
// Message Router and returns one response per request, in order. The
// packet's own status 0x1E (embedded service error) is not an error: each
// response carries its status; use [ResponseError] to turn one into an
// error.
func (c *Client) MultipleService(ctx context.Context, reqs []cip.Request) ([]cip.Response, error) {
	return multipleService(ctx, c, reqs)
}

// ResponseError returns the *ethernetip.CIPError of resp, the response to
// req, or nil when its status is success.
func ResponseError(req cip.Request, resp cip.Response) error {
	if resp.OK() {
		return nil
	}
	return &ethernetip.CIPError{Service: req.Service, Path: req.Path, Status: resp.Status, Extended: resp.Extended, Data: resp.Data}
}

func getAttributeSingle(ctx context.Context, d Doer, class cip.Class, instance uint32, attribute uint16) ([]byte, error) {
	resp, err := d.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(class, instance, attribute)})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func setAttributeSingle(ctx context.Context, d Doer, class cip.Class, instance uint32, attribute uint16, value []byte) error {
	_, err := d.Do(ctx, cip.Request{Service: cip.ServiceSetAttributeSingle, Path: cip.AttributePath(class, instance, attribute), Data: value})
	return err
}

func getAttributesAll(ctx context.Context, d Doer, class cip.Class, instance uint32) ([]byte, error) {
	resp, err := d.Do(ctx, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(class, instance)})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func identity(ctx context.Context, d Doer) (cip.Identity, error) {
	b, err := getAttributesAll(ctx, d, cip.ClassIdentity, 1)
	if err != nil {
		return cip.Identity{}, err
	}
	id, err := cip.DecodeIdentity(b)
	if err != nil {
		return cip.Identity{}, fmt.Errorf("%w: %w", ethernetip.ErrProtocol, err)
	}
	return id, nil
}

func multipleService(ctx context.Context, d Doer, reqs []cip.Request) ([]cip.Response, error) {
	data, err := cip.EncodeMultipleService(reqs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	resp, err := d.Do(ctx, cip.Request{Service: cip.ServiceMultipleServicePacket, Path: cip.MessageRouterPath(), Data: data})
	if err != nil && resp.Status != cip.StatusEmbeddedServiceError {
		return nil, err
	}
	parts, err := cip.SplitMultiple(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: multiple service reply: %w", ethernetip.ErrProtocol, err)
	}
	if len(parts) != len(reqs) {
		return nil, fmt.Errorf("%w: %d replies to %d requests", ethernetip.ErrProtocol, len(parts), len(reqs))
	}
	out := make([]cip.Response, len(parts))
	for i, p := range parts {
		r, err := cip.DecodeResponse(p)
		if err != nil {
			return nil, fmt.Errorf("%w: reply %d: %w", ethernetip.ErrProtocol, i, err)
		}
		if r.Service != reqs[i].Service {
			return nil, fmt.Errorf("%w: reply %d to service 0x%02X for 0x%02X", ethernetip.ErrProtocol, i, uint8(r.Service), uint8(reqs[i].Service))
		}
		out[i] = r
	}
	return out, nil
}

// ListIdentity sends ListIdentity over the session's TCP connection and
// returns the target's identity item.
func (c *Client) ListIdentity(ctx context.Context) (encap.IdentityItem, error) {
	pkt, err := c.roundTrip(ctx, encap.CommandListIdentity, nil)
	if err != nil {
		return encap.IdentityItem{}, err
	}
	return decodeListIdentity(pkt.Data)
}

func decodeListIdentity(b []byte) (encap.IdentityItem, error) {
	items, err := encap.DecodeCPF(b)
	if err != nil {
		return encap.IdentityItem{}, fmt.Errorf("%w: ListIdentity reply: %w", ethernetip.ErrProtocol, err)
	}
	it, ok := encap.Find(items, encap.ItemListIdentity)
	if !ok {
		return encap.IdentityItem{}, fmt.Errorf("%w: ListIdentity reply without an identity item", ethernetip.ErrProtocol)
	}
	id, err := encap.DecodeIdentityItem(it.Data)
	if err != nil {
		return id, fmt.Errorf("%w: ListIdentity reply: %w", ethernetip.ErrProtocol, err)
	}
	return id, nil
}

// ListServices sends ListServices over the session's TCP connection and
// returns the services the target offers.
func (c *Client) ListServices(ctx context.Context) ([]encap.ServiceItem, error) {
	pkt, err := c.roundTrip(ctx, encap.CommandListServices, nil)
	if err != nil {
		return nil, err
	}
	return decodeListServices(pkt.Data)
}

func decodeListServices(b []byte) ([]encap.ServiceItem, error) {
	items, err := encap.DecodeCPF(b)
	if err != nil {
		return nil, fmt.Errorf("%w: ListServices reply: %w", ethernetip.ErrProtocol, err)
	}
	var out []encap.ServiceItem
	for _, it := range items {
		if it.Type != encap.ItemListServices {
			continue
		}
		s, err := encap.DecodeServiceItem(it.Data)
		if err != nil {
			return nil, fmt.Errorf("%w: ListServices reply: %w", ethernetip.ErrProtocol, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// ListInterfaces sends ListInterfaces over the session's TCP connection and
// returns the items of the reply; most targets have none.
func (c *Client) ListInterfaces(ctx context.Context) ([]encap.Item, error) {
	pkt, err := c.roundTrip(ctx, encap.CommandListInterfaces, nil)
	if err != nil {
		return nil, err
	}
	items, err := encap.DecodeCPF(pkt.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: ListInterfaces reply: %w", ethernetip.ErrProtocol, err)
	}
	return items, nil
}
