// SPDX-License-Identifier: MIT

package cip

import (
	"fmt"
	"math"
)

// Request is an explicit message request to the Message Router: a service,
// the path of the object it is addressed to, and the service data.
type Request struct {
	Service Service
	Path    Path
	Data    []byte
}

// String returns for example "Get_Attribute_Single @1/1/7".
func (r Request) String() string {
	c, _ := r.Path.Class()
	return ServiceName(c, r.Service) + " " + r.Path.String()
}

// Encode returns the encoding of the request: service, path size in words,
// padded path, data.
func (r Request) Encode() ([]byte, error) { return r.AppendTo(nil) }

// AppendTo appends the encoding of the request to b.
func (r Request) AppendTo(b []byte) ([]byte, error) {
	if r.Service&ReplyBit != 0 {
		return b, fmt.Errorf("%w: request service 0x%02X has the reply bit", ErrMalformed, uint8(r.Service))
	}
	start := len(b)
	b = append(b, byte(r.Service), 0)
	b, err := r.Path.AppendTo(b, false)
	if err != nil {
		return b[:start], err
	}
	n := len(b) - start - 2
	if n%2 != 0 || n/2 > math.MaxUint8 {
		return b[:start], fmt.Errorf("%w: request path of %d octets", ErrTooLarge, n)
	}
	b[start+1] = byte(n / 2)
	return append(b, r.Data...), nil
}

// DecodeRequest decodes a request. The data aliases b.
func DecodeRequest(b []byte) (Request, error) {
	r := NewReader(b)
	svc := Service(r.Uint8())
	words := int(r.Uint8())
	raw := r.Bytes(2 * words)
	if err := r.Err(); err != nil {
		return Request{}, fmt.Errorf("request: %w", err)
	}
	if svc&ReplyBit != 0 {
		return Request{}, fmt.Errorf("%w: request service 0x%02X has the reply bit", ErrMalformed, uint8(svc))
	}
	p, err := DecodePath(raw)
	if err != nil {
		return Request{Service: svc}, fmt.Errorf("request path: %w", err)
	}
	return Request{Service: svc, Path: p, Data: r.Rest()}, nil
}

// Response is an explicit message response.
type Response struct {
	// Service is the service of the request; the reply bit is removed
	// when decoding and added when encoding.
	Service Service
	// Status is the general status.
	Status GeneralStatus
	// Extended is the additional status, at most 255 words.
	Extended []uint16
	// Data is the response data.
	Data []byte
}

// OK reports whether the general status is success.
func (r Response) OK() bool { return r.Status == StatusSuccess }

// Encode returns the encoding of the response: service with the reply bit,
// reserved octet, general status, additional status size in words,
// additional status, data.
func (r Response) Encode() ([]byte, error) { return r.AppendTo(nil) }

// AppendTo appends the encoding of the response to b.
func (r Response) AppendTo(b []byte) ([]byte, error) {
	if len(r.Extended) > math.MaxUint8 {
		return b, fmt.Errorf("%w: %d additional status words", ErrTooLarge, len(r.Extended))
	}
	b = append(b, byte(r.Service|ReplyBit), 0, byte(r.Status), byte(len(r.Extended)))
	for _, w := range r.Extended {
		b = AppendUint16(b, w)
	}
	return append(b, r.Data...), nil
}

// DecodeResponse decodes a response. The data aliases b.
func DecodeResponse(b []byte) (Response, error) {
	r := NewReader(b)
	svc := Service(r.Uint8())
	r.Skip(1)
	st := GeneralStatus(r.Uint8())
	n := int(r.Uint8())
	if r.Err() == nil && n > r.Len()/2 {
		return Response{}, fmt.Errorf("response: %w: %d additional status words in %d octets", ErrTruncated, n, r.Len())
	}
	var ext []uint16
	if n > 0 {
		ext = make([]uint16, n)
		for i := range ext {
			ext[i] = r.Uint16()
		}
	}
	if err := r.Err(); err != nil {
		return Response{}, fmt.Errorf("response: %w", err)
	}
	if svc&ReplyBit == 0 {
		return Response{}, fmt.Errorf("%w: response service 0x%02X lacks the reply bit", ErrMalformed, uint8(svc))
	}
	return Response{Service: svc &^ ReplyBit, Status: st, Extended: ext, Data: r.Rest()}, nil
}

// ErrorResponse returns a response to req with status st and optional
// additional status words.
func ErrorResponse(req Request, st GeneralStatus, ext ...uint16) Response {
	return Response{Service: req.Service, Status: st, Extended: ext}
}

// EncodeMultipleService returns the request data of a Multiple Service
// Packet (0x0A) carrying reqs: their count, the offset of each from the
// start of the count, and the encoded requests.
func EncodeMultipleService(reqs []Request) ([]byte, error) {
	if len(reqs) == 0 || len(reqs) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: multiple service packet of %d requests", ErrTooLarge, len(reqs))
	}
	enc := make([][]byte, len(reqs))
	for i, r := range reqs {
		b, err := r.Encode()
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i, err)
		}
		enc[i] = b
	}
	return packMultiple(enc)
}

// EncodeMultipleServiceResponse returns the response data of a Multiple
// Service Packet carrying resps.
func EncodeMultipleServiceResponse(resps []Response) ([]byte, error) {
	if len(resps) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: multiple service packet of %d responses", ErrTooLarge, len(resps))
	}
	enc := make([][]byte, len(resps))
	for i, r := range resps {
		b, err := r.Encode()
		if err != nil {
			return nil, fmt.Errorf("response %d: %w", i, err)
		}
		enc[i] = b
	}
	return packMultiple(enc)
}

func packMultiple(items [][]byte) ([]byte, error) {
	off := 2 + 2*len(items)
	total := off
	for _, it := range items {
		total += len(it)
	}
	b := make([]byte, 0, total)
	b = AppendUint16(b, uint16(len(items)))
	for _, it := range items {
		if off > math.MaxUint16 {
			return nil, fmt.Errorf("%w: multiple service packet of %d octets", ErrTooLarge, total)
		}
		b = AppendUint16(b, uint16(off))
		off += len(it)
	}
	for _, it := range items {
		b = append(b, it...)
	}
	return b, nil
}

// SplitMultiple splits the data of a Multiple Service Packet request or
// response into its embedded messages. The slices alias b. Offsets must be
// within b and increasing; each message ends where the next begins.
func SplitMultiple(b []byte) ([][]byte, error) {
	r := NewReader(b)
	n := int(r.Uint16())
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("multiple service packet: %w", err)
	}
	if n == 0 {
		return nil, nil
	}
	if n > (len(b)-2)/2 {
		return nil, fmt.Errorf("multiple service packet: %w: %d services in %d octets", ErrTruncated, n, len(b))
	}
	offs := make([]int, n+1)
	for i := 0; i < n; i++ {
		offs[i] = int(r.Uint16())
	}
	offs[n] = len(b)
	lo := 2 + 2*n
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		if offs[i] < lo || offs[i] > offs[i+1] || offs[i+1] > len(b) {
			return nil, fmt.Errorf("multiple service packet: %w: offset %d of service %d", ErrMalformed, offs[i], i)
		}
		lo = offs[i]
		out[i] = b[offs[i]:offs[i+1]:offs[i+1]]
	}
	return out, nil
}
