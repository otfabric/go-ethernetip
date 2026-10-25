// SPDX-License-Identifier: MIT

package logix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
)

// Client reads and writes the tags of a Logix controller over a
// client.Doer: a *client.Client (unconnected, usually routed to the
// controller's slot with client.WithRoute) or a *client.Conn (Class 3, as
// Logix tools use). It is safe for concurrent use.
type Client struct {
	d       client.Doer
	maxData int

	mu        sync.Mutex
	templates map[uint16]*Template
}

// ClientOption configures a [Client].
type ClientOption func(*Client)

// WithMaxData sets the largest data a request or reply may carry before
// the fragmented services are used: about the connection size of a Class 3
// connection less 40 octets, and 480 for unconnected messaging (the
// default).
func WithMaxData(n int) ClientOption {
	return func(c *Client) {
		if n >= 64 {
			c.maxData = n
		}
	}
}

// NewClient returns a client of the controller d speaks to.
func NewClient(d client.Doer, opts ...ClientOption) *Client {
	c := &Client{d: d, maxData: 480, templates: map[uint16]*Template{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

func tagPath(name string) (cip.Path, error) {
	tp, err := ParseTag(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	if tp.Bit >= 0 {
		return nil, fmt.Errorf("%w: %q addresses a bit: read the integer, or use WriteBit", ethernetip.ErrInvalidOption, name)
	}
	return tp.Path, nil
}

// Read reads count elements of a tag (or of an element or member of one)
// with Read Tag, continuing with Read Tag Fragmented while the controller
// answers with partial transfers.
func (c *Client) Read(ctx context.Context, tag string, count int) (Value, error) {
	path, err := tagPath(tag)
	if err != nil {
		return Value{}, err
	}
	if count < 1 || count > 0xFFFF {
		return Value{}, fmt.Errorf("%w: count %d", ethernetip.ErrInvalidOption, count)
	}
	return c.read(ctx, path, count)
}

func (c *Client) read(ctx context.Context, path cip.Path, count int) (Value, error) {
	resp, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceReadTag, Path: path, Data: cip.AppendUint16(nil, uint16(count))})
	partial := err != nil && resp.Status == cip.StatusPartialTransfer
	if err != nil && !partial {
		return Value{}, err
	}
	v, data, err := decodeRead(resp.Data)
	if err != nil {
		return Value{}, err
	}
	v.Count = count
	for partial {
		req := cip.AppendUint16(nil, uint16(count))
		req = cip.AppendUint32(req, uint32(len(data)))
		resp, err = c.d.Do(ctx, cip.Request{Service: cip.ServiceReadTagFragmented, Path: path, Data: req})
		partial = err != nil && resp.Status == cip.StatusPartialTransfer
		if err != nil && !partial {
			return Value{}, err
		}
		_, more, err := decodeRead(resp.Data)
		if err != nil {
			return Value{}, err
		}
		if len(more) == 0 && partial {
			return Value{}, fmt.Errorf("%w: empty partial transfer", ethernetip.ErrProtocol)
		}
		data = append(data, more...)
		if len(data) > 1<<24 {
			return Value{}, fmt.Errorf("%w: fragmented read beyond 16 MiB", ethernetip.ErrProtocol)
		}
	}
	v.Data = data
	if n := v.ElemSize(); !v.IsStruct() && n > 0 && len(data) != n*count {
		return v, fmt.Errorf("%w: %d octets for %d elements of %s", ethernetip.ErrProtocol, len(data), count, v.Type)
	}
	return v, nil
}

func decodeRead(b []byte) (Value, []byte, error) {
	r := cip.NewReader(b)
	t, h := decodeType(r)
	if err := r.Err(); err != nil {
		return Value{}, nil, fmt.Errorf("%w: Read Tag reply: %w", ethernetip.ErrProtocol, err)
	}
	return Value{Type: t, Handle: h}, append([]byte(nil), r.Rest()...), nil
}

// Write writes v to a tag (or an element or member of one) with Write
// Tag, or Write Tag Fragmented when the data is larger than the client's
// maximum. The value's type must be the tag's.
func (c *Client) Write(ctx context.Context, tag string, v Value) error {
	path, err := tagPath(tag)
	if err != nil {
		return err
	}
	return c.write(ctx, path, v)
}

func (c *Client) write(ctx context.Context, path cip.Path, v Value) error {
	if v.Count < 1 || v.Count > 0xFFFF || len(v.Data) == 0 {
		return fmt.Errorf("%w: value %s", ethernetip.ErrInvalidOption, v)
	}
	if len(v.Data) <= c.maxData {
		req := cip.AppendUint16(v.appendType(nil), uint16(v.Count))
		_, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceWriteTag, Path: path, Data: append(req, v.Data...)})
		return err
	}
	step := c.maxData
	if n := v.ElemSize(); n > 0 && n < step {
		step -= step % n
	}
	for off := 0; off < len(v.Data); off += step {
		end := min(off+step, len(v.Data))
		req := cip.AppendUint16(v.appendType(nil), uint16(v.Count))
		req = cip.AppendUint32(req, uint32(off))
		if _, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceWriteTagFragmented, Path: path, Data: append(req, v.Data[off:end]...)}); err != nil {
			return err
		}
	}
	return nil
}

// WriteBit sets or clears one bit of an integer tag with Read-Modify-Write
// Tag; the name ends in the bit number ("Flags.3"). size is the integer's
// size in octets (1, 2, 4 or 8).
func (c *Client) WriteBit(ctx context.Context, tag string, size int, set bool) error {
	tp, err := ParseTag(tag)
	if err != nil {
		return fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
	}
	if tp.Bit < 0 || (size != 1 && size != 2 && size != 4 && size != 8) || tp.Bit >= 8*size {
		return fmt.Errorf("%w: bit write of %q on %d octets", ethernetip.ErrInvalidOption, tag, size)
	}
	or := make([]byte, size)
	and := make([]byte, size)
	for i := range and {
		and[i] = 0xFF
	}
	if set {
		or[tp.Bit/8] |= 1 << (tp.Bit % 8)
	} else {
		and[tp.Bit/8] &^= 1 << (tp.Bit % 8)
	}
	data := cip.AppendUint16(nil, uint16(size))
	data = append(append(data, or...), and...)
	_, err = c.d.Do(ctx, cip.Request{Service: cip.ServiceReadModifyWriteTag, Path: tp.Path, Data: data})
	return err
}

// Result is the outcome of one tag of ReadMany.
type Result struct {
	Tag   string
	Value Value
	Err   error
}

// ReadMany reads one element of each tag in one Multiple Service Packet
// (per batch that fits the client's maximum). Errors of single tags are in
// their Result; the returned error is for the exchange itself.
func (c *Client) ReadMany(ctx context.Context, tags []string) ([]Result, error) {
	out := make([]Result, len(tags))
	var reqs []cip.Request
	var idx []int
	size := 2
	flush := func() error {
		if len(reqs) == 0 {
			return nil
		}
		resps, err := msp(ctx, c.d, reqs)
		if err != nil {
			return err
		}
		for i, r := range resps {
			k := idx[i]
			if err := client.ResponseError(reqs[i], r); err != nil {
				out[k].Err = err
				continue
			}
			v, data, err := decodeRead(r.Data)
			v.Count, v.Data = 1, data
			out[k].Value, out[k].Err = v, err
		}
		reqs, idx, size = nil, nil, 2
		return nil
	}
	for i, t := range tags {
		out[i].Tag = t
		path, err := tagPath(t)
		if err != nil {
			out[i].Err = err
			continue
		}
		req := cip.Request{Service: cip.ServiceReadTag, Path: path, Data: []byte{1, 0}}
		enc, err := req.Encode()
		if err != nil {
			out[i].Err = fmt.Errorf("%w: %w", ethernetip.ErrInvalidOption, err)
			continue
		}
		if size+2+len(enc) > c.maxData {
			if err := flush(); err != nil {
				return out, err
			}
		}
		reqs, idx = append(reqs, req), append(idx, i)
		size += 2 + len(enc)
	}
	return out, flush()
}

// msp sends a Multiple Service Packet; it uses the method of the doer when
// it has one.
func msp(ctx context.Context, d client.Doer, reqs []cip.Request) ([]cip.Response, error) {
	type multi interface {
		MultipleService(context.Context, []cip.Request) ([]cip.Response, error)
	}
	if m, ok := d.(multi); ok {
		return m.MultipleService(ctx, reqs)
	}
	return nil, fmt.Errorf("%w: the doer has no MultipleService", ethernetip.ErrUnsupported)
}

// Tag is an entry of the controller's tag list.
type Tag struct {
	// Instance is the Symbol object instance.
	Instance uint32
	// Name is the tag's name; program-scoped tags of ListTags(program) are
	// returned with the "Program:Name." prefix.
	Name string
	Type SymbolType
	// Dims are the array dimensions (zero when absent).
	Dims [3]uint32
}

// ListTags reads the tag list of the Symbol object with Get Instance
// Attribute List (0x55): controller-scoped tags when program is "", the
// tags of a program ("Program:Main") otherwise. System tags and the names
// of programs are included as the controller reports them.
func (c *Client) ListTags(ctx context.Context, program string) ([]Tag, error) {
	var prefix cip.Path
	if program != "" {
		if !strings.HasPrefix(strings.ToLower(program), "program:") {
			program = "Program:" + program
		}
		prefix = cip.Path{cip.SymbolSegment{Name: program}}
	}
	var out []Tag
	next := uint32(0)
	for {
		path := append(append(cip.Path{}, prefix...), cip.ClassSegment(cip.ClassSymbol), cip.InstanceSegment(next))
		data := []byte{3, 0, 1, 0, 2, 0, 8, 0} // name, type, dimensions
		resp, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceGetInstanceAttributeList, Path: path, Data: data})
		partial := err != nil && resp.Status == cip.StatusPartialTransfer
		if err != nil && !partial {
			return out, err
		}
		r := cip.NewReader(resp.Data)
		n := 0
		for r.Len() > 0 && r.Err() == nil {
			t := Tag{Instance: r.Uint32()}
			t.Name = r.String()
			t.Type = SymbolType(r.Uint16())
			for i := range t.Dims {
				t.Dims[i] = r.Uint32()
			}
			if r.Err() != nil {
				break
			}
			if program != "" {
				t.Name = program + "." + t.Name
			}
			out = append(out, t)
			next = t.Instance + 1
			n++
		}
		if err := r.Err(); err != nil {
			return out, fmt.Errorf("%w: tag list: %w", ethernetip.ErrProtocol, err)
		}
		if !partial {
			return out, nil
		}
		if n == 0 {
			return out, fmt.Errorf("%w: empty partial tag list", ethernetip.ErrProtocol)
		}
	}
}

// Template reads a structure template (Template object instance id): its
// attributes, then its definition with Read_Template. Templates are cached.
func (c *Client) Template(ctx context.Context, id uint16) (*Template, error) {
	if id == StringTemplate.ID {
		t := StringTemplate
		return &t, nil
	}
	c.mu.Lock()
	t := c.templates[id]
	c.mu.Unlock()
	if t != nil {
		return t, nil
	}
	path := cip.ObjectPath(cip.ClassTemplate, uint32(id))
	resp, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceGetAttributeList, Path: path, Data: []byte{4, 0, 4, 0, 5, 0, 2, 0, 1, 0}})
	if err != nil {
		return nil, err
	}
	r := cip.NewReader(resp.Data)
	if n := r.Uint16(); n != 4 && r.Err() == nil {
		return nil, fmt.Errorf("%w: template attributes: %d of 4", ethernetip.ErrProtocol, n)
	}
	attrs := map[uint16]uint32{}
	for i := 0; i < 4 && r.Err() == nil; i++ {
		id, st := r.Uint16(), r.Uint16()
		if st != 0 {
			return nil, fmt.Errorf("%w: template attribute %d: status 0x%02X", ethernetip.ErrProtocol, id, st)
		}
		if id == 4 || id == 5 {
			attrs[id] = r.Uint32()
		} else {
			attrs[id] = uint32(r.Uint16())
		}
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("%w: template attributes: %w", ethernetip.ErrProtocol, err)
	}
	total := int(attrs[4])*4 - 21
	if total <= 0 || total > 1<<20 {
		return nil, fmt.Errorf("%w: template definition of %d words", ethernetip.ErrProtocol, attrs[4])
	}
	var def []byte
	for len(def) < total {
		req := cip.AppendUint32(nil, uint32(len(def)))
		req = cip.AppendUint16(req, uint16(min(total-len(def), 0xFFFF)))
		resp, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceReadTemplate, Path: path, Data: req})
		partial := err != nil && resp.Status == cip.StatusPartialTransfer
		if err != nil && !partial {
			return nil, err
		}
		if len(resp.Data) == 0 {
			break
		}
		def = append(def, resp.Data...)
		if !partial {
			break
		}
	}
	name, members, err := parseDefinition(def, int(attrs[2]))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrProtocol, err)
	}
	t = &Template{ID: id, Name: name, Handle: uint16(attrs[1]), Size: attrs[5], Members: members}
	c.mu.Lock()
	c.templates[id] = t
	c.mu.Unlock()
	return t, nil
}

// DecodeStruct decodes the first element of a structure value, reading
// the templates of id and of its nested structures from the controller.
func (c *Client) DecodeStruct(ctx context.Context, id uint16, v Value) ([]Field, error) {
	t, err := c.Template(ctx, id)
	if err != nil {
		return nil, err
	}
	if !v.IsStruct() || v.Handle != t.Handle {
		return nil, fmt.Errorf("%w: value %s is not of template %s", ErrType, v, t.Name)
	}
	var lookupErr error
	lookup := func(sub uint16) *Template {
		st, err := c.Template(ctx, sub)
		if err != nil {
			lookupErr = errors.Join(lookupErr, err)
			return nil
		}
		return st
	}
	f, err := t.Decode(v.Data, lookup)
	if err == nil {
		err = lookupErr
	}
	return f, err
}

// ProgramName reads the controller's program (project) name from the
// Program Name object (0x64), as Logix programming tools show it.
func (c *Client) ProgramName(ctx context.Context) (string, error) {
	resp, err := c.d.Do(ctx, cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.ClassProgramName, 1)})
	if err != nil {
		return "", err
	}
	r := cip.NewReader(resp.Data)
	s := r.String()
	if err := r.Err(); err != nil {
		return "", fmt.Errorf("%w: program name: %w", ethernetip.ErrProtocol, err)
	}
	return s, nil
}
