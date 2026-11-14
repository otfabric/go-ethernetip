// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"net"
	"slices"
	"sync"

	"github.com/otfabric/go-ethernetip/cip"
)

// Request is an explicit request as an object sees it.
type Request struct {
	cip.Request
	// Instance is the instance the path addresses; 0 addresses the class.
	Instance uint32
	// Attribute is the attribute the path addresses, when HasAttribute.
	Attribute    uint16
	HasAttribute bool
	// Rest are the segments after the class, instance and attribute
	// (member IDs, for one).
	Rest cip.Path
	// Remote is the address of the originator.
	Remote net.Addr
	// Connected is true for a request received on a Class 3 connection.
	Connected bool
	// MaxReply, for a request received on a Class 3 connection, is the
	// largest reply data the connection carries (its T->O size less the
	// sequence count and the reply header). An object that can split its
	// reply (a partial transfer) keeps within it; a larger reply cannot be
	// delivered to the originator. 0 elsewhere.
	MaxReply int
}

// Object is a CIP object class the Message Router dispatches requests to.
// ServeCIP is called from the goroutine of the session that received the
// request, concurrently for different sessions: an Object must be safe for
// concurrent use.
type Object interface {
	// Class returns the class code.
	Class() cip.Class
	// ServeCIP handles a request addressed to the class or one of its
	// instances and returns the response; its Service is set by the
	// router. r.Data is only valid until ServeCIP returns: it aliases the
	// session's read buffer, which the next packet overwrites. Copy what
	// you keep.
	ServeCIP(ctx context.Context, r *Request) cip.Response
}

// SymbolHandler handles requests whose path starts with a symbol segment
// (Logix tag services). See the logix package for an emulation. As for
// [Object.ServeCIP], r.Data is only valid until ServeSymbol returns; copy
// what you keep.
type SymbolHandler interface {
	ServeSymbol(ctx context.Context, r *Request) cip.Response
}

// Attribute is an attribute of a [StandardObject]'s class or instance.
type Attribute struct {
	// Get returns the encoded value; nil makes the attribute write-only.
	Get func() []byte
	// Set stores an encoded value and returns the status of the reply:
	// cip.StatusSuccess, cip.StatusNotEnoughData, cip.StatusTooMuchData,
	// cip.StatusInvalidAttributeValue, ... nil makes the attribute
	// read-only (attribute not settable). data is only valid until Set
	// returns: it aliases the session's read buffer, which the next
	// packet overwrites. Copy what you keep.
	Set func(data []byte) cip.GeneralStatus
	// InGetAll includes the attribute in Get_Attributes_All replies, in
	// the order of the attribute IDs.
	InGetAll bool
}

// ServiceFunc implements a service of a [StandardObject]. As for
// [Object.ServeCIP], r.Data is only valid until the function returns;
// copy what you keep.
type ServiceFunc func(ctx context.Context, r *Request) cip.Response

// StandardObject is an [Object] made of attributes and services: the class
// attributes 1 (revision), 2 (max instance), 3 (number of instances), 6
// (max class attribute) and 7 (max instance attribute) are maintained,
// Get_Attribute_Single, Get_Attributes_All, Get_Attribute_List and
// Set_Attribute_Single work on the attributes, and further services are
// added with HandleService. It is safe for concurrent use; the attribute
// functions must be too.
type StandardObject struct {
	class    cip.Class
	revision uint16

	mu         sync.RWMutex
	classAttrs map[uint16]Attribute
	instances  map[uint32]*Instance
	services   map[cip.Service]ServiceFunc
	maxInstID  uint32
}

// Instance is an instance of a [StandardObject].
type Instance struct {
	ID uint32

	obj   *StandardObject
	attrs map[uint16]Attribute
}

// NewObject returns an object of class c, revision rev, without instances.
func NewObject(c cip.Class, rev uint16) *StandardObject {
	o := &StandardObject{
		class:      c,
		revision:   rev,
		classAttrs: map[uint16]Attribute{},
		instances:  map[uint32]*Instance{},
		services:   map[cip.Service]ServiceFunc{},
	}
	o.classAttrs[1] = Attribute{Get: func() []byte { return cip.AppendUint16(nil, o.revision) }, InGetAll: true}
	o.classAttrs[2] = Attribute{Get: func() []byte { return cip.AppendUint16(nil, saturate16(o.maxInstance())) }, InGetAll: true}
	o.classAttrs[3] = Attribute{Get: func() []byte { return cip.AppendUint16(nil, saturate16(o.numInstances())) }, InGetAll: true}
	o.classAttrs[6] = Attribute{Get: func() []byte { return cip.AppendUint16(nil, o.maxAttr(0)) }, InGetAll: true}
	o.classAttrs[7] = Attribute{Get: func() []byte { return cip.AppendUint16(nil, o.maxAttr(1)) }, InGetAll: true}
	return o
}

// Class returns the class code.
func (o *StandardObject) Class() cip.Class { return o.class }

// AddInstance adds instance id (not 0) and returns it, or returns the
// existing one.
func (o *StandardObject) AddInstance(id uint32) *Instance {
	o.mu.Lock()
	defer o.mu.Unlock()
	if in := o.instances[id]; in != nil {
		return in
	}
	in := &Instance{ID: id, obj: o, attrs: map[uint16]Attribute{}}
	o.instances[id] = in
	if id > o.maxInstID {
		o.maxInstID = id
	}
	return in
}

// RemoveInstance removes an instance.
func (o *StandardObject) RemoveInstance(id uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.instances, id)
	o.maxInstID = 0
	for k := range o.instances {
		if k > o.maxInstID {
			o.maxInstID = k
		}
	}
}

// Instance returns instance id, or nil.
func (o *StandardObject) Instance(id uint32) *Instance {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.instances[id]
}

// SetClassAttribute sets a class attribute (instance 0).
func (o *StandardObject) SetClassAttribute(id uint16, a Attribute) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.classAttrs[id] = a
}

// SetAttribute sets an attribute of the instance.
func (in *Instance) SetAttribute(id uint16, a Attribute) {
	in.obj.mu.Lock()
	defer in.obj.mu.Unlock()
	in.attrs[id] = a
}

// HandleService adds or replaces a service; it receives requests to the
// class and to every instance (r.Instance tells which). Get_Attribute_Single,
// Get_Attributes_All, Get_Attribute_List and Set_Attribute_Single can be
// replaced too.
func (o *StandardObject) HandleService(s cip.Service, f ServiceFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.services[s] = f
}

// saturate16 returns n as a UINT attribute value: 0 when negative, 0xFFFF
// when larger (instance IDs and counts are 32-bit here, the class
// attributes that report them 16-bit).
func saturate16[T int | uint32](n T) uint16 {
	if n <= 0 {
		return 0
	}
	if n >= math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(n)
}

// saturate8 is saturate16 for a USINT.
func saturate8(n int) uint8 {
	if n <= 0 {
		return 0
	}
	if n >= math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(n)
}

func (o *StandardObject) maxInstance() uint32 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.maxInstID
}

func (o *StandardObject) numInstances() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.instances)
}

// maxAttr returns the highest attribute ID of the class (which 0) or of
// any instance (which 1).
func (o *StandardObject) maxAttr(which int) uint16 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var m uint16
	if which == 0 {
		for id := range o.classAttrs {
			m = max(m, id)
		}
		return m
	}
	for _, in := range o.instances {
		for id := range in.attrs {
			m = max(m, id)
		}
	}
	return m
}

// attrs returns the attributes of the class (0) or of an instance, and
// whether the instance exists.
func (o *StandardObject) attrs(instance uint32) (map[uint16]Attribute, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if instance == 0 {
		return o.classAttrs, true
	}
	in := o.instances[instance]
	if in == nil {
		return nil, false
	}
	return in.attrs, true
}

// ServeCIP dispatches a request to the object's services.
func (o *StandardObject) ServeCIP(ctx context.Context, r *Request) cip.Response {
	attrs, ok := o.attrs(r.Instance)
	if !ok {
		return cip.Response{Status: cip.StatusPathDestinationUnknown}
	}
	o.mu.RLock()
	f := o.services[r.Service]
	o.mu.RUnlock()
	if f != nil {
		return f(ctx, r)
	}
	// The attribute map is read under the lock: a copy of the needed
	// entries is taken first.
	switch r.Service {
	case cip.ServiceGetAttributeSingle:
		if !r.HasAttribute {
			return cip.Response{Status: cip.StatusPathSegmentError}
		}
		a, ok := o.attr(attrs, r.Attribute)
		if !ok || a.Get == nil {
			return cip.Response{Status: cip.StatusAttributeNotSupported}
		}
		return cip.Response{Data: a.Get()}
	case cip.ServiceSetAttributeSingle:
		if !r.HasAttribute {
			return cip.Response{Status: cip.StatusPathSegmentError}
		}
		a, ok := o.attr(attrs, r.Attribute)
		if !ok {
			return cip.Response{Status: cip.StatusAttributeNotSupported}
		}
		if a.Set == nil {
			return cip.Response{Status: cip.StatusAttributeNotSettable}
		}
		return cip.Response{Status: a.Set(r.Data)}
	case cip.ServiceGetAttributesAll:
		return o.getAll(ctx, attrs)
	case cip.ServiceGetAttributeList:
		return o.getList(ctx, attrs, r.Data)
	default:
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
}

func (o *StandardObject) attr(attrs map[uint16]Attribute, id uint16) (Attribute, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	a, ok := attrs[id]
	return a, ok
}

// getAll answers Get_Attributes_All. The reply stops at the request's
// budget (reply data too large) without calling the remaining Get
// functions.
func (o *StandardObject) getAll(ctx context.Context, attrs map[uint16]Attribute) cip.Response {
	budget, bounded := replyBudget(ctx)
	o.mu.RLock()
	ids := make([]uint16, 0, len(attrs))
	sel := make(map[uint16]Attribute, len(attrs))
	for id, a := range attrs {
		if a.InGetAll && a.Get != nil {
			ids = append(ids, id)
			sel[id] = a
		}
	}
	o.mu.RUnlock()
	slices.Sort(ids)
	var b []byte
	for _, id := range ids {
		v := sel[id].Get()
		if bounded && len(b)+len(v) > budget {
			return overBudget(ctx)
		}
		b = append(b, v...)
	}
	return cip.Response{Data: b}
}

// maxListAttributes bounds the attributes of one Get_Attribute_List.
const maxListAttributes = 256

// getList answers Get_Attribute_List. The reply stops at the request's
// budget (reply data too large) without calling the remaining Get
// functions.
func (o *StandardObject) getList(ctx context.Context, attrs map[uint16]Attribute, data []byte) cip.Response {
	budget, bounded := replyBudget(ctx)
	r := cip.NewReader(data)
	n := int(r.Uint16())
	if r.Err() != nil {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	if n == 0 || n > maxListAttributes || n > r.Len()/2 {
		if n > r.Len()/2 {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		return cip.Response{Status: cip.StatusInvalidParameter}
	}
	out := cip.AppendUint16(nil, uint16(n))
	st := cip.StatusSuccess
	for range n {
		id := r.Uint16()
		a, ok := o.attr(attrs, id)
		out = cip.AppendUint16(out, id)
		if !ok || a.Get == nil {
			out = cip.AppendUint16(out, uint16(cip.StatusAttributeNotSupported))
			st = cip.StatusAttributeListError
		} else {
			out = cip.AppendUint16(out, 0)
			v := a.Get()
			if bounded && len(out)+len(v) > budget {
				return overBudget(ctx)
			}
			out = append(out, v...)
		}
		if bounded && len(out) > budget {
			return overBudget(ctx)
		}
	}
	return cip.Response{Status: st, Data: out}
}
