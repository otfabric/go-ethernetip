// SPDX-License-Identifier: MIT

package logix

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/server"
)

// Logix extended status codes (general status 0xFF).
const (
	ExtAccessBeyondEnd uint16 = 0x2105
	ExtTypeMismatch    uint16 = 0x2107
)

// TagServer emulates the tag database of a Logix controller on a
// server.Server: symbolic and instance addressing of tags, Read Tag, Write
// Tag and their fragmented forms, Read-Modify-Write, the Symbol object's
// tag list, the Template object and the Program Name object. It is meant
// for tests and simulators, not as a controller.
//
// A TagServer is safe for concurrent use.
type TagServer struct {
	maxReply    int
	maxUnconn   int
	programName string

	mu        sync.RWMutex
	tags      map[string]*tagEntry // by lower-case full name
	byInst    map[uint32]*tagEntry
	programs  map[string]uint32 // lower-case "program:x" -> instance
	progNames map[uint32]string
	templates map[uint16]*Template
	nextInst  uint32
	onWrite   func(name string)
}

type tagEntry struct {
	name    string // as declared, without the program
	program string // "Program:Main" or ""
	inst    uint32
	typ     SymbolType
	tmpl    *Template
	dims    [3]uint32
	data    []byte
}

func (t *tagEntry) elemSize() int {
	if t.tmpl != nil {
		return int(t.tmpl.Size)
	}
	if t.typ.Atomic() == cip.TypeBOOL && t.typ.Dims() > 0 {
		return 4
	}
	return t.typ.Atomic().Size()
}

func (t *tagEntry) elements() int {
	n := 1
	for i := 0; i < t.typ.Dims(); i++ {
		n *= int(t.dims[i])
	}
	if t.typ.Atomic() == cip.TypeBOOL && t.typ.Dims() > 0 && t.tmpl == nil {
		n = (n + 31) / 32
	}
	return n
}

// TagServerOption configures a [TagServer].
type TagServerOption func(*TagServer)

// WithProgramName sets the name the Program Name object returns; default
// "OTFabric".
func WithProgramName(name string) TagServerOption {
	return func(ts *TagServer) { ts.programName = name }
}

// WithMaxReply sets the largest reply data of connected requests; larger
// reads become partial transfers. Default 3990, which suits a 4000 octet
// Large_Forward_Open connection. Unconnected replies are at most 480.
func WithMaxReply(n int) TagServerOption {
	return func(ts *TagServer) {
		if n >= 64 {
			ts.maxReply = n
		}
	}
}

// NewTagServer returns an empty tag database.
func NewTagServer(opts ...TagServerOption) *TagServer {
	ts := &TagServer{
		maxReply:    3990,
		maxUnconn:   480,
		programName: "OTFabric",
		tags:        map[string]*tagEntry{},
		byInst:      map[uint32]*tagEntry{},
		programs:    map[string]uint32{},
		progNames:   map[uint32]string{},
		templates:   map[uint16]*Template{StringTemplate.ID: ptr(StringTemplate)},
		nextInst:    1,
	}
	for _, o := range opts {
		o(ts)
	}
	return ts
}

func ptr[T any](v T) *T { return &v }

// OnWrite sets a function called with the full name of a tag after an
// originator wrote it.
func (ts *TagServer) OnWrite(f func(name string)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onWrite = f
}

// AddTemplate adds a structure template. Its ID (1 to 0x0FFF) and handle
// must be unique and its members must fit its size.
func (ts *TagServer) AddTemplate(t Template) error {
	if t.ID == 0 || t.ID > 0x0FFF || t.Size == 0 || t.Name == "" {
		return fmt.Errorf("%w: template %q id %d size %d", ethernetip.ErrInvalidOption, t.Name, t.ID, t.Size)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.templates[t.ID] != nil {
		return fmt.Errorf("%w: template %d exists", ethernetip.ErrInvalidOption, t.ID)
	}
	for _, o := range ts.templates {
		if o.Handle == t.Handle {
			return fmt.Errorf("%w: template handle 0x%04X in use", ethernetip.ErrInvalidOption, t.Handle)
		}
	}
	t.Members = append([]Member(nil), t.Members...)
	ts.templates[t.ID] = &t
	return nil
}

func splitProgram(name string) (program, tag string, err error) {
	if strings.HasPrefix(strings.ToLower(name), "program:") {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", "", fmt.Errorf("%w: %q", ErrTagName, name)
		}
		return name[:i], name[i+1:], nil
	}
	return "", name, nil
}

// AddTag adds an atomic tag (dims empty) or array (up to three
// dimensions). name may be program-scoped ("Program:Main.Speed"). Arrays of
// BOOL are stored as DWORDs, as in Logix.
func (ts *TagServer) AddTag(name string, t cip.DataType, dims ...int) error {
	if !t.Known() || t.Size() == 0 {
		return fmt.Errorf("%w: tag type %s", ethernetip.ErrInvalidOption, t)
	}
	return ts.add(name, NewAtomicType(t, len(dims), 0), nil, dims)
}

// AddStructTag adds a structure tag or array of template id; the STRING
// template (StringTemplate.ID) is predefined.
func (ts *TagServer) AddStructTag(name string, id uint16, dims ...int) error {
	ts.mu.RLock()
	tmpl := ts.templates[id]
	ts.mu.RUnlock()
	if tmpl == nil {
		return fmt.Errorf("%w: no template %d", ethernetip.ErrInvalidOption, id)
	}
	return ts.add(name, NewStructType(id, len(dims)), tmpl, dims)
}

func (ts *TagServer) add(name string, typ SymbolType, tmpl *Template, dims []int) error {
	if len(dims) > 3 {
		return fmt.Errorf("%w: %d dimensions", ethernetip.ErrInvalidOption, len(dims))
	}
	program, tag, err := splitProgram(name)
	if err != nil || !validSymbol(tag) {
		return fmt.Errorf("%w: tag name %q", ethernetip.ErrInvalidOption, name)
	}
	e := &tagEntry{name: tag, program: program, typ: typ, tmpl: tmpl}
	for i, d := range dims {
		if d < 1 || d > 1<<20 {
			return fmt.Errorf("%w: dimension %d", ethernetip.ErrInvalidOption, d)
		}
		e.dims[i] = uint32(d)
	}
	if e.elements()*e.elemSize() > 1<<24 {
		return fmt.Errorf("%w: tag %q larger than 16 MiB", ethernetip.ErrInvalidOption, name)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	key := strings.ToLower(name)
	if ts.tags[key] != nil {
		return fmt.Errorf("%w: tag %q exists", ethernetip.ErrInvalidOption, name)
	}
	if program != "" {
		pk := strings.ToLower(program)
		if _, ok := ts.programs[pk]; !ok {
			ts.programs[pk] = ts.nextInst
			ts.progNames[ts.nextInst] = program
			ts.nextInst++
		}
	}
	e.inst = ts.nextInst
	ts.nextInst++
	e.data = make([]byte, e.elements()*e.elemSize())
	if tmpl == &StringTemplate || (tmpl != nil && tmpl.ID == StringTemplate.ID) {
		e.tmpl = ts.templates[StringTemplate.ID]
	}
	ts.tags[key] = e
	ts.byInst[e.inst] = e
	return nil
}

// Get returns the whole value of a tag.
func (ts *TagServer) Get(name string) (Value, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	e := ts.tags[strings.ToLower(name)]
	if e == nil {
		return Value{}, fmt.Errorf("%w: no tag %q", ethernetip.ErrInvalidOption, name)
	}
	return e.value(0, e.elements(), append([]byte(nil), e.data...)), nil
}

func (e *tagEntry) value(_, count int, data []byte) Value {
	if e.tmpl != nil {
		return Value{Handle: e.tmpl.Handle, Count: count, Data: data}
	}
	t := e.typ.Atomic()
	if t == cip.TypeBOOL && e.typ.Dims() > 0 {
		t = cip.TypeDWORD
	}
	return Value{Type: t, Count: count, Data: data}
}

// Set replaces the whole value of a tag; the value's type and size must
// be the tag's.
func (ts *TagServer) Set(name string, v Value) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	e := ts.tags[strings.ToLower(name)]
	if e == nil {
		return fmt.Errorf("%w: no tag %q", ethernetip.ErrInvalidOption, name)
	}
	want := e.value(0, e.elements(), nil)
	if v.Type != want.Type || v.Handle != want.Handle || len(v.Data) != len(e.data) {
		return fmt.Errorf("%w: %s for tag %q of %s[%d]", ErrType, v, name, want.Type, e.elements())
	}
	copy(e.data, v.Data)
	return nil
}

// Attach registers the emulation on a server: the symbol handler, the
// Symbol (0x6B), Template (0x6C) and Program Name (0x64) objects.
func (ts *TagServer) Attach(s *server.Server) {
	s.HandleSymbols(ts)
	s.RegisterObject(&symbolObject{ts})
	s.RegisterObject(&templateObject{ts})
	s.RegisterObject(&programNameObject{ts})
}

// target is the part of a tag a path addresses.
type target struct {
	e        *tagEntry
	off      int // octet offset in e.data
	elemSize int
	avail    int // elements from off to the end of the addressed array
	typ      cip.DataType
	handle   uint16
	bit      int // a BOOL member: its bit in the octet at off; -1 otherwise
	full     string
}

var (
	errNoTag   = cip.Response{Status: cip.StatusPathDestinationUnknown}
	errBadPath = cip.Response{Status: cip.StatusPathSegmentError}
	errBeyond  = cip.Response{Status: cip.StatusGeneralError, Extended: []uint16{ExtAccessBeyondEnd}}
	errType    = cip.Response{Status: cip.StatusGeneralError, Extended: []uint16{ExtTypeMismatch}}
)

// resolve finds what path addresses, starting at entry e (instance
// addressing) or at the symbol segments of path. ts.mu is held.
func (ts *TagServer) resolve(e *tagEntry, path cip.Path) (target, *cip.Response) {
	i := 0
	if e == nil {
		program := ""
		sym, ok := path[0].(cip.SymbolSegment)
		if !ok {
			return target{}, &errBadPath
		}
		i = 1
		if strings.HasPrefix(strings.ToLower(sym.Name), "program:") {
			program = sym.Name
			if len(path) < 2 {
				return target{}, &errBadPath
			}
			if sym, ok = path[1].(cip.SymbolSegment); !ok {
				return target{}, &errBadPath
			}
			i = 2
		}
		name := sym.Name
		if program != "" {
			name = program + "." + name
		}
		if e = ts.tags[strings.ToLower(name)]; e == nil {
			return target{}, &errNoTag
		}
	}
	t := target{e: e, elemSize: e.elemSize(), avail: e.elements(), bit: -1, full: e.name}
	if e.program != "" {
		t.full = e.program + "." + e.name
	}
	if e.tmpl != nil {
		t.handle = e.tmpl.Handle
	} else {
		t.typ = e.value(0, 0, nil).Type
	}
	dims, dimLen := e.typ.Dims(), e.dims
	tmpl := e.tmpl
	bool32 := e.tmpl == nil && e.typ.Atomic() == cip.TypeBOOL && dims > 0
	for i < len(path) {
		// Indices of the current array.
		var idx []uint32
		for i < len(path) {
			l, ok := path[i].(cip.LogicalSegment)
			if !ok || l.Type != cip.LogicalMember {
				break
			}
			idx = append(idx, l.Value)
			i++
		}
		if len(idx) > 0 {
			if len(idx) != dims {
				return t, &errBadPath
			}
			flat := uint32(0)
			for d := 0; d < dims; d++ {
				if idx[d] >= dimLen[d] {
					return t, &errBeyond
				}
				flat = flat*dimLen[d] + idx[d]
			}
			total := 1
			for d := 0; d < dims; d++ {
				total *= int(dimLen[d])
			}
			if bool32 {
				// A BOOL array element is read as its DWORD.
				t.off += int(flat/32) * 4
				t.avail = (total+31)/32 - int(flat/32)
			} else {
				t.off += int(flat) * t.elemSize
				t.avail = total - int(flat)
			}
			dims = 0
			continue
		}
		sym, ok := path[i].(cip.SymbolSegment)
		if !ok || tmpl == nil || dims != 0 {
			return t, &errBadPath
		}
		i++
		var m *Member
		for k := range tmpl.Members {
			if strings.EqualFold(tmpl.Members[k].Name, sym.Name) && !tmpl.Members[k].Hidden() {
				m = &tmpl.Members[k]
			}
		}
		if m == nil {
			return t, &errNoTag
		}
		t.off += int(m.Offset)
		t.avail, t.handle, tmpl, bool32 = 1, 0, nil, false
		dims, dimLen = 0, [3]uint32{}
		switch {
		case m.Type.IsStruct():
			tmpl = ts.templates[m.Type.Template()]
			if tmpl == nil {
				return t, &errNoTag
			}
			t.typ, t.handle, t.elemSize = 0, tmpl.Handle, int(tmpl.Size)
		case m.Type.Atomic() == cip.TypeBOOL && m.Type.Dims() == 0 && m.Info < 8:
			t.typ, t.elemSize, t.bit = cip.TypeBOOL, 1, int(m.Info)
		default:
			t.typ, t.elemSize = m.Type.Atomic(), m.Type.Atomic().Size()
		}
		if m.Type.Dims() > 0 || (m.Info > 0 && t.bit < 0) {
			dims, dimLen[0], t.avail = 1, uint32(m.Info), int(m.Info)
			if t.typ == cip.TypeBOOL {
				t.typ, t.elemSize, bool32 = cip.TypeDWORD, 4, true
				t.avail = (int(m.Info) + 31) / 32
			}
		}
	}
	return t, nil
}

// limit returns the largest reply data of a request.
func (ts *TagServer) limit(r *server.Request) int {
	if r.Connected {
		return ts.maxReply
	}
	return ts.maxUnconn
}

// ServeSymbol implements server.SymbolHandler.
func (ts *TagServer) ServeSymbol(ctx context.Context, r *server.Request) cip.Response {
	if r.Service == cip.ServiceGetInstanceAttributeList {
		// A program-scoped tag list: Program:X, then the Symbol object.
		return ts.listTags(r)
	}
	return ts.serveTag(nil, r, r.Path)
}

func (ts *TagServer) serveTag(e *tagEntry, r *server.Request, path cip.Path) cip.Response {
	switch r.Service {
	case cip.ServiceReadTag, cip.ServiceReadTagFragmented:
		ts.mu.RLock()
		defer ts.mu.RUnlock()
		t, fail := ts.resolve(e, path)
		if fail != nil {
			return *fail
		}
		return ts.read(t, r)
	case cip.ServiceWriteTag, cip.ServiceWriteTagFragmented, cip.ServiceReadModifyWriteTag:
		ts.mu.Lock()
		t, fail := ts.resolve(e, path)
		var resp cip.Response
		if fail != nil {
			resp = *fail
		} else if r.Service == cip.ServiceReadModifyWriteTag {
			resp = ts.readModifyWrite(t, r.Data)
		} else {
			resp = ts.write(t, r)
		}
		f := ts.onWrite
		ts.mu.Unlock()
		if resp.OK() && f != nil {
			f(t.full)
		}
		return resp
	default:
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
}

func appendTypeCode(b []byte, t target) []byte {
	if t.typ == 0 {
		b = binary.LittleEndian.AppendUint16(b, StructTypeCode)
		return binary.LittleEndian.AppendUint16(b, t.handle)
	}
	return binary.LittleEndian.AppendUint16(b, uint16(t.typ))
}

func (ts *TagServer) read(t target, r *server.Request) cip.Response {
	rd := cip.NewReader(r.Data)
	count := int(rd.Uint16())
	var offset int
	if r.Service == cip.ServiceReadTagFragmented {
		offset = int(rd.Uint32())
	}
	if rd.Err() != nil {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	if count < 1 || count > t.avail {
		return errBeyond
	}
	var data []byte
	if t.bit >= 0 {
		if count != 1 {
			return errBeyond
		}
		data = []byte{(t.e.data[t.off] >> t.bit) & 1}
	} else {
		data = t.e.data[t.off : t.off+count*t.elemSize]
	}
	if offset > len(data) {
		return cip.Response{Status: cip.StatusInvalidParameter}
	}
	data = data[offset:]
	head := appendTypeCode(nil, t)
	room := ts.limit(r) - len(head)
	st := cip.StatusSuccess
	if len(data) > room {
		data, st = data[:room], cip.StatusPartialTransfer
	}
	return cip.Response{Status: st, Data: append(head, data...)}
}

func (ts *TagServer) write(t target, r *server.Request) cip.Response {
	rd := cip.NewReader(r.Data)
	typ, handle := decodeType(rd)
	count := int(rd.Uint16())
	var offset int
	if r.Service == cip.ServiceWriteTagFragmented {
		offset = int(rd.Uint32())
	}
	if rd.Err() != nil {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	data := rd.Rest()
	if typ != t.typ || (typ == 0 && handle != t.handle) {
		return errType
	}
	if count < 1 || count > t.avail {
		return errBeyond
	}
	if t.bit >= 0 {
		if count != 1 || offset != 0 || len(data) != 1 {
			return errBeyond
		}
		if data[0] != 0 {
			t.e.data[t.off] |= 1 << t.bit
		} else {
			t.e.data[t.off] &^= 1 << t.bit
		}
		return cip.Response{}
	}
	total := count * t.elemSize
	if offset < 0 || offset+len(data) > total {
		return cip.Response{Status: cip.StatusTooMuchData}
	}
	if r.Service == cip.ServiceWriteTag && len(data) < total {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	copy(t.e.data[t.off+offset:], data)
	return cip.Response{}
}

func (ts *TagServer) readModifyWrite(t target, data []byte) cip.Response {
	rd := cip.NewReader(data)
	n := int(rd.Uint16())
	or := rd.Bytes(n)
	and := rd.Bytes(n)
	if rd.Err() != nil || n == 0 {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	// pycomm3 sends 8 octets of AND mask for every size: the rest is
	// ignored.
	if t.bit >= 0 || t.typ == 0 || t.elemSize < n || !t.typ.IsInteger() {
		return errType
	}
	b := t.e.data[t.off : t.off+n]
	for i := range b {
		b[i] = (b[i] | or[i]) & and[i]
	}
	return cip.Response{}
}

// symbol attributes of the tag list.
func (ts *TagServer) appendSymbol(b []byte, inst uint32, name string, typ SymbolType, dims [3]uint32, attrs []uint16) []byte {
	b = cip.AppendUint32(b, inst)
	for _, a := range attrs {
		switch a {
		case 1:
			b, _ = cip.AppendString(b, name)
		case 2:
			b = cip.AppendUint16(b, uint16(typ))
		case 3, 5, 6:
			b = cip.AppendUint32(b, 0)
		case 7:
			b = cip.AppendUint16(b, 0)
		case 8:
			for _, d := range dims {
				b = cip.AppendUint32(b, d)
			}
		case 10:
			b = append(b, 0)
		}
	}
	return b
}

// listTags answers Get Instance Attribute List of the Symbol object, in
// controller scope or, with a Program:X prefix, in program scope.
func (ts *TagServer) listTags(r *server.Request) cip.Response {
	program := ""
	path := r.Path
	if len(path) > 0 {
		if s, ok := path[0].(cip.SymbolSegment); ok {
			program = s.Name
			path = path[1:]
		}
	}
	var start uint32
	if len(path) < 1 {
		return errBadPath
	}
	if c, ok := path[0].(cip.LogicalSegment); !ok || c.Type != cip.LogicalClass || cip.Class(c.Value) != cip.ClassSymbol {
		return errBadPath
	}
	if len(path) > 1 {
		if in, ok := path[1].(cip.LogicalSegment); ok && in.Type == cip.LogicalInstance {
			start = in.Value
		}
	}
	rd := cip.NewReader(r.Data)
	n := int(rd.Uint16())
	if rd.Err() != nil || n == 0 || n > 16 || n > rd.Len()/2 {
		return cip.Response{Status: cip.StatusNotEnoughData}
	}
	attrs := make([]uint16, n)
	for i := range attrs {
		attrs[i] = rd.Uint16()
		switch attrs[i] {
		case 1, 2, 3, 5, 6, 7, 8, 10:
		default:
			return cip.Response{Status: cip.StatusAttributeNotSupported}
		}
	}
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	type sym struct {
		inst uint32
		name string
		typ  SymbolType
		dims [3]uint32
	}
	var syms []sym
	if program == "" {
		for inst, p := range ts.progNames {
			syms = append(syms, sym{inst, p, 0x1068, [3]uint32{}})
		}
	} else if _, ok := ts.programs[strings.ToLower(program)]; !ok {
		return errNoTag
	}
	for _, e := range ts.tags {
		if strings.EqualFold(e.program, program) {
			syms = append(syms, sym{e.inst, e.name, e.typ, e.dims})
		}
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].inst < syms[j].inst })
	var out []byte
	limit := ts.limit(r)
	for _, s := range syms {
		if s.inst < start {
			continue
		}
		next := ts.appendSymbol(nil, s.inst, s.name, s.typ, s.dims, attrs)
		if len(out)+len(next) > limit {
			if len(out) == 0 {
				return cip.Response{Status: cip.StatusReplyDataTooLarge}
			}
			return cip.Response{Status: cip.StatusPartialTransfer, Data: out}
		}
		out = append(out, next...)
	}
	return cip.Response{Data: out}
}

// symbolObject is the Symbol object: the tag list, and tag services by
// instance (revision 21 and later of Logix firmware).
type symbolObject struct{ ts *TagServer }

func (o *symbolObject) Class() cip.Class { return cip.ClassSymbol }

func (o *symbolObject) ServeCIP(_ context.Context, r *server.Request) cip.Response {
	if r.Service == cip.ServiceGetInstanceAttributeList {
		return o.ts.listTags(r)
	}
	o.ts.mu.RLock()
	e := o.ts.byInst[r.Instance]
	o.ts.mu.RUnlock()
	if e == nil {
		return errNoTag
	}
	return o.ts.serveTag(e, r, r.Rest)
}

// templateObject is the Template object.
type templateObject struct{ ts *TagServer }

func (o *templateObject) Class() cip.Class { return cip.ClassTemplate }

func (o *templateObject) ServeCIP(_ context.Context, r *server.Request) cip.Response {
	o.ts.mu.RLock()
	t := o.ts.templates[uint16(r.Instance)]
	o.ts.mu.RUnlock()
	if t == nil || r.Instance > 0xFFFF {
		return errNoTag
	}
	def := t.definition()
	words := definitionWords(len(def))
	switch r.Service {
	case cip.ServiceGetAttributeList:
		rd := cip.NewReader(r.Data)
		n := int(rd.Uint16())
		if rd.Err() != nil || n == 0 || n > rd.Len()/2 {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		out := cip.AppendUint16(nil, uint16(n))
		st := cip.StatusSuccess
		for i := 0; i < n; i++ {
			id := rd.Uint16()
			out = cip.AppendUint16(out, id)
			switch id {
			case 1:
				out = cip.AppendUint16(cip.AppendUint16(out, 0), t.Handle)
			case 2:
				out = cip.AppendUint16(cip.AppendUint16(out, 0), uint16(len(t.Members)))
			case 4:
				out = cip.AppendUint32(cip.AppendUint16(out, 0), words)
			case 5:
				out = cip.AppendUint32(cip.AppendUint16(out, 0), t.Size)
			default:
				out = cip.AppendUint16(out, uint16(cip.StatusAttributeNotSupported))
				st = cip.StatusAttributeListError
			}
		}
		return cip.Response{Status: st, Data: out}
	case cip.ServiceReadTemplate:
		rd := cip.NewReader(r.Data)
		off := int(rd.Uint32())
		n := int(rd.Uint16())
		if rd.Err() != nil {
			return cip.Response{Status: cip.StatusNotEnoughData}
		}
		total := int(words)*4 - 21
		if off > total {
			return cip.Response{Status: cip.StatusInvalidParameter}
		}
		full := make([]byte, total)
		copy(full, def)
		data := full[off:min(off+n, total)]
		st := cip.StatusSuccess
		if lim := o.ts.limit(r); len(data) > lim {
			data, st = data[:lim-lim%4], cip.StatusPartialTransfer
		}
		return cip.Response{Status: st, Data: data}
	default:
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
}

// programNameObject is the Program Name object (0x64).
type programNameObject struct{ ts *TagServer }

func (o *programNameObject) Class() cip.Class { return cip.ClassProgramName }

func (o *programNameObject) ServeCIP(_ context.Context, r *server.Request) cip.Response {
	if r.Instance != 1 {
		return errNoTag
	}
	if r.Service != cip.ServiceGetAttributesAll {
		return cip.Response{Status: cip.StatusServiceNotSupported}
	}
	b, _ := cip.AppendString(nil, o.ts.programName)
	return cip.Response{Data: b}
}
