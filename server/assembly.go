// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"fmt"
	"sync"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/implicit"
)

// AssemblyKind is the role of an assembly instance in I/O connections.
type AssemblyKind uint8

// Assembly kinds.
const (
	// AssemblyInput is produced by the server (T->O): the application
	// sets its data, originators read it.
	AssemblyInput AssemblyKind = iota + 1
	// AssemblyOutput is consumed by the server (O->T): originators write
	// it, the application reads it. One connection owns it at a time
	// (exclusive owner).
	AssemblyOutput
	// AssemblyConfig receives the configuration data of Forward_Open.
	AssemblyConfig
	// AssemblyInputOnly is the heartbeat connection point of input-only
	// connections: an O->T point without data.
	AssemblyInputOnly
	// AssemblyListenOnly is the heartbeat connection point of listen-only
	// connections, which only join an existing multicast T->O production.
	AssemblyListenOnly
)

// String returns "input", "output", "config", "input-only" or
// "listen-only".
func (k AssemblyKind) String() string {
	switch k {
	case AssemblyInput:
		return "input"
	case AssemblyOutput:
		return "output"
	case AssemblyConfig:
		return "config"
	case AssemblyInputOnly:
		return "input-only"
	case AssemblyListenOnly:
		return "listen-only"
	default:
		return fmt.Sprintf("kind-%d", uint8(k))
	}
}

// Assembly is an instance of the Assembly object: a block of data that I/O
// connections produce or consume and explicit messages read (attribute 3)
// and, for output and configuration assemblies, write. An Assembly is safe
// for concurrent use.
type Assembly struct {
	instance uint32
	kind     AssemblyKind
	size     int

	mu      sync.Mutex
	data    []byte
	run     bool
	owner   *ioConn // exclusive owner of an output assembly
	onWrite func(data []byte, run bool)
	// producers are the change-of-state productions of an input assembly.
	producers map[*implicit.Connection]bool
}

// Instance returns the instance number.
func (a *Assembly) Instance() uint32 { return a.instance }

// Kind returns the kind.
func (a *Assembly) Kind() AssemblyKind { return a.kind }

// Size returns the size of the data in octets.
func (a *Assembly) Size() int { return a.size }

// Data returns a copy of the data.
func (a *Assembly) Data() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.data...)
}

// Run reports whether the last data consumed from a connection said run
// (output assemblies; false before the first datagram and after the
// connection closed).
func (a *Assembly) Run() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.run
}

// SetData replaces the data; it must be exactly Size octets. Connections
// producing the assembly send it from their next interval on.
func (a *Assembly) SetData(data []byte) error {
	if len(data) != a.size {
		return fmt.Errorf("%w: %d octets for assembly %d of %d", ethernetip.ErrInvalidOption, len(data), a.instance, a.size)
	}
	a.mu.Lock()
	changed := !bytes.Equal(a.data, data)
	copy(a.data, data)
	var trig []*implicit.Connection
	if changed {
		for c := range a.producers {
			trig = append(trig, c)
		}
	}
	a.mu.Unlock()
	for _, c := range trig {
		c.Trigger()
	}
	return nil
}

// OnWrite sets a function called with the new data whenever an originator
// writes the assembly, by an I/O connection (with its run/idle state) or by
// Set_Attribute_Single (run true). It is called on a server goroutine and
// must not block; data is only valid during the call.
func (a *Assembly) OnWrite(f func(data []byte, run bool)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onWrite = f
}

// write stores data written by an originator.
func (a *Assembly) write(data []byte, run bool) {
	a.mu.Lock()
	copy(a.data, data)
	a.run = run
	f := a.onWrite
	a.mu.Unlock()
	if f != nil {
		f(data, run)
	}
}

// assemblyObject is the Assembly object (class 0x04).
type assemblyObject struct {
	*StandardObject

	mu    sync.Mutex
	insts map[uint32]*Assembly
}

func newAssemblyObject(*Server) *assemblyObject {
	return &assemblyObject{StandardObject: NewObject(cip.ClassAssembly, 2), insts: map[uint32]*Assembly{}}
}

func (o *assemblyObject) get(inst uint32) *Assembly {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.insts[inst]
}

// AddAssembly adds an assembly instance of size octets. Heartbeat kinds
// have size 0.
func (s *Server) AddAssembly(instance uint32, kind AssemblyKind, size int) (*Assembly, error) {
	if instance == 0 || size < 0 || size > 65000 {
		return nil, invalidOption("assembly instance %d of %d octets", instance, size)
	}
	if (kind == AssemblyInputOnly || kind == AssemblyListenOnly) && size != 0 {
		return nil, invalidOption("heartbeat assembly %d with data", instance)
	}
	if kind < AssemblyInput || kind > AssemblyListenOnly {
		return nil, invalidOption("assembly kind %d", kind)
	}
	o := s.assemblies
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.insts[instance] != nil {
		return nil, invalidOption("assembly instance %d exists", instance)
	}
	a := &Assembly{instance: instance, kind: kind, size: size, data: make([]byte, size)}
	o.insts[instance] = a
	in := o.AddInstance(instance)
	settable := kind == AssemblyOutput || kind == AssemblyConfig
	attr := Attribute{Get: a.Data, InGetAll: true}
	if settable {
		attr.Set = func(d []byte) cip.GeneralStatus {
			if st := fixedSize(d, size); st != cip.StatusSuccess {
				return st
			}
			a.mu.Lock()
			owned := a.owner != nil
			a.mu.Unlock()
			if owned {
				// An I/O connection owns the data.
				return cip.StatusObjectStateConflict
			}
			a.write(d, true)
			return cip.StatusSuccess
		}
	}
	in.SetAttribute(3, attr)
	in.SetAttribute(4, Attribute{Get: func() []byte { return cip.AppendUint16(nil, uint16(size)) }})
	return a, nil
}

// Assembly returns assembly instance, or nil.
func (s *Server) Assembly(instance uint32) *Assembly { return s.assemblies.get(instance) }
