// SPDX-License-Identifier: MIT

package eds

import (
	"fmt"
	"strconv"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
)

// Spec describes a device for [Build].
type Spec struct {
	Identity   cip.Identity
	VendorName string
	// Description is the [File] DescText.
	Description string
	// Date is the creation date and time; zero means now.
	Date        time.Time
	Assemblies  []SpecAssembly
	Connections []SpecConnection
}

// SpecAssembly is an assembly of a [Spec].
type SpecAssembly struct {
	Instance uint32
	Name     string
	Size     int
}

// SpecConnection is an I/O connection of a [Spec]: assembly instances and
// the application data sizes.
type SpecConnection struct {
	Name                  string
	Config, Output, Input uint32
	OutputSize            int
	InputSize             int
	// RPI is the default RPI; zero means 10 ms.
	RPI time.Duration
}

// Build returns an EDS file for a device: [File], [Device], [Device
// Classification], [Params] (the RPI parameter), [Assembly] and
// [Connection Manager]. The trigger and parameter masks of the connections
// are those of a Class 1 cyclic point-to-point connection with a fixed
// size, as common EDS files have them; review them against your device.
func Build(s Spec) (*File, error) {
	if s.Date.IsZero() {
		s.Date = time.Now()
	}
	str := func(v string) Field { return Field{Kind: FieldString, Value: v} }
	tok := func(v string) Field { return Field{Kind: FieldToken, Value: v} }
	num := func(v int64) Field { return tok(strconv.FormatInt(v, 10)) }
	empty := Field{}
	date, clock := s.Date.Format("01-02-2006"), s.Date.Format("15:04:05")
	desc := s.Description
	if desc == "" {
		desc = s.Identity.ProductName
	}
	f := &File{}
	f.Sections = append(f.Sections, Section{Name: "File", Entries: []Entry{
		{Keyword: "DescText", Fields: []Field{str(desc)}},
		{Keyword: "CreateDate", Fields: []Field{tok(date)}},
		{Keyword: "CreateTime", Fields: []Field{tok(clock)}},
		{Keyword: "ModDate", Fields: []Field{tok(date)}},
		{Keyword: "ModTime", Fields: []Field{tok(clock)}},
		{Keyword: "Revision", Fields: []Field{tok("1.0")}},
	}})
	id := s.Identity
	vendor := s.VendorName
	if vendor == "" {
		vendor = cip.VendorName(id.VendorID)
	}
	f.Sections = append(f.Sections, Section{Name: "Device", Entries: []Entry{
		{Keyword: "VendCode", Fields: []Field{num(int64(id.VendorID))}},
		{Keyword: "VendName", Fields: []Field{str(vendor)}},
		{Keyword: "ProdType", Fields: []Field{num(int64(id.DeviceType))}},
		{Keyword: "ProdTypeStr", Fields: []Field{str(id.DeviceType.String())}},
		{Keyword: "ProdCode", Fields: []Field{num(int64(id.ProductCode))}},
		{Keyword: "MajRev", Fields: []Field{num(int64(id.Revision.Major))}},
		{Keyword: "MinRev", Fields: []Field{num(int64(id.Revision.Minor))}},
		{Keyword: "ProdName", Fields: []Field{str(id.ProductName)}},
	}})
	f.Sections = append(f.Sections, Section{Name: "Device Classification", Entries: []Entry{
		{Keyword: "Class1", Fields: []Field{tok("EtherNetIP")}},
	}})
	f.Sections = append(f.Sections, Section{Name: "Params", Entries: []Entry{{Keyword: "Param1", Fields: []Field{
		num(0), empty, empty, tok("0x0000"), tok("0xC8"), num(4), str("RPI"), str("us"), str("Requested packet interval"),
		num(1000), num(3600000000), num(10000), empty, empty, empty, empty, empty, empty, empty, empty, empty,
	}}}})
	asm := Section{Name: "Assembly"}
	byInst := map[uint32]int{}
	for _, a := range s.Assemblies {
		if a.Instance == 0 || a.Size < 0 {
			return nil, fmt.Errorf("eds: assembly %d of %d octets", a.Instance, a.Size)
		}
		path, err := FormatEPATH(cip.ObjectPath(cip.ClassAssembly, a.Instance))
		if err != nil {
			return nil, err
		}
		fields := []Field{str(a.Name), str(path), num(int64(a.Size)), tok("0x0000"), empty, empty}
		if a.Size > 0 {
			fields = append(fields, num(int64(8*a.Size)), empty)
		}
		asm.Entries = append(asm.Entries, Entry{Keyword: "Assem" + strconv.FormatUint(uint64(a.Instance), 10), Fields: fields})
		byInst[a.Instance] = a.Size
	}
	f.Sections = append(f.Sections, asm)
	cm := Section{Name: "Connection Manager"}
	for i, c := range s.Connections {
		if _, ok := byInst[c.Output]; !ok {
			return nil, fmt.Errorf("eds: connection %q: no assembly %d", c.Name, c.Output)
		}
		if _, ok := byInst[c.Input]; !ok {
			return nil, fmt.Errorf("eds: connection %q: no assembly %d", c.Name, c.Input)
		}
		p := cip.Path{cip.ClassSegment(cip.ClassAssembly)}
		if c.Config != 0 {
			p = append(p, cip.InstanceSegment(c.Config))
		}
		p = append(p, cip.ConnectionPointSegment(c.Output), cip.ConnectionPointSegment(c.Input))
		path, err := FormatEPATH(p)
		if err != nil {
			return nil, err
		}
		rpi := tok("Param1")
		ref := func(inst uint32) Field { return tok("Assem" + strconv.FormatUint(uint64(inst), 10)) }
		cfgSize, cfgFmt := empty, empty
		if sz, ok := byInst[c.Config]; ok && c.Config != 0 {
			cfgSize, cfgFmt = num(int64(sz)), ref(c.Config)
		}
		cm.Entries = append(cm.Entries, Entry{Keyword: "Connection" + strconv.Itoa(i+1), Fields: []Field{
			tok("0x04010002"), tok("0x44640405"),
			rpi, num(int64(c.OutputSize)), ref(c.Output),
			rpi, num(int64(c.InputSize)), ref(c.Input),
			empty, empty, cfgSize, cfgFmt,
			str(c.Name), str(""), str(path),
		}})
	}
	f.Sections = append(f.Sections, cm)
	return f, nil
}
