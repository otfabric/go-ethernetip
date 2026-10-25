// SPDX-License-Identifier: MIT

// Command gencatalog generates the code and documentation that follow from
// the CIP catalog, cip/catalog.json, and the vendor list, cip/vendors.json:
//
//   - cip/catalog_gen.go: the class, service, status, data type and device
//     type constants with their names, and the vendor names;
//   - CATALOG.md: the catalog as a document, with the provenance of each
//     table.
//
// Run it from the module root with go generate ./... (doc.go carries the
// directive). With -check it writes nothing and fails when the generated
// files differ from what the catalog generates; CI runs it so.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Entry is one row of a table: a code, its name and its Go identifier.
type Entry struct {
	Class    string `json:"class"`
	Code     string `json:"code"`
	Name     string `json:"name"`
	Ident    string `json:"ident"`
	Source   string `json:"source"`
	Vendor   bool   `json:"vendor"`
	Symbolic bool   `json:"symbolic"`
	Size     int    `json:"size"`
	Kind     string `json:"kind"`
}

// Catalog is cip/catalog.json.
type Catalog struct {
	Sources          map[string]string `json:"sources"`
	Classes          []Entry           `json:"classes"`
	Services         []Entry           `json:"services"`
	ClassServices    []Entry           `json:"classServices"`
	GeneralStatus    []Entry           `json:"generalStatus"`
	ConnectionStatus []Entry           `json:"connectionStatus"`
	DataTypes        []Entry           `json:"dataTypes"`
	DeviceTypes      []Entry           `json:"deviceTypes"`
}

// Vendor is one entry of cip/vendors.json.
type Vendor struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Vendors is cip/vendors.json.
type Vendors struct {
	Comment []string `json:"_comment"`
	Vendors []Vendor `json:"vendors"`
}

func main() {
	check := flag.Bool("check", false, "fail when the generated files are out of date instead of writing them")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, "gencatalog:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	var cat Catalog
	if err := readJSON("cip/catalog.json", &cat); err != nil {
		return err
	}
	var vend Vendors
	if err := readJSON("cip/vendors.json", &vend); err != nil {
		return err
	}
	if err := validate(&cat, &vend); err != nil {
		return err
	}
	code, err := genCode(&cat, &vend)
	if err != nil {
		return err
	}
	doc := genDoc(&cat, &vend)
	files := map[string][]byte{"cip/catalog_gen.go": code, "CATALOG.md": doc}
	var stale []string
	for _, name := range []string{"cip/catalog_gen.go", "CATALOG.md"} {
		if check {
			have, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(have, files[name]) {
				stale = append(stale, name)
			}
			continue
		}
		if err := os.WriteFile(name, files[name], 0o644); err != nil {
			return err
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("out of date, run make generate: %s", strings.Join(stale, ", "))
	}
	return nil
}

func readJSON(name string, v any) error {
	b, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func num(s string) int {
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		panic(fmt.Sprintf("bad number %q", s))
	}
	return int(v)
}

// validate checks the catalog: numbers parse, codes and identifiers are
// unique within a table, every source is declared.
func validate(cat *Catalog, vend *Vendors) error {
	tables := map[string][]Entry{
		"classes": cat.Classes, "services": cat.Services, "classServices": cat.ClassServices,
		"generalStatus": cat.GeneralStatus, "connectionStatus": cat.ConnectionStatus,
		"dataTypes": cat.DataTypes, "deviceTypes": cat.DeviceTypes,
	}
	var errs []error
	for name, t := range tables {
		codes := map[string]bool{}
		idents := map[string]bool{}
		for _, e := range t {
			if _, err := strconv.ParseUint(e.Code, 0, 32); err != nil {
				errs = append(errs, fmt.Errorf("%s: code %q: %w", name, e.Code, err))
				continue
			}
			key := e.Class + "/" + strconv.Itoa(num(e.Code))
			if codes[key] {
				errs = append(errs, fmt.Errorf("%s: duplicate code %s", name, e.Code))
			}
			codes[key] = true
			id := e.Ident
			if name == "dataTypes" {
				id = e.Name
			}
			if id == "" {
				errs = append(errs, fmt.Errorf("%s: %s has no ident", name, e.Code))
			}
			if idents[id] {
				errs = append(errs, fmt.Errorf("%s: duplicate ident %s", name, id))
			}
			idents[id] = true
			if e.Source != "" && cat.Sources[e.Source] == "" {
				errs = append(errs, fmt.Errorf("%s: %s: unknown source %q", name, e.Code, e.Source))
			}
		}
	}
	seen := map[int]bool{}
	for _, v := range vend.Vendors {
		if v.ID < 0 || v.ID > 0xFFFF || seen[v.ID] {
			errs = append(errs, fmt.Errorf("vendors: bad or duplicate id %d", v.ID))
		}
		seen[v.ID] = true
	}
	return errors.Join(errs...)
}

func genCode(cat *Catalog, vend *Vendors) ([]byte, error) {
	var b bytes.Buffer
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("// Code generated by internal/cmd/gencatalog from cip/catalog.json and cip/vendors.json. DO NOT EDIT.\n\n")
	p("// SPDX-License-Identifier: MIT\n\npackage cip\n\n")

	p("// Object class codes.\nconst (\n")
	for _, e := range cat.Classes {
		p("\t// Class%s is the %s object (0x%02X).\n\tClass%s Class = 0x%02X\n", e.Ident, e.Name, num(e.Code), e.Ident, num(e.Code))
	}
	p(")\n\nvar classNames = map[Class]string{\n")
	for _, e := range cat.Classes {
		p("\tClass%s: %q,\n", e.Ident, e.Name)
	}
	p("}\n\n")
	p("// vendorClasses are the classes of vendor-specific (Rockwell) objects.\nvar vendorClasses = map[Class]bool{\n")
	for _, e := range cat.Classes {
		if e.Vendor {
			p("\tClass%s: true,\n", e.Ident)
		}
	}
	p("}\n\n")

	p("// Common services, defined for every object class that supports them.\nconst (\n")
	for _, e := range cat.Services {
		p("\t// Service%s is %s (0x%02X).\n\tService%s Service = 0x%02X\n", e.Ident, e.Name, num(e.Code), e.Ident, num(e.Code))
	}
	p(")\n\n")
	p("// Object-specific services. Their codes are only meaningful for the class\n// named in the comment: 0x4C is Read_Tag to a symbol and Read_Template to\n// the Template object.\nconst (\n")
	for _, e := range cat.ClassServices {
		cls := className(cat, e.Class)
		p("\t// Service%s is %s (0x%02X) of the %s object.\n\tService%s Service = 0x%02X\n", e.Ident, e.Name, num(e.Code), cls, e.Ident, num(e.Code))
	}
	p(")\n\nvar serviceNames = map[Service]string{\n")
	for _, e := range cat.Services {
		p("\tService%s: %q,\n", e.Ident, e.Name)
	}
	p("}\n\n")
	p("type classService struct {\n\tclass   Class\n\tservice Service\n}\n\nvar classServiceNames = map[classService]string{\n")
	for _, e := range cat.ClassServices {
		p("\t{0x%02X, 0x%02X}: %q,\n", num(e.Class), num(e.Code), e.Name)
	}
	p("}\n\n")

	p("// General status codes.\nconst (\n")
	for _, e := range cat.GeneralStatus {
		p("\t// Status%s is %q (0x%02X).\n\tStatus%s GeneralStatus = 0x%02X\n", e.Ident, e.Name, num(e.Code), e.Ident, num(e.Code))
	}
	p(")\n\nvar generalStatusNames = map[GeneralStatus]string{\n")
	for _, e := range cat.GeneralStatus {
		p("\tStatus%s: %q,\n", e.Ident, e.Name)
	}
	p("}\n\n")

	p("// Extended status codes of the Connection Manager, carried with general\n// status 0x01 (connection failure).\nconst (\n")
	for _, e := range cat.ConnectionStatus {
		p("\t// ConnStatus%s is %q (0x%04X).\n\tConnStatus%s ConnectionStatus = 0x%04X\n", e.Ident, e.Name, num(e.Code), e.Ident, num(e.Code))
	}
	p(")\n\nvar connectionStatusNames = map[ConnectionStatus]string{\n")
	for _, e := range cat.ConnectionStatus {
		p("\tConnStatus%s: %q,\n", e.Ident, e.Name)
	}
	p("}\n\n")

	p("// Elementary data type codes.\nconst (\n")
	for _, e := range cat.DataTypes {
		p("\t// Type%s is the %s elementary data type (0x%02X).\n\tType%s DataType = 0x%02X\n", ident(e.Name), e.Name, num(e.Code), ident(e.Name), num(e.Code))
	}
	p(")\n\nvar dataTypeInfo = map[DataType]typeInfo{\n")
	for _, e := range cat.DataTypes {
		p("\tType%s: {%q, %d, kind%s},\n", ident(e.Name), e.Name, e.Size, strings.ToUpper(e.Kind[:1])+e.Kind[1:])
	}
	p("}\n\n")

	p("// Device types (Identity object attribute 2).\nconst (\n")
	for _, e := range cat.DeviceTypes {
		p("\t// DeviceType%s is %q (0x%02X).\n\tDeviceType%s DeviceType = 0x%02X\n", e.Ident, e.Name, num(e.Code), e.Ident, num(e.Code))
	}
	p(")\n\nvar deviceTypeNames = map[DeviceType]string{\n")
	for _, e := range cat.DeviceTypes {
		p("\tDeviceType%s: %q,\n", e.Ident, e.Name)
	}
	p("}\n\n")

	vs := append([]Vendor(nil), vend.Vendors...)
	sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
	p("// vendors is sorted by ID for VendorName.\nvar vendors = [...]vendorEntry{\n")
	for _, v := range vs {
		p("\t{%d, %q},\n", v.ID, v.Name)
	}
	p("}\n")

	return format.Source(b.Bytes())
}

// ident turns a data type name into a Go identifier suffix: SHORT_STRING
// becomes ShortString, BOOL stays BOOL.
func ident(name string) string {
	if !strings.Contains(name, "_") {
		return name
	}
	parts := strings.Split(name, "_")
	for i, p := range parts {
		parts[i] = p[:1] + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "")
}

func className(cat *Catalog, code string) string {
	for _, c := range cat.Classes {
		if num(c.Code) == num(code) {
			return c.Name
		}
	}
	return code
}

func genDoc(cat *Catalog, vend *Vendors) []byte {
	var b bytes.Buffer
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("<!-- Code generated by internal/cmd/gencatalog from cip/catalog.json and cip/vendors.json. DO NOT EDIT. -->\n\n")
	p("# CIP catalog\n\n")
	p("The codes the `cip` package names, generated from [cip/catalog.json](cip/catalog.json)\n")
	p("and [cip/vendors.json](cip/vendors.json). Codes marked *vendor* are Rockwell\n")
	p("Automation extensions, not part of CIP; the `logix` package uses them.\n\n")
	p("## Provenance\n\nThe ODVA specifications are sold by ODVA and are not redistributed here. Every\n")
	p("code below is a fact published in at least the source named in its row:\n\n| Source | Reference |\n|---|---|\n")
	keys := make([]string, 0, len(cat.Sources))
	for k := range cat.Sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p("| `%s` | %s |\n", k, cat.Sources[k])
	}
	p("\n## Object classes\n\n| Code | Class | Go constant | Source |\n|---|---|---|---|\n")
	for _, e := range cat.Classes {
		v := ""
		if e.Vendor {
			v = " *vendor*"
		}
		p("| 0x%02X | %s%s | `cip.Class%s` | %s |\n", num(e.Code), e.Name, v, e.Ident, e.Source)
	}
	p("\n## Common services\n\n| Code | Service | Go constant |\n|---|---|---|\n")
	for _, e := range cat.Services {
		p("| 0x%02X | %s | `cip.Service%s` |\n", num(e.Code), e.Name, e.Ident)
	}
	p("\n## Object-specific services\n\n| Class | Code | Service | Go constant |\n|---|---|---|---|\n")
	for _, e := range cat.ClassServices {
		v := ""
		if e.Vendor {
			v = " *vendor*"
		}
		p("| %s | 0x%02X | %s%s | `cip.Service%s` |\n", className(cat, e.Class), num(e.Code), e.Name, v, e.Ident)
	}
	p("\n## General status codes\n\n| Code | Meaning | Go constant |\n|---|---|---|\n")
	for _, e := range cat.GeneralStatus {
		p("| 0x%02X | %s | `cip.Status%s` |\n", num(e.Code), e.Name, e.Ident)
	}
	p("\n## Connection Manager extended status codes\n\n| Code | Meaning | Go constant |\n|---|---|---|\n")
	for _, e := range cat.ConnectionStatus {
		p("| 0x%04X | %s | `cip.ConnStatus%s` |\n", num(e.Code), e.Name, e.Ident)
	}
	p("\n## Elementary data types\n\n| Code | Type | Size (octets) | Go constant |\n|---|---|---|---|\n")
	for _, e := range cat.DataTypes {
		size := strconv.Itoa(e.Size)
		if e.Size == 0 {
			size = "variable"
		}
		p("| 0x%02X | %s | %s | `cip.Type%s` |\n", num(e.Code), e.Name, size, ident(e.Name))
	}
	p("\n## Device types\n\n| Code | Device type | Go constant |\n|---|---|---|\n")
	for _, e := range cat.DeviceTypes {
		p("| 0x%02X | %s | `cip.DeviceType%s` |\n", num(e.Code), e.Name, e.Ident)
	}
	p("\n## Vendors\n\n%d vendor IDs, from ODVA's public vendor list as pycomm3 1.2.16 carries it\n", len(vend.Vendors))
	p("(see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)); `cip.VendorName(id)` looks them up.\n")
	return b.Bytes()
}
