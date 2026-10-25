# Code generation

Two generators, both deterministic, both with a `-check` mode that CI runs
(`make generate-check`).

## The CIP catalog

`cip/catalog.json` lists the object classes, services (common and
object-specific), general status codes, Connection Manager extended status
codes, data types and device types, each with the public source it was
checked against; `cip/vendors.json` the vendor IDs.
`internal/cmd/gencatalog` validates them (unique codes and identifiers,
known sources) and writes `cip/catalog_gen.go` (typed constants and name
tables) and `CATALOG.md`. Edit the JSON and run `make generate`.

Machine-readable sources investigated: eds_pie's `ethernetip_lib.json`,
`common_object_class.json` and `meta_eds_lib.json` (MIT; EDS keyword
grammar and class codes, used to cross-check class codes), ODVA's CIP
Identification and CIP Security JSON schemas (registration and terms
required, no licence for redistribution: not used), Rockwell's L5X export
format (documented in a public manual, no XSD published: not used; the
Logix data model comes from the tag services themselves). No
machine-readable CIP object library with a redistributable licence exists;
the catalog is the curated alternative.

## Devices from EDS files

`eds.GenerateGo` (and `ethernetipctl eds codegen`) turns an EDS into a Go
package:

- identity constants and `Key()` (the electronic key);
- per parameter a `ParamInfo`, the default as a typed constant and a
  `Check...` range function; enumerated parameters get a type with
  constants and `String`;
- per assembly its instance and size and, when its members are whole
  octets of numeric parameters, a struct with `Encode` and `Decode...`;
- per I/O connection a function returning its `scanner.IOConfig`.

`eds/internal/sampledevice` is the generator's output for
`eds/testdata/otfabric_adapter.eds`, committed and tested like any package
(`internal/cmd/gensample`). The generator's own tests type-check the
output for a second, richer file.
