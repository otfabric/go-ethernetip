# Electronic Data Sheets

An EDS is the text file in which a vendor describes a device: identity,
parameters, assemblies and I/O connections. Package `eds`:

| Function | |
|---|---|
| `Parse(r)`, `ParseString(s)` | sections and entries, unchanged (vendor sections survive) |
| `File.Device()`, `Params()`, `Assemblies()`, `Connections()` | typed views of the public sections |
| `Validate(f)` | errors and warnings with line numbers |
| `File.Format()` | canonical text; `Parse(Format(f))` gives `f` |
| `Build(spec)` | an EDS for a device you describe (for example from a live device's identity and assemblies) |
| `GenerateGo(f, opts)` | Go source: see [CODEGEN.md](CODEGEN.md) |
| `ParseEPATH`, `FormatEPATH` | the packed hex EPATHs of EDS files |

## Grammar

`[Section]` headers; entries `Keyword = field, field, ...;` over any
number of lines; `$` comments; quoted strings (adjacent ones joined, `\"`
and `\\` escaped); empty fields (`,,`); datasets `{...}`; tokens for numbers
(decimal, `0x` hex), dates `mm-dd-yyyy`, times `hh:mm:ss`, keywords and
references (`Param3`, `Assem100`). Limits: 16 MiB, 4096 fields per entry,
262144 entries.

The grammar follows eds_pie (MIT) and published EDS files; the ODVA EDS
specification is not available to this project. Validation checks the
structure and consistency; it is not ODVA's EZ-EDS conformance check.

## Licensing of EDS files

Vendor EDS files are the vendors' and are usually not redistributable.
This repository contains only EDS files written for it
(`eds/testdata/*.eds`). Keep vendor files outside source control and
generate code from them locally.
