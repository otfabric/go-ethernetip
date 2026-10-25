# Engineering assessment: OT Fabric conventions applied to EtherNet/IP

The discovery deliverable of the EtherNet/IP work: what the existing OT
Fabric repositories do, which of it this module, ethernetip-interop and
ethernetipctl follow, and what they do not copy.

## 1. Patterns found

| Area | Pattern | Seen in |
|---|---|---|
| Module | `github.com/otfabric/go-<proto>`, `go 1.23` floor, **no third-party dependencies** | go-dnp3, go-iec104, go-bacnet |
| Licence | MIT, `Copyright (c) 2026 OT Fabric`, `// SPDX-License-Identifier: MIT` on every file | all libraries |
| Layout | root package = shared sentinel/typed errors, `Logger`, `Metrics`, `State`; `client`, `server` and pure codec packages; `internal/logx`; `e2e/`; `interop/` (build tag `interop`); `examples/`; `internal/cmd/gen*` | go-dnp3 (`app`, `link`, `transport`), go-iec104 (`apci`, `asdu`) |
| Options | functional options `WithX(...) Option` returning `error`, validated into `ErrInvalidOption` | go-dnp3 client/server |
| Errors | sentinels wrapped with `%w`, typed errors for peer answers (`*IINError`, `*CommandError`) with `Is` methods | go-dnp3 |
| Logging | `Logger` (printf), `FieldLogger`, `ContextLogger`, `NewSlogLogger`; silent by default; `internal/logx` writes constant messages with fields | go-dnp3 |
| Metrics | callback interfaces with `NopMetrics` to embed, optional extensions (`RequestMetrics`, `ServerMetrics`) detected by type assertion | go-dnp3 |
| Generation | a JSON catalog is the source of truth; `go generate` writes code and a Markdown table; `generate-check` fails CI on drift | go-dnp3 `app/catalog.json` |
| Tests | race detector always; e2e over loopback; chaos proxy with seeded RNG; fuzz targets per codec with seeds; no fixed sleeps (deadline + condition) | go-dnp3, go-modbus |
| Makefile | self-documenting `help`; `GOWORK=off`; `fmt` with the go.mod-version gofmt; `check`, `test`, `coverage` (coverpkg), `fuzz FUZZTIME`, `bench`, `generate`, `generate-check`, `coverpkg-check`, `interop` | go-dnp3 |
| CI | `otfabric/.github/.github/workflows/go-ci.yml@v2` with `coverpkg` and `go-versions`; extra jobs for fuzz, examples, generate; interop workflow pulling pinned images | go-dnp3 |
| Release | `go-package-release.yml@v2` (libraries), `go-binary-release.yml@v2` (CLIs); `RELEASE.md` with one section per version, no "Unreleased" | go-dnp3, dnp3ctl |
| Interop repos | reference stacks in containers behind a **container contract** (`server`, `client <op>` printing JSON, `print-capabilities`, `print-fixture`, exit codes), fixtures, `versions.yaml` pins, `compose.yaml`, self-tests; the library's `interop/` package consumes the images | dnp3-interop, iec104-interop, modbus-interop |
| CLIs | cobra; `internal/{errs,format,runner,config}`; `--format text\|json\|table`; stable exit codes (`docs/exitcodes.md`); JSON field conventions (`docs/json-output.md`); writes need explicit flags | dnp3ctl, modbusctl |

## 2. Reused

- `internal/logx` and the `Logger` family: copied from go-dnp3 with the
  package renamed (same organisation, same licence).
- The catalog-and-generator pattern: `cip/catalog.json` +
  `internal/cmd/gencatalog` → `cip/catalog_gen.go`, `CATALOG.md`.
- The chaos proxy design (seeded, protocol-agnostic TCP fault injection).
- The interop architecture: ethernetip-interop owns images and fixtures;
  go-ethernetip owns its assertions in `interop/`.
- dnp3ctl's `errs`/`format`/`runner` structure for ethernetipctl.

## 3. Standards followed

All of section 1. In particular: no dependencies outside the standard
library, Go 1.23 language level (verified with the go1.23 toolchain), every
exported symbol documented with comments ending in a period (`godot`),
`exhaustive` switches, `make check` as the pre-push gate.

## 4. Differences between the reference repositories

- go-opcua is go 1.26 with dependencies (crypto); go-sunspec depends on
  go-modbus and a JSON-schema library; go-iec61850 on go-mms and cobra.
  go-dnp3, go-iec104 and go-bacnet have none. EtherNet/IP needs nothing but
  the standard library (TLS is `crypto/tls`), so it follows the latter.
- go-modbus keeps everything in one flat package with 100+ files; go-dnp3
  and go-iec104 split codecs, client and server into packages. The split is
  the better model for a protocol with several roles and is followed.
- go-s7comm and go-iec61850 commit coverage files and have no codecov/CI
  coverage gate; go-dnp3 enforces 90% via codecov and `make coverage`.

## 5. Conventions chosen for EtherNet/IP

- Packages: `cip` (CIP codec + catalog), `encap` (encapsulation codec),
  `implicit` (I/O codec + UDP endpoint), `client` (explicit originator),
  `scanner` (I/O originator), `server` (target/adapter), `logix` (vendor
  extensions, isolated), `eds` (Electronic Data Sheets).
- Vendor-specific (Rockwell Logix) codes are marked `vendor` in the
  catalog and live in `logix`; nothing in `cip`/`client`/`server` depends
  on them.
- Coverage gate 90% over all library packages (`coverpkg`), CI-enforced.

## 6. Not copied

- Committed coverage artefacts (`coverage.out`, `cover.out`) in go-s7comm
  and go-iec61850.
- The single flat package of go-modbus.
- PLAN.md/PROGRESS.md left stale after completion (go-iec61850): this
  repository's PROGRESS.md is updated at each milestone and reduced to a
  status record at the end.
