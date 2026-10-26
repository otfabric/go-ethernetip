# EtherNet/IP delivery report

Date: 2026-10-26. All three repositories merged to `main` and released
as **v0.1.0** (go-ethernetip, ethernetip-interop with its four images,
ethernetipctl with its binaries), with GitHub CI green on the merged
commits.

Status words: **Implemented** (in the code with tests between the
library's own ends), **Interop verified** (also passed against an
independent implementation), **Partial**, **Not implemented**, **Blocked**.

## 1. Repositories and commits

| Repository | Commits on the branch | Content |
|---|---|---|
| [otfabric/go-ethernetip](https://github.com/otfabric/go-ethernetip) | [PR #1](https://github.com/otfabric/go-ethernetip/pull/1), [v0.1.0](https://github.com/otfabric/go-ethernetip/releases/tag/v0.1.0) | library, tests, interop suite, docs, CI |
| [otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop) | [PR #1](https://github.com/otfabric/ethernetip-interop/pull/1), [v0.1.0](https://github.com/otfabric/ethernetip-interop/releases/tag/v0.1.0) | OpENer, cpppo, EIPScanner, pycomm3 adapters and images; contract, fixtures, schemas, self-tests, CI |
| [otfabric/ethernetipctl](https://github.com/otfabric/ethernetipctl) | [PR #1](https://github.com/otfabric/ethernetipctl/pull/1), [v0.1.0](https://github.com/otfabric/ethernetipctl/releases/tag/v0.1.0) | CLI, 7 release binaries |

## 2. Architecture

Pure Go, no dependencies, Go 1.23 floor (verified with the go1.23.0
toolchain). Packages: `cip` (CIP codec and a generated catalog), `encap`
(encapsulation), `implicit` (I/O datagrams, UDP endpoint, connection
runtime), `client` (explicit originator), `scanner` (I/O originator),
`server` (target), `logix` (Rockwell extensions, isolated), `eds`. See
[ARCHITECTURE.md](../ARCHITECTURE.md). Conventions follow go-dnp3 /
dnp3-interop / dnp3ctl ([ENGINEERING_ASSESSMENT.md](ENGINEERING_ASSESSMENT.md)).

## 3. Protocol features

Full matrix: [INTEROPERABILITY.md](../INTEROPERABILITY.md#protocol-coverage).
Encapsulation (all session/list commands TCP and UDP, SendRRData,
SendUnitData, CPF items, status codes, limits, inactivity timeout) —
interop verified. CIP messages, EPATH (all segment types), Multiple Service
Packet, Unconnected_Send, Forward_Open/Large/Close — interop verified.
EtherNet/IP over TLS — implemented (no interop peer). Class 2,
Get/Search_Connection_Data, Get_Connection_Owner, IndicateStatus/Cancel —
not implemented.

## 4. Code generation

- `cip/catalog.json` + `cip/vendors.json` → `cip/catalog_gen.go`,
  `CATALOG.md` (`internal/cmd/gencatalog`): 78 classes, 23 common and 14
  object-specific services, 46 general statuses, 71 Connection Manager
  statuses, 30 data types, 41 device types, 1463 vendors; each entry with
  its public source (OpENer, pycomm3, eds_pie, Rockwell 1756-PM020).
- EDS → Go (`eds.GenerateGo`, `ethernetipctl eds codegen`): identity, key,
  parameter descriptors and range checks, enums, assembly structs with
  Encode/Decode, scanner configurations. Committed sample
  `eds/internal/sampledevice` (`internal/cmd/gensample`).
- Both deterministic, `-check` mode in `make generate-check` and CI.
- Investigated and not used: ODVA CIP Identification/Security JSON schemas
  (registration and terms, no redistribution licence), Rockwell L5X (no
  published XSD), eds_pie JSON (used to cross-check class codes only).

## 5. Scanner and adapter

Scanner: Class 0/1, exclusive owner, input only, listen only, multicast,
run/idle, initial output and idle start, sequence handling, timeout,
reconnect — interop verified with OpENer (point-to-point, input only,
multicast, Large_Forward_Open, refusals). Adapter: ownership rules,
heartbeats, shared multicast production, change-of-state, all Forward_Open
refusals with extended status, limits — interop verified with EIPScanner
(exclusive owner, input only, Large_Forward_Open, refusal) and pycomm3 and
cpppo for explicit and Class 3.

## 6. CIP objects

Server: Identity, Message Router, Assembly, Connection Manager — interop
verified; Port, TCP/IP Interface, Ethernet Link — implemented; user objects
via `server.Object` / `server.NewObject`. Not implemented: Parameter, File,
QoS, DLR, CIP Security objects.

## 7. Logix extensions

Client and emulation: Read/Write Tag, fragmented forms, Multiple Service
Packet of tags, tag list (0x55), program name — interop verified (pycomm3
and cpppo against the emulation, the client against cpppo).
Read-Modify-Write, templates/UDT decoding, instance addressing —
implemented (no reference exercises them: cpppo lacks them, the fixture
has no structures).

## 8. Interoperability results

Against the published, digest-pinned ethernetip-interop v0.1.0 images,
locally and in GitHub CI on amd64 and arm64: **49 pass, 0 fail, 10 N/A** ([matrix](../INTEROPERABILITY.md#interop-matrix),
`interop/results/matrix.json`).

| Stack | Version | Direction(s) | Highlights |
|---|---|---|---|
| OpENer | d8820ef (v2.3+588) | go → OpENer | identity TCP/UDP, ListServices, attributes, echo, errors, Class 3, Class 1 p2p/input-only/multicast/Large, size refusal; N/A: MSP, routing, Logix |
| EIPScanner | 1.3.0+33 | EIPScanner → go | ListIdentity, 16-bit segments, GAA, SAS, MSP, Class 1 p2p/input-only/Large, refusal; N/A: Class 3, multicast, Logix |
| pycomm3 | 1.2.16 | pycomm3 → go | identity TCP/UDP, Class 3 (Large FO), errors, Unconnected_Send, LogixDriver open, tag list, reads, 1200-octet fragmented read, writes, multi-tag |
| cpppo | 5.2.5 | both | go → cpppo: identity, attributes, MSP, Logix reads/writes, fragmented reads unconnected and Class 3; cpppo → go: identity, attributes, MSP, Logix |

ethernetip-interop's own self-test (references against each other): 50
pass, 0 fail, 58 N/A; smoke 94/94 checks. Defects found by interop and
fixed in go-ethernetip: UDP ListIdentity address, multicast membership on
Linux, Logix partial transfers ending mid-element, Write Tag tolerance of
pycomm3's duplicated requests.

## 9. Unit, integration and E2E tests

All pass with `-race` (`make test`), in a clean clone, and with Go 1.23.0.
e2e covers explicit, routing, MSP, Class 3, Class 1 exchange, refusals,
timeouts/recovery, Logix; the server has a raw-socket encapsulation suite
and a 9000-message robustness test.

## 10. Coverage (combined profile, race, `make coverage-check`)

Total **98.6%** (gate 90%). cip 99.9, encap 100, implicit ~96, client 98.2,
server 97.8, scanner 97.7, logix 99.9, eds 99.5, root 100, internal/logx
100. ethernetipctl: **95.0%** (gate 90%). Excluded, documented: examples,
internal/cmd, the generated sample package, the interop suite.

## 11. Race detector

No known race. Races found and fixed: two concurrent Forward_Opens could
both own an output assembly (TestConcurrentOwners); a scanner WaitGroup
Add/Wait race. `make stress` repeats the concurrency suites 10×.

## 12. Chaos and stress

TCP proxy (splits, delays, kills, corruption), UDP faults (20% drop, 10%
duplicate, 10% reorder, blackout), forged/replayed I/O datagrams, many
clients, shared sessions with 8 in flight, session and connection limits
under contention, reconnect storms with server restarts, shutdown under
load, random cancellation, connect cycles; leak check (goroutines, file
descriptors) after the e2e suite. All pass. Found: requests with short
deadlines closed the shared session (fixed).

## 13. Fuzzing

15 targets; 60 s each locally (e.g. FuzzSplitMultiple 24.5 M execs,
FuzzParse 2.8 M); CI 15 s per push, 10 min nightly. Fixed: panic on a
malformed Multiple Service Packet (server crash), 32-bit class truncation,
EDS round-trip and generator defects (9), Logix template recursion and
exponential decode. No open crashers.

## 14. Platforms

Tested natively in GitHub CI: Linux amd64 and arm64, macOS amd64 and
arm64, Windows amd64 and arm64 (race detector everywhere except Windows
arm64, which Go does not support), Go 1.23 to 1.26. Interop on Linux amd64
and arm64. Cross-built only: linux/arm, freebsd, js/wasm (multicast reports
ErrUnsupported there). The first CI runs found and fixed: a Serve/Close
WaitGroup race (Windows), a Close reported as a lost connection, and
platform assumptions in tests (CRLF checkouts, broadcast sends, timer
granularity).

## 15. Benchmarks

[TESTING.md](../TESTING.md#benchmarks): explicit round trip 30 µs, 11 µs
per request with 8 in flight, request encode 48 ns / 0 allocs, packet
read 66 ns / 0 allocs, I/O receive path 72 ns. No comparison with the
references (they run in containers; the harness dominates).

## 16. CI status

Green on the merged commits of all three repositories. Workflows: go-ethernetip `ci.yml` (reusable go-ci@v2,
coverage gate, generated code, examples, platforms, fuzz, chaos/stress),
`interop.yml`, `fuzz.yml`, `release.yml`; ethernetip-interop `ci.yml`
(validate, shellcheck, native amd64/arm64 build/smoke/self-test),
`release.yml`; ethernetipctl `ci.yml`, `release.yml`. Releases ran through
the organisation's reusable release workflows.

## 17. Documentation

go-ethernetip: README, API, ARCHITECTURE, ERRORS, OBSERVABILITY, SECURITY,
TESTING, CONTRIBUTING, RELEASE, INTEROPERABILITY, CATALOG,
THIRD_PARTY_NOTICES, docs/ (GETTING_STARTED, EXPLICIT, IMPLICIT, OBJECTS,
LOGIX, EDS, CODEGEN, STANDARDS, LIMITATIONS, ENGINEERING_ASSESSMENT,
research/STACKS), examples (7) and executable examples.
ethernetip-interop: README, CONTAINER_CONTRACT, FIXTURES, CAPABILITIES,
COMPATIBILITY, THIRD_PARTY_NOTICES and repo files. ethernetipctl: README,
docs/exitcodes, json-output, adapter-config and repo files.

## 18. Licensing

All three repositories MIT with SPDX headers, except the cpppo adapter and
image (GPL-3.0-or-later, because cpppo is). Upstream licences ship in the
images; notices in THIRD_PARTY_NOTICES. The vendor table comes from
pycomm3 (MIT, attributed). No ODVA text, no vendor EDS files. **Unresolved
obligations** (for products, not for the code): ODVA vendor ID and Terms
of Usage; no conformance claim ([STANDARDS.md](STANDARDS.md)).

## 19. Known limitations and risks

[LIMITATIONS.md](LIMITATIONS.md). Main ones: CIP Security is TLS only (DTLS
and the security objects **blocked**: no ODVA Volume 8, no DTLS in the
standard library, no reference peer); behaviour that only the ODVA
specifications define and no reference exercises may deviate; I/O is
unauthenticated; one scanner
endpoint cannot consume one multicast production twice.

## 20. Next steps

1. Add interop cases for listen-only, configuration data, Read-Modify-Write
   and templates (needs a structure in the logix fixture).
2. CIP Security beyond TLS if ODVA Volume 8 and a DTLS dependency are
   accepted; consider a hardware validation against a real ControlLogix.
