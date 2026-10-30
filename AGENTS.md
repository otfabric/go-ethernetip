# AGENTS.md — go-ethernetip

## What this is

Pure Go EtherNet/IP and CIP library: scanner and adapter roles, explicit and implicit (Class 0/1) messaging, EDS, Rockwell Logix tags. No cgo, no dependencies outside the standard library. Profile: **protocol-library**. Nothing here is certified by ODVA; what is verified, and against what, is in INTEROPERABILITY.md.

## Organisation standards

This repository follows **otfabric/engineering policy 1.1**, profile **protocol-library** (`.otfabric/policy.yaml`, mode `enforce`). Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Standards used, and what is public | docs/STANDARDS.md |
| Codes and vendors | `cip/catalog.json`, `cip/vendors.json` (generate `cip/catalog_gen.go`, CATALOG.md) |
| What is supported and verified | INTEROPERABILITY.md, docs/LIMITATIONS.md |
| How to test | TESTING.md |
| Errors | ERRORS.md |
| Release history | RELEASE.md (`## vX.Y.Z` … `---`) |

## Hard rules

1. Never lower `COVERAGE_MIN` (90), add lint suppressions, or skip or delete tests to make CI pass.
2. Never invent protocol semantics; ODVA specification text is never copied, and every code added to the catalog names its source.
3. Never claim conformance or interoperability beyond the evidence in INTEROPERABILITY.md.
4. No dependencies outside the standard library.
5. Codecs stay pure: `cip`, `encap` and the codec of `implicit` do no I/O beyond `encap.ReadPacket`. Vendor extensions stay in `logix`.
6. Change the catalog or the sample EDS and run `make generate`; never edit generated files.

## Commands

| When you change… | Run |
|---|---|
| anything | `make check` |
| a decoder | `make fuzz` (a new decoder needs a fuzz target) |
| sessions, connections, shutdown | `make chaos stress` |
| interop-relevant behaviour | `make interop` (Docker) |

## Definition of Done

`make check` green; tests for new behaviour including error paths; fuzz target for new decoders; API.md, ERRORS.md and docs/LIMITATIONS.md updated; RELEASE.md section for user-visible changes; failing or skipped steps reported.

## Git and releases

Branches and PRs. Do not push to `main`, tag or run the Release workflow unless the maintainer asks in the session.
