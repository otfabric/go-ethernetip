# Implementation progress

Durable state of the EtherNet/IP work across go-ethernetip,
ethernetip-interop and ethernetipctl. Updated at every milestone.

No work in progress: every branch is merged.

## Decisions

- Conventions: see [docs/ENGINEERING_ASSESSMENT.md](docs/ENGINEERING_ASSESSMENT.md).
- Research of the four reference stacks: [docs/research/STACKS.md](docs/research/STACKS.md).
- ODVA specifications are not available to this project (sold by
  subscription); codes come from public implementations, recorded per entry
  in `cip/catalog.json` and CATALOG.md.
- CIP Security: EtherNet/IP over TLS (TCP 2221) implemented with
  `crypto/tls`; DTLS (UDP 2221) and the security objects (0x5D, 0x5E, 0x5F)
  are not (no DTLS in the standard library, no reference peer).
- Server tolerance: accepts 8/16/32-bit logical segments (and pycomm3's
  format-3 32-bit), any source port for O->T datagrams, replies to
  SendUnitData with the T->O ID.

## Status

| Release | Date | Where |
|---|---|---|
| go-ethernetip v0.3.0 (seven more references; template size, connection size, Multiple Service fixes) | 2026-10-26 | https://github.com/otfabric/go-ethernetip/releases/tag/v0.3.0 |
| go-ethernetip v0.3.2 (interop pinned to ethernetip-interop v0.5.0) | 2026-10-26 | https://github.com/otfabric/go-ethernetip/releases/tag/v0.3.2 |
| ethernetip-interop v0.5.0 (weekly upstream candidates check; OpENer 2.3-591) | 2026-10-26 | https://github.com/otfabric/ethernetip-interop/releases/tag/v0.5.0 |
| ethernetip-interop v0.4.0 (12 multi-arch images: + go-ethernetip (loki-os)) | 2026-10-26 | https://github.com/otfabric/ethernetip-interop/releases/tag/v0.4.0 |
| ethernetip-interop v0.3.0 (11 multi-arch images: + libplctag, gologix, pylogix, etherip, eip-rs, node-ethernet-ip, EEIP.NET) | 2026-10-26 | https://github.com/otfabric/ethernetip-interop/releases/tag/v0.3.0 |
| go-ethernetip v0.2.1 (fix: ListIdentity over UDP could be off) | 2026-10-26 | https://github.com/otfabric/go-ethernetip/releases/tag/v0.2.1 |
| go-ethernetip v0.2.0 | 2026-10-26 | https://github.com/otfabric/go-ethernetip/releases/tag/v0.2.0 |
| ethernetip-interop v0.2.0 (4 multi-arch images, public on GHCR) | 2026-10-26 | https://github.com/otfabric/ethernetip-interop/releases/tag/v0.2.0 |
| ethernetipctl v0.2.0 (7 binaries, checksums), on go-ethernetip v0.2.0 | 2026-10-26 | https://github.com/otfabric/ethernetipctl/releases/tag/v0.2.0 |
| go-ethernetip, ethernetip-interop, ethernetipctl v0.1.0 | 2026-10-26 | the v0.1.0 tags of each repository |

GitHub CI green on the merged commits: go-ethernetip on Linux, macOS and
Windows (amd64 and arm64; race detector everywhere but Windows arm64), Go
1.23-1.26, 90% coverage gate (98.7%), lint, fuzz, chaos (with the chaos
monkey) and stress; interop on amd64 and arm64 against the pinned
ethernetip-interop v0.5.0 images (twelve references): 184 pass, 0 fail, 146 N/A
([matrix](INTEROPERABILITY.md#interop-matrix)). ethernetip-interop native
amd64/arm64 build, smoke and self-test (52 pass, 0 fail). ethernetipctl
reusable CI and 32-bit typecheck.

v0.2.0 in short: listen-only connections next to their owner,
configuration data, Logix bit writes, structures and STRING verified
against the references, and the defects they found fixed (see
[RELEASE.md](RELEASE.md)); e2e for Class 0, TLS, discovery and a shared
scanner endpoint; a seeded chaos monkey; the README comparison with the
four reference stacks; ethernetipctl's docs/examples.md generated from
real runs.

## Open issues (owner decisions)

These wait for a decision of the project owner; nothing is in progress.

1. **CIP Security beyond TLS.** Today: EtherNet/IP over TLS (TCP 2221)
   for explicit messaging, with `crypto/tls`. Not implemented: DTLS for
   Class 0/1 I/O (UDP 2221) and the CIP Security (0x5D), EtherNet/IP
   Security (0x5E) and Certificate Management (0x5F) objects. Needs two
   decisions:
   - **ODVA Volume 8** (CIP Security), sold by subscription: buy it and use
     it as the source, or keep building only from public information. The
     objects' attributes, services and state machines are defined there.
   - **A DTLS dependency** (for example `github.com/pion/dtls`, MIT): the
     standard library has no DTLS, and the module has no dependencies
     today. Accept one (in the module, or in a separate module such as
     `go-ethernetip/cipsecurity` so the core stays dependency-free), or
     leave DTLS out.
   - Also open: no reference implementation among the interop stacks
     supports CIP Security, so a peer for interop tests would have to be
     found (a commercial device, or a stack added to ethernetip-interop).
2. **Hardware validation** (optional): a run against a real ControlLogix
   or CompactLogix and a commercial adapter, to check behaviour that only
   the ODVA specifications define and no reference exercises.

## Next actions

None scheduled; see [Open issues](#open-issues-owner-decisions).
