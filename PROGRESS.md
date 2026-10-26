# Implementation progress

Durable state of the EtherNet/IP work across go-ethernetip,
ethernetip-interop and ethernetipctl. Updated at every milestone.

Branch: `feature/initial-implementation` in each repository.

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

Released 2026-10-26:

| Release | Where |
|---|---|
| go-ethernetip v0.1.0 | https://github.com/otfabric/go-ethernetip/releases/tag/v0.1.0 |
| ethernetip-interop v0.1.0 (4 multi-arch images, public on GHCR) | https://github.com/otfabric/ethernetip-interop/releases/tag/v0.1.0 |
| ethernetipctl v0.1.0 (7 binaries, checksums) | https://github.com/otfabric/ethernetipctl/releases/tag/v0.1.0 |

GitHub CI green on the merged commits: go-ethernetip on Linux, macOS and
Windows (amd64 and arm64; race detector everywhere but Windows arm64), Go
1.23-1.26, 90% coverage gate, lint, fuzz, chaos and stress; interop on
amd64 and arm64 against the pinned v0.1.0 images (49 pass, 0 fail, 10
N/A). ethernetip-interop native amd64/arm64 build, smoke and self-test.
ethernetipctl reusable CI and 32-bit typecheck.

## Next actions

See docs/DELIVERY_REPORT.md, section 20.
