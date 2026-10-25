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

| Milestone | State |
|---|---|
| Discovery, research | done |
| cip, encap codecs + catalog generator | done |
| client (explicit, Class 3, Forward_Open/Close, discovery) | done |
| implicit (Class 0/1 codec, endpoint, connection runtime) | done |
| server (objects, sessions, Connection Manager, I/O, multicast) | done |
| scanner (I/O originator, timeout, reconnect) | done |
| e2e: explicit, routing, MSP, I/O exchange, refusals, timeouts | done (passing, -race) |
| unit tests of codecs, fuzz, chaos, stress, leak tests | next |
| logix (client + server emulation) | pending |
| eds (parser, validation, writer, Go generator) | pending |
| docs, examples, Makefile, CI | pending |
| ethernetip-interop (OpENer, cpppo, EIPScanner, pycomm3) | pending |
| ethernetipctl | pending |

## Next actions

1. Unit tests + fuzz targets for cip, encap, implicit.
2. logix package.
3. eds package.
