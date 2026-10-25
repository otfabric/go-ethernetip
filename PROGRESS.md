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
| cip, encap, implicit codecs; catalog generator | done (unit 96-100%, fuzzed) |
| client, scanner, server | done; unit tests in progress (subagent) |
| logix, eds | done (99.9%, 99.5%) |
| e2e, chaos (TCP + UDP + forged datagrams), stress, leak checks | done |
| benchmarks, examples, executable examples | done |
| Makefile, CI (ci, interop, fuzz, release), codecov | done (not yet run on GitHub: nothing pushed) |
| docs: README, ARCHITECTURE, ERRORS, OBSERVABILITY, SECURITY, TESTING, CONTRIBUTING, RELEASE, INTEROPERABILITY, THIRD_PARTY_NOTICES, docs/*.md | done; API.md pending |
| interopnode + interop suite | done: 49 pass / 10 N/A / 0 fail locally (dev images) |
| ethernetip-interop docs/infra | in progress (subagent) |
| ethernetipctl | in progress (subagent) |

## Next actions

1. Integrate the client/server test subagent's work (incl. the write-deadline fix); re-run coverage gate.
2. API.md; lint client/server/scanner.
3. Re-run interop with matrix; render INTEROPERABILITY.md (internal/cmd/genmatrix).
4. Review ethernetip-interop and ethernetipctl results; final verification from clean checkouts.
