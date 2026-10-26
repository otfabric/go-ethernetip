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
| go-ethernetip: all packages, tests, docs, CI config | done; combined coverage 98.6% (race), lint clean |
| fuzz: 15 targets x 60 s locally, CI 15 s per push and 10 min nightly | no crashers after the fixes |
| interop (dev images): 49 pass / 0 fail / 10 N/A | done, rendered in INTEROPERABILITY.md |
| ethernetip-interop: adapters, contract, fixtures, scripts, CI | done (commit 534a275): smoke 94/94, self-test 50 pass / 58 N/A |
| ethernetipctl | done: 95.0% coverage, lint clean, 7 release targets build, verified against OpENer in Docker |
| push, PRs, CI on GitHub, v0.1.0 tags and image digests | not done: needs the user's go-ahead |

## Next actions

1. With approval: push branches, open PRs, tag ethernetip-interop v0.1.0 so images publish, pin digests in interop/harness_test.go.
