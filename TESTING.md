# Testing

Tests need nothing but Go. Clients, scanners and servers run against each
other over loopback TCP and UDP; no mocks stand in for the network.

| Suite | Where | What it shows | Run |
|---|---|---|---|
| Unit | each package | codecs with known vectors and round trips, every error path, option validation, object behaviour, scripted peers for protocol violations | `make test` |
| End to end | `e2e/` | client, scanner and server against each other: identity, discovery, attributes, errors, Multiple Service Packet, routing, Class 3, TLS, Class 0 and Class 1 exchange, configuration data, multicast with a listen-only connection, several adapters on one scanner endpoint, refusals, timeouts and recovery, Logix tags, structures and bits through the emulation | `make test` |
| Chaos | `e2e/chaos_test.go`, `e2e/monkey_test.go`, `implicit/chaos_test.go` | TCP proxy that splits, delays, corrupts and kills connections; UDP faults (drop, duplicate, reorder, blackout) injected at the I/O endpoint; forged and replayed I/O datagrams; a chaos monkey: workers mixing explicit, Class 3, Logix and Class 1 operations and client churn at random through the faulty proxy, checking every answer and the state afterwards (`ETHERNETIP_MONKEY_DURATION`, default 3 s) | `make chaos` |
| Stress and parallel | `e2e/stress_test.go` and the packages | many clients, shared sessions with requests in flight, session and connection limits under contention, concurrent Forward_Open/Close, reconnection storms, shutdown under load, random cancellation | `make stress` |
| Leaks | `e2e/main_test.go` | after the whole e2e suite: no goroutine and no file descriptor left | `make test` |
| Fuzz | `*_fuzz_test.go` | every decoder (encapsulation, CPF, CIP requests and responses, EPATH, Multiple Service Packet, Forward_Open, Unconnected_Send, identity, I/O datagrams, EDS) and the server's Logix dispatch: no panic, bounded allocation, round trips | `make fuzz` (CI: 15 s each per push, 10 min each nightly) |
| Benchmarks | `cip`, `encap`, `implicit`, `e2e` | codec throughput and allocations; request latency, throughput, Class 3, fragmented Logix reads | `make bench` |
| Interop | `interop/` (build tag `interop`) | the library against OpENer, EIPScanner, pycomm3 and cpppo, both directions | `make interop` (Docker) |

## Rules

- Every test passes with `-race`, repeatedly (`-count=10` for new ones).
- A test that waits polls a condition with a deadline; it does not sleep a
  fixed time for something to happen.
- Chaos tests use seeded randomness and print the seed on failure;
  `ETHERNETIP_CHAOS_SEED=<seed> make chaos` repeats a run;
  `ETHERNETIP_MONKEY_DURATION=10m` soaks the chaos monkey.
- Multicast tests over loopback skip, saying so, where the system does not
  deliver multicast on the loopback interface.
- Coverage is measured across the library packages together (`make
  coverage`: `-coverpkg` over every library package, so that the e2e suite
  counts for the packages it exercises) and must be at least 90%
  (`make coverage-check`, CI job "Coverage gate"). Not counted: the
  examples, `internal/cmd` (generators and the interop node), the
  generated sample package `eds/internal/sampledevice` (tested, but
  generated), the interop suite.

## Platforms

CI runs the unit, e2e, chaos and stress suites natively on Linux amd64 and
arm64, macOS amd64 and arm64, and Windows amd64 and arm64 (job
"platforms"; with the race detector everywhere but Windows arm64, which
Go's race detector does not support), and cross-compiles for FreeBSD and 32-bit ARM Linux (`make
cross`; built, not tested). Multicast membership uses `IP_ADD_MEMBERSHIP`
on Unix and Windows; on other systems it reports `ErrUnsupported`. The
interop suite needs Docker and runs on Linux amd64 and arm64.

## Benchmarks

On an Apple M-series laptop (darwin/arm64, Go 1.27, loopback), from
`make bench`:

| Benchmark | Result |
|---|---|
| EPATH encode (6 segments) | 77 ns, 0 allocs |
| EPATH decode | 484 ns, 9 allocs |
| Request encode / decode | 48 ns, 0 allocs / 175 ns, 4 allocs |
| Response decode | 31 ns, 0 allocs |
| Forward_Open encode + decode | 412 ns |
| Encapsulation packet encode (500 octets) | 45 ns, 0 allocs |
| `ReadPacket` (500 octets) | 66 ns, 0 allocs |
| I/O datagram decode | 30 ns, 1 alloc |
| I/O receive path (decode, checks, callback) | 72 ns, 1 alloc |
| Explicit request round trip (unconnected) | 30 µs |
| Explicit request round trip (Class 3) | 31 µs |
| Shared session, 8 in flight | 11 µs per request |
| One session per goroutine | 12 µs per request |
| Multiple Service Packet of 16 requests | 127 µs |
| Logix read of 1000 INT (Class 3, 2000 octets) | 34 µs |

Numbers depend on the machine; compare runs on the same one. No
comparison with the reference implementations is published: they run in
containers through the interop harness, whose start-up dominates any
measurement.
