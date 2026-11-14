# Testing

Tests need nothing but Go. Clients, scanners and servers run against each
other over loopback TCP and UDP; no mocks stand in for the network.

| Suite | Where | What it shows | Run |
|---|---|---|---|
| Unit | each package | codecs with known vectors and round trips, every error path, option validation, object behaviour, scripted peers for protocol violations | `make test` |
| End to end | `e2e/` | client, scanner and server against each other: identity, discovery, attributes, errors, Multiple Service Packet, routing, Class 3, TLS, Class 0 and Class 1 exchange, configuration data, multicast with a listen-only connection, several adapters on one scanner endpoint, refusals, timeouts and recovery, Logix tags, structures and bits through the emulation | `make e2e`; also part of `make test` |
| Chaos | `e2e/chaos_test.go`, `e2e/monkey_test.go`, `implicit/chaos_test.go` | TCP proxy that splits, delays, corrupts and kills connections; UDP faults (drop, duplicate, reorder, blackout) injected at the I/O endpoint; forged and replayed I/O datagrams; a chaos monkey: workers mixing explicit, Class 3, Logix and Class 1 operations and client churn at random through the faulty proxy, checking every answer and the state afterwards (`ETHERNETIP_MONKEY_DURATION`, default 3 s) | `make chaos` |
| Stress and parallel | `e2e/stress_test.go` and the packages | many clients, shared sessions with requests in flight, session and connection limits under contention, concurrent Forward_Open/Close, reconnection storms, shutdown under load, random cancellation | `make stress` |
| Leaks | `e2e/main_test.go`; `main_test.go` of `client`, `server`, `implicit`, `scanner` | after the whole e2e suite: no goroutine and no file descriptor left; after the tests of each of the four packages: no goroutine left that runs code of the module and did not exist before the tests (stacks compared, `internal/testenv`) | `make test` |
| Fuzz | `*_fuzz_test.go`, `eds/fuzz_test.go`, `logix/fuzz_test.go` | the decoders of EPATH (padded and packed), CIP requests and responses, Multiple Service Packet, Forward_Open, the Forward_Open and Forward_Close replies, connection failures, Unconnected_Send, identity, the encapsulation header, packets and stream, CPF, the identity item, I/O datagrams and payloads, EDS files, Logix templates and read replies; the client's handling of reply streams; the server's handling of request streams and of Logix requests: every input is decoded or refused with an error, and decodes back to itself where the format has a round trip | `make fuzz` runs every `Fuzz` function it finds (`go test -list`); CI: 10 s each per pull request, 10 min each nightly |
| Allocation budgets | `cip/budget_test.go`, `encap/budget_test.go`, `implicit/budget_test.go`, `eds/limits_test.go`, `server/budget_test.go`, `logix/hostile_test.go` | what one call allocates at the documented limits, with the largest counts and sizes the fields can state: decoders within 16 octets per input octet plus 64 KiB; CPF and I/O datagrams within 4 KiB; `ReadPacket` within twice its limit; `eds.Parse` within 256 MiB for any file up to 16 MiB; a server reply within four times the encapsulation maximum; a Logix template decode within 64 MiB | `make test` |
| Benchmarks | `cip`, `encap`, `implicit`, `e2e` | codec throughput and allocations; request latency, throughput, Class 3, fragmented Logix reads | `make bench` |
| Recorded traffic | `*/capture_test.go`, `internal/capture`, [testdata/captures](testdata/captures/README.md) | 20 committed captures (31 MB, about 200,000 messages) of a 1756-L63 ControlLogix, a 1756-ENBT/A, a Micro850, a MicroLogix 1400 and unidentified targets: every message decodes and encodes back byte for byte; the client and the Logix client against the recorded replies (a request no recorded originator sent fails); the server and the Logix emulation against the recorded requests (the devices' answers byte for byte, known differences pinned); Class 1 datagrams; truncations, malformed variants and 300 seeded mutated streams | `make test` |
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
  `ETHERNETIP_REQUIRE_MULTICAST=1` turns that skip into a failure; the CI job
  "Coverage gate" sets it.
- Coverage is measured across the library packages together (`make
  coverage`: `-coverpkg` over every library package, so that the e2e suite
  counts for the packages it exercises) and must be at least 90%
  (`make coverage-check`, CI job "Coverage gate"), and so must each package
  (`make coverage-pkg-check`, `COVER_PKG_MIN`). Not counted: the
  examples, `internal/cmd` (generators and the interop node), the
  test helper `internal/testenv`, the generated sample package
  `eds/internal/sampledevice` (tested, but generated), the interop suite,
  and the capture reader `internal/capture` (test infrastructure, tested
  at 97 %).
- Capture tests read only committed files: no download, no network.

## Platforms

CI runs the unit, e2e, chaos and stress suites natively on Linux amd64 and
arm64, macOS amd64 and arm64, and Windows amd64 and arm64 (job
"platforms"; with the race detector everywhere but Windows arm64, which
Go's race detector does not support), and cross-compiles for FreeBSD and 32-bit ARM Linux (`make
cross`; built, not tested). Nightly, `fuzz.yml` runs the tests of `cip`,
`encap`, `implicit`, `logix` and `eds` with `GOARCH=386` (a 32-bit
`int`) on Linux amd64. Multicast membership uses `IP_ADD_MEMBERSHIP`
on Unix and Windows; on other systems it reports `ErrUnsupported`. The
interop suite needs Docker and runs on Linux amd64 and arm64.

## Lifecycle contracts

The long-lived types against the rows of the contract matrix (L1–L16 of
the OT Fabric testing standard): `client.Client` (C), `client.Conn` (Cn),
`server.Server` (S), `scanner.Scanner` (Sc), `scanner.IO` (IO),
`implicit.Endpoint` (E), `implicit.Connection` (IC).

| Row | Covered by | Not covered |
|---|---|---|
| L1 Close twice | C `TestLifecycleAgainstServer`; Cn `TestConnAgainstServer`; S `TestLifecycle`; Sc `TestOptions`; IO `TestExchangeAndAPI`; E `TestEndpointClose`; IC `TestCloseStopsCallbacks` | — |
| L2 Two goroutines call Close | C, Cn `client/lifecycle_test.go` `TestConcurrentClose`; S `server/lifecycle_test.go` `TestConcurrentClose`; Sc, IO `scanner/lifecycle_test.go` `TestConcurrentClose`; E, IC `implicit/lifecycle_test.go` `TestConcurrentClose` | — |
| L3 Close during a blocked read | C `TestClientCloseDuringRead`; Cn `TestConnCloseDuringRead`; S `TestHostileCloseWithIdlePeers`, `TestCloseUnregistered`; E `TestEndpointClose` | — |
| L4 Close during a write | C `TestClientCloseDuringWrite` (`Close` waits for the write, at most the client's timeout); Cn `TestConnCloseDuringWrite`, `TestConnWriteFailureBoundedByContext`; write failures: C `TestWriteFailure`, `TestSessionLostOnWriteFailure`, `TestWriteDeadlineIsClientTimeout`; S `TestReplyWriteFailure` | S: no test closes during a reply's write |
| L5 Close during the handshake | C `TestCloseWhileConnecting`; Sc `TestOpenRacingClose` (`Open` waiting for the Forward_Open reply) | S: no test closes during a TLS handshake or a RegisterSession |
| L6 Cancel a pending request | C `TestTimeoutAndCancel`; Cn `TestConnAgainstServer`; e2e `TestStressCancellation` | — |
| L7 Response after the timeout | C `TestDroppedPackets`; Cn `TestConnDroppedReplies`; e2e `TestStressCancellation` | late replies are dropped with a Debug log, not counted |
| L8 Response after a reconnect | — (a session's pending requests and connections belong to that session; sender contexts come from a counter that does not repeat) | no test that a reply of the old session completes nothing |
| L9 A callback calls a public method | S `TestHandlerCallsServer`; Sc, IO `TestCallbacksCallMethods` (`OnInput`, `OnState`); E, IC `TestCallbacksCallConnection` (`OnData`, `OnTimeout`) | C: the state handler must not call the client (`WithStateHandler`) |
| L10 A callback calls Close | IO `TestOnStateCallsClose` (`IO.Close` and `Scanner.Close` from `OnState`, with and without `Reconnect`); IC `TestCallbacksCallConnection` (`Connection.Close` from `OnData` and `OnTimeout`) | `implicit.Config.Produce` calling `Connection.Close`, `OnData` calling `Endpoint.Close`, `OnInput` calling `Scanner.Close`, a server handler calling `Server.Close`: these wait for the goroutine the callback runs on, and are not supported |
| L11 Slow callback | documented: callbacks must not block (API.md) | no test; a slow `OnData` or `OnInput` holds every connection of its endpoint |
| L12 Queue at capacity | C `TestMaxPendingCorrelation`; S `TestDelayedDiscoveryBound`, `TestTCPConnectionLimit`, `TestForwardOpenLimits`, `TestMaxConnectionsPerOriginator`; e2e `TestStressSessionLimit` | — |
| L13 Concurrent sessions | S `TestHostileForeignSessionHandle`, `TestForwardCloseOtherOriginator`, `TestConcurrentOwners`; e2e `TestStressSharedSession`, `TestStressManyClients` | — |
| L14 Failure during construction | C `TestDialFailures`, `TestHostileRegisterReplies`; S `TestListenErrors`, `TestIOEndpointFailure`, `TestTLSHandshakeFailureReleasesSlot`; E, IC `TestOpenErrors`, `TestMulticastJoinFailure`, `TestEndpointCloseStopsProducers`; Sc `TestOpenWithoutTarget`, `TestForwardOpenReplyChecks`; the leak checks of each package | — |
| L15 Shutdown(ctx) | n/a: there is no `Shutdown`; `Scanner.Close(ctx)`, `IO.Close(ctx)` and `Conn.Close(ctx)` bound their Forward_Close by the context | — |
| L16 Close racing a reconnect | IO `TestCloseDuringReconnect`; Sc `TestOpenRacingClose`; C reconnects only inside a request (L5) | — |

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
| I/O receive path (decode, checks, callback) | 115–189 ns, 2 allocs (72 B)\* |
| Explicit request round trip (unconnected) | 30 µs |
| Explicit request round trip (Class 3) | 31 µs |
| Shared session, 8 in flight | 11 µs per request |
| One session per goroutine | 12 µs per request |
| Multiple Service Packet of 16 requests | 127 µs |
| Logix read of 1000 INT (Class 3, 2000 octets) | 34 µs |

\* Measured on an Apple M1 (darwin/arm64), Go 1.27.4, on 2026-11-14, for
v0.6.1: `go test -run '^$' -bench 'BenchmarkConsume$' -benchtime 2s
-count 5 ./implicit`, the range of the five runs. Every datagram of the
benchmark is newer than the last and reaches the callback
(`TestConsumeDatagram`).

Numbers depend on the machine; compare runs on the same one. No
comparison with the reference implementations is published: they run in
containers through the interop harness, whose start-up dominates any
measurement.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml`, `interop.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml`, `interop.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Schedule | `fuzz.yml`, `interop.yml` | the scheduled runs, on `main` |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
