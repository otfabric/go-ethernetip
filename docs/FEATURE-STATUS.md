# Feature status

What go-ethernetip supports and how far each part is verified, as of v0.3.3.
The detail of every feature, and the generated results per peer, are in
[INTEROPERABILITY.md](../INTEROPERABILITY.md); what is left out, and why, in
[LIMITATIONS.md](LIMITATIONS.md).

None of this is a conformance claim: go-ethernetip has not been through ODVA
conformance testing and the ODVA specifications are not available to this
project ([STANDARDS.md](STANDARDS.md)). Behaviour follows public sources and
the reference implementations.

Status words, as in INTEROPERABILITY.md:

- **Interop verified**: passed against at least one independent implementation.
- **Implemented**: in the library, tested between the library's own ends.
- **Partial**: implemented with the restriction named.
- **Not implemented**: absent.

## Features

| Area | Status | Notes |
|---|---|---|
| Encapsulation: sessions, ListIdentity, ListServices, SendRRData, SendUnitData, common packet format | Interop verified | NOP, ListInterfaces, status codes and the inactivity timeout: implemented |
| EtherNet/IP over TLS (TCP 2221) | Implemented | no interop peer; no DTLS and no CIP Security objects |
| CIP data types, EPATH, Message Router, Multiple Service Packet | Interop verified | |
| Server objects: Identity, Message Router, Assembly, Connection Manager | Interop verified | |
| Server objects: Port, TCP/IP Interface, Ethernet Link, user objects | Implemented | |
| Server objects: Parameter, File, QoS, DLR, CIP Security | Not implemented | |
| Class 3 connected messaging | Interop verified | |
| Class 1 cyclic I/O, exclusive owner, input only, listen only, T->O multicast | Interop verified | |
| Class 0 I/O, run/idle, timeouts and recovery, electronic key check, Sockaddr Info | Implemented | |
| Application trigger | Partial | server, Class 3 only |
| Class 2, redundant owner, CIP Safety, scheduled priority | Not implemented | |
| Logix tags: read, write, fragmented, read-modify-write, tag list, templates | Interop verified | client and emulation; the emulation holds tags and templates only |
| Instance addressing (Symbol object) | Implemented | emulation only |
| EDS: parser, views, validation, formatting, code generation | Implemented | fuzzed; no conformance corpus to verify it against |

## Verification

| Evidence | Where |
|---|---|
| Unit, end-to-end, chaos, stress and leak suites with the race detector | [TESTING.md](../TESTING.md) |
| Coverage of at least 90 % in total and per package | `make coverage-check coverage-pkg-check` |
| 15 fuzz targets on the decoders and the server, in CI and in `fuzz.yml` | `make fuzz` |
| Independent peers: ethernetip-interop v0.5.0, images pinned by digest | `interop/harness_test.go`, `interop.yml`, nightly |

## Platforms

Tested natively on Linux, macOS and Windows, amd64 and arm64; FreeBSD and
32-bit ARM Linux are built, not tested. The interop suite runs on Linux amd64
and arm64. Multicast needs `IP_ADD_MEMBERSHIP` (Unix, Windows). Go 1.23 to 1.26
in CI.
