# go-ethernetip - EtherNet/IP and CIP Scanner and Adapter Library for Go

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-ethernetip.svg)](https://pkg.go.dev/github.com/otfabric/go-ethernetip)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Status](https://github.com/otfabric/go-ethernetip/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-ethernetip/actions/workflows/ci.yml)
[![Interop](https://github.com/otfabric/go-ethernetip/actions/workflows/interop.yml/badge.svg)](https://github.com/otfabric/go-ethernetip/actions/workflows/interop.yml)
[![Code Coverage](https://codecov.io/gh/otfabric/go-ethernetip/graph/badge.svg)](https://codecov.io/gh/otfabric/go-ethernetip)

A pure Go implementation of EtherNet/IP and the Common Industrial Protocol
(CIP), the industrial Ethernet protocol of programmable controllers, I/O
adapters, drives and sensors. No cgo, no dependencies outside the standard
library.

The library provides:

- A **client** (originator of explicit messages): sessions, unconnected
  requests (SendRRData), routing through Unconnected_Send, connected
  explicit messaging over Class 3 connections (SendUnitData),
  Multiple Service Packet, Forward_Open, Large_Forward_Open and
  Forward_Close, ListIdentity, ListServices and ListInterfaces over TCP and
  UDP, discovery
- A **scanner** (originator of implicit I/O): Class 1 and Class 0
  connections to a target's assemblies, cyclic UDP exchange on port 2222,
  run/idle, sequence handling, timeout detection, automatic reopening,
  point-to-point and multicast T->O, exclusive owner, input-only and
  listen-only connection points
- A **server** (target, adapter): the Message Router with the Identity,
  Message Router, Assembly, Connection Manager, Port, TCP/IP Interface and
  Ethernet Link objects, user-defined objects, Class 0/1/3 connections with
  ownership rules, multicast production shared between connections, every
  Connection Manager refusal with its extended status, resource limits
- **Rockwell Logix extensions** (vendor specific, in package `logix`): tag
  reads and writes by name, fragmented reads and writes, Read-Modify-Write
  for bits, the tag list, templates and UDT decoding; and an emulation of a
  Logix tag database on the server, for tests and simulators
- **Electronic Data Sheets**: parser, validation, writer, an EDS builder,
  and a generator of Go constants, assembly structs and scanner
  configurations from an EDS file
- **EtherNet/IP over TLS** (the transport of CIP Security, port 2221) for
  explicit messaging, with `crypto/tls`
- What production use needs: `context.Context` on every call, typed and
  sentinel errors with the peer's general and extended status, structured
  logging, metrics hooks, bounded allocations on every decoder, connection
  and session limits
- **Verified against twelve independent implementations**: OpENer,
  EIPScanner, pycomm3, cpppo, libplctag, gologix, pylogix, etherip, eip-rs,
  node-ethernet-ip, EEIP.NET and loki-os's go-ethernet-ip, in both roles
  where they have them, in the
  containers of [otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop)
  (see [INTEROPERABILITY.md](INTEROPERABILITY.md))

**Docs:** [API.md](API.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [INTEROPERABILITY.md](INTEROPERABILITY.md) (protocol coverage and interop results) · [ERRORS.md](ERRORS.md) · [OBSERVABILITY.md](OBSERVABILITY.md) · [SECURITY.md](SECURITY.md) · [TESTING.md](TESTING.md) · [CATALOG.md](CATALOG.md) (CIP codes and their sources) · [RELEASE.md](RELEASE.md) · guides in [docs/](docs/)

## Table of contents

- [go-ethernetip vs the reference stacks](#go-ethernetip-vs-the-reference-stacks)
- [Install](#install)
- [Project structure](#project-structure)
- [Client quickstart](#client-quickstart)
- [I/O quickstart](#io-quickstart)
- [Adapter quickstart](#adapter-quickstart)
- [Logix tags](#logix-tags)
- [EDS files](#eds-files)
- [Error semantics](#error-semantics)
- [Examples](#examples)
- [Development](#development)
- [Interop tests](#interop-tests)
- [Standards, licensing and conformance](#standards-licensing-and-conformance)
- [Limitations](#limitations)
- [License](#license)

## go-ethernetip vs the reference stacks

go-ethernetip is tested against twelve independent implementations (see
[Interop tests](#interop-tests)). Each suits different needs; this table
shows where they differ, from their public sources, the
[ethernetip-interop capability records](https://github.com/otfabric/ethernetip-interop/blob/main/docs/CAPABILITIES.md)
and the interop runs, so you can pick the right one for your project, and
see where more interop or more features would help.

| Capability | go-ethernetip | OpENer | EIPScanner | pycomm3 | cpppo | libplctag | gologix | pylogix | etherip | eip-rs | node-ethernet-ip | EEIP.NET | go-ethernet-ip (loki-os) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Project** | | | | | | | | | | | | | |
| Language | Go | C | C++ | Python | Python | C | Go | Python | Java | Rust | TypeScript | C# | Go |
| Licence | MIT | adapted BSD | MIT | MIT | GPL-3.0 | MPL-2.0 or LGPL-2.0+ | MIT | Apache-2.0 | EPL-1.0 | MIT | MIT | MIT | WTFPL |
| Version compared | this module | master 0e1ab7e | 1.3.0+33 | 1.2.16 | 5.2.5 | 2.7.2 | 0.44.0-beta | 1.1.6 | main ce0688a | main 16e2236 | 2.0.0 | master 58b91a0 | master 535f797 |
| Originator (scanner, client) | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Target (adapter, server) | ✅ | ✅ | — | — | Logix simulator | ab_server simulator | Logix tags, Class 1 I/O | — | — | — | — | — | — |
| Dependencies | none (standard library) | none | none | none | greenery | none | crc16 | none | none (JRE) | tokio and others | none (Node.js) | none (.NET) | none |
| **Discovery and encapsulation** | | | | | | | | | | | | | |
| ListIdentity over TCP | C, T | ✅ | — | ✅ | C, T | — | C, T | — | ✅ | ✅ | ✅ | — | ✅ |
| ListIdentity over UDP, discovery | C, T; broadcast | ✅ | ✅ | ✅ | C, T | — | — | broadcast only | ✅ | ✅ | ✅ | unicast ¹ | — |
| ListServices | C, T | ✅ | — | — | C, T | — | C ² | — | ✅ | TCP | — | — | ✅ |
| ListInterfaces | C, T | ✅ | — | — | T | — | — | — | — | — | — | — | not tested |
| EtherNet/IP over TLS (port 2221) | explicit messaging | — | — | — | — | — | — | — | — | — | — | — | — |
| CIP Security beyond TLS (DTLS, security objects) | — (open issue) | — | — | — | — | — | — | — | — | — | — | — | — |
| **Explicit messaging** | | | | | | | | | | | | | |
| Get_Attribute_Single | C, T | ✅ | ✅ | ✅ | C, T | C ³ | C ² | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Set_Attribute_Single | C, T | ✅ | ✅ | ✅ | C, T | C ³ | C ² | ✅ | — | ✅ | ✅ | ✅ | ✅ |
| Get_Attributes_All | C, T | ✅ | ✅ | ✅ | C, T | C ³ | C; T (Identity) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Get_Attribute_List | C, T | ✅ | — | — | T | — | — | — | — | — | — | — | — |
| Multiple Service Packet | C, T | — | C (adapter-built) | Logix reads | C, T | C: tag reads; T | C; T: Class 3 tag services | tag reads | tag reads | ✅ | ✅ | — | ✅ |
| Unconnected_Send routing | C, T | — | — | ✅ | C, T | T ³ | T | ✅ | ✅ | ✅ | — | — | ✅ |
| Class 3 connected explicit messaging | C, T | ✅ | — | ✅ | T | C, T | C (always), T | Logix only | — | ✅ | ✅ | — | ✅ |
| Large_Forward_Open | C, T | ✅ | ✅ | ✅ | T | C, T | C, T | ✅ | — | — | ✅ | ✅ | not used |
| Identity and Assembly objects (target) | ✅ | ✅ | n/a | n/a | Identity; assemblies as attributes | — | Identity only | n/a | n/a | n/a | n/a | n/a | n/a |
| TCP/IP Interface, Ethernet Link objects (target) | ✅ | ✅ | n/a | n/a | — | — | — | n/a | n/a | n/a | n/a | n/a | n/a |
| **Implicit (Class 0/1) I/O** | | | | | | | | | | | | | |
| Class 1 exclusive owner | C, T | T | C | — | — | — | T | — | — | — | — | C | — |
| Class 0 | C, T | not tested | not tested | — | — | — | not tested | — | — | — | — | not tested | — |
| Input-only (heartbeat) | C, T | T | C | — | — | — | T | — | — | — | — | C | — |
| Listen-only | C, T | T ⁴ | — | — | — | — | — | — | — | — | — | C | — |
| T->O multicast | C, T | T | — | — | — | — | — | — | — | — | — | C | — |
| Configuration data in the Forward_Open | C, T | T | C | — | — | — | T: ignored | — | — | — | — | — | — |
| Large_Forward_Open for I/O | C, T | T | C | — | — | — | T: no data | — | — | — | — | C | — |
| **Rockwell Logix (vendor specific)** | | | | | | | | | | | | | |
| Read Tag, Write Tag | client and emulation | — | — | ✅ | C, T | C, T | C, T | ✅ | ✅ | ✅ | ✅ | — | reads; scalar writes ⁸ |
| Read Tag Fragmented | client and emulation | — | — | ✅ | C, T | C, T | partial | ✅ | — | ✅ | — | — | — |
| Write Tag Fragmented | client and emulation | — | — | ✅ | T | T; C above 4000 octets | — | above 3.9 kB | — | ✅ | — | — | — |
| Several tags in one Multiple Service Packet | client and emulation | — | — | ✅ | T | C, T | C, T | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| LINT, LREAL | client and emulation | — | — | ✅ | T | C, T | C, T | ✅ | — | ✅ | ✅ | — | ✅ |
| Tag list (0x55) | client and emulation | — | — | ✅ | — | C | C ⁵ | ✅ | — | ✅ | ✅ | — | ✅ |
| STRING | client and emulation | — | — | ✅ | not tested | C, T | C | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| Structures (templates): read | client and emulation | — | — | ✅ | — | raw octets | raw octets | raw octets | — | ✅ | ✅ | — | raw octets |
| Structures: write | client and emulation | — | — | ✅ | — | members only | members only | members only | — | ✅ | members only ⁶ | — | — |
| Bit writes on integers (Read-Modify-Write) | client and emulation | — | — | ✅ | — | C | — | ✅ | — | ✅ | ✅ | — | — |
| BOOL array elements | client and emulation | — | — | ✅ | not tested | own form ⁷ | — | ✅ | — | ✅ | — | — | — |
| **Tooling and API** | | | | | | | | | | | | | |
| EDS files: parse, validate, write, generate Go code | ✅ | — | — | — | — | — | — | — | — | — | — | — | — |
| Cancellation and deadlines per call | `context.Context` | — | — | socket timeout | — | timeout per call | not tested | socket timeout | timeouts | async (tokio) | promises | — | — |
| Structured logging, metrics | `Logger` (slog), `Metrics` | own logger | own logger | `logging` | `logging` | debug levels | `log/slog` | `print` | Java logging | not tested | not tested | console | not tested |
| **Testing** | | | | | | | | | | | | | |
| Tested against go-ethernetip ([matrix](INTEROPERABILITY.md#interop-matrix)) | — | 17 pass | 11 pass | 18 pass | 17 pass | 17 pass | 19 pass | 14 pass | 9 pass | 21 pass | 19 pass | 11 pass | 11 pass |
| Tested against other stacks in CI | ✅ all twelve, both directions | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| ODVA conformance tested | no, and no claim | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested | not tested |

✅ = available in the roles the stack has · C = as originator (client,
scanner) · T = as target (adapter, server) · — = not available · n/a = the
stack has no target role · not tested = neither documented nor exercised by
the interop suite. For the versions go-ethernetip is tested against, as of
October 2026.

¹ EEIP.NET's own ListIdentity broadcasts without SO_BROADCAST and fails on
Linux; the adapter sends one unicast datagram built and parsed by EEIP.NET.
² gologix's target answers ListServices with the wrong command and
Get_Attribute_Single with malformed replies; Set_Attribute_Single only on
its own class 0xC8.
³ libplctag 2.7.2 builds unconnected requests without their route path, so
its attribute requests work over Class 3 only; ab_server has no attributes.
⁴ OpENer stops the shared production and drops the owner when a
listen-only connection closes first.
⁵ gologix's target answers the tag list without the requested attributes.
⁶ node-ethernet-ip writes a whole structure with the template instance ID
instead of the structure handle (refused 0x2107).
⁷ libplctag writes a BOOL array element as `Bits[1].5` (DWORD, bit), not
`Bits[37]`.
⁸ go-ethernet-ip writes a tag only whole (all elements, by instance), so
scalar tags only; it does not check the reply of a write.

The interop counts are the cases each stack passes against go-ethernetip,
in both directions where it has a target, of those it declares; every
documented limit is listed with its reason in the matrix. If you spot an
inaccuracy, please [open an issue](https://github.com/otfabric/go-ethernetip/issues)
and we will correct it.

## Install

```sh
go get github.com/otfabric/go-ethernetip
```

Requires Go 1.23 or later.

## Project structure

| Package | What it is |
|---------|-----------|
| [`ethernetip`](https://pkg.go.dev/github.com/otfabric/go-ethernetip) | Shared types: sentinel and typed errors, `Logger`, `Metrics`, `State` |
| [`client`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/client) | Originator of explicit messages; discovery |
| [`scanner`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/scanner) | Originator of Class 0/1 I/O connections |
| [`server`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/server) | Target (adapter): objects, sessions, connections |
| [`logix`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/logix) | Rockwell Logix tag services, client and emulation (vendor specific) |
| [`eds`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/eds) | Electronic Data Sheets: parse, validate, format, build, generate Go |
| [`cip`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/cip) | CIP codec: data types, EPATHs, messages, Connection Manager services, generated catalog of codes |
| [`encap`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/encap) | Encapsulation codec: header, commands, common packet format |
| [`implicit`](https://pkg.go.dev/github.com/otfabric/go-ethernetip/implicit) | I/O datagram codec, UDP endpoint, connection runtime |

`cip`, `encap` and the codec half of `implicit` are pure: useful on their
own to analysers and test tools. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Client quickstart

```go
ctx := context.Background()
c, err := client.Dial(ctx, "192.168.1.10") // port 44818
if err != nil {
    log.Fatal(err)
}
defer c.Close()

id, err := c.Identity(ctx) // Get_Attributes_All of the Identity object
fmt.Println(id)            // OpENer PC (vendor 1, Communications Adapter, product 65001, rev 2.3, ...)

data, err := c.GetAttributeSingle(ctx, cip.ClassAssembly, 100, 3)

// Several requests in one Multiple Service Packet.
resps, err := c.MultipleService(ctx, []cip.Request{
    {Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 1)},
    {Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.ClassIdentity, 1, 7)},
})

// Connected explicit messaging (Class 3).
cn, err := c.OpenConnection(ctx, client.ConnectionOptions{})
name, err := cn.GetAttributeSingle(ctx, cip.ClassIdentity, 1, 7)
_ = cn.Close(ctx)
```

A controller behind a communication module is reached with a route:
`client.WithRoute(route)` where `route, _ := cip.ParseRoute("1/0")` (port
1, the backplane, slot 0) sends every request through the module's
Unconnected_Send.

`client.Discover(ctx, client.DiscoverOptions{Address: "192.168.1.255"})`
sends one ListIdentity datagram and lists the devices that answer.

## I/O quickstart

```go
s, err := scanner.New(c) // UDP port 2222
io, err := s.Open(ctx, scanner.IOConfig{
    ConfigInstance: 151, OutputInstance: 150, InputInstance: 100,
    OutputSize: 32, InputSize: 32, RPI: 10 * time.Millisecond,
    Reconnect: &scanner.Reconnect{}, // reopen after a timeout
})
_ = io.SetOutput(out)       // sent from the next interval on
in, run, at := io.Input()   // the last input and when it arrived
<-io.Done()                 // only without Reconnect, after a timeout
_ = io.Close(ctx)           // Forward_Close
```

## Adapter quickstart

```go
srv, err := server.New(server.WithIdentity(cip.Identity{
    VendorID: 0xFFFF, DeviceType: cip.DeviceTypeCommunicationsAdapter,
    ProductCode: 1, Revision: cip.Revision{Major: 1, Minor: 0},
    SerialNumber: 42, ProductName: "My adapter",
}))
in, _ := srv.AddAssembly(100, server.AssemblyInput, 32)
out, _ := srv.AddAssembly(150, server.AssemblyOutput, 32)
_, _ = srv.AddAssembly(151, server.AssemblyConfig, 10)
out.OnWrite(func(data []byte, run bool) { /* drive the outputs */ })
_ = in.SetData(inputs) // produced to every connection from the next RPI
log.Fatal(srv.ListenAndServe(":44818")) // TCP+UDP 44818, I/O UDP 2222
```

Objects of your own implement `server.Object`, or are built from
`server.NewObject(class, revision)` with attributes and services.

## Logix tags

The `logix` package speaks the Rockwell Automation extensions, which only
Logix controllers (and compatible devices) implement:

```go
route, _ := cip.ParseRoute("1/0")
c, _ := client.Dial(ctx, "192.168.1.10", client.WithRoute(route))
lc := logix.NewClient(c)
v, err := lc.Read(ctx, "Program:Main.Speeds[3]", 1)
f, _ := v.Float(0)
dv, _ := logix.Ints(cip.TypeDINT, 42)
err = lc.Write(ctx, "Counter", dv)
tags, err := lc.ListTags(ctx, "")
```

`logix.NewTagServer()` attached to a `server.Server` emulates a controller's
tags (symbolic and instance addressing, fragmentation, templates), enough
for pycomm3 and cpppo to work against it. See [docs/LOGIX.md](docs/LOGIX.md).

## EDS files

```go
f, err := eds.Parse(file)
for _, issue := range eds.Validate(f) { fmt.Println(issue) }
src, err := eds.GenerateGo(f, eds.GenerateOptions{Package: "drive"})
```

The generated package has the identity, a descriptor and range check per
parameter, enumerations, assembly instances with Encode/Decode structs, and
a `scanner.IOConfig` per I/O connection. See [docs/EDS.md](docs/EDS.md).

## Error semantics

Errors are sentinels tested with `errors.Is` (`ethernetip.ErrTimeout`,
`ErrConnectionLost`, `ErrConnectFailed`, `ErrProtocol`, `ErrSession`,
`ErrUnsupported`, ...) and typed errors for the peer's answers, matched
with `errors.As`: `*ethernetip.CIPError` (general status, extended status,
service and path) and `*ethernetip.EncapError` (encapsulation status). A
response with an error status is returned together with its error. See
[ERRORS.md](ERRORS.md).

## Examples

Runnable programs under [examples/](examples/): `quickstart`, `io`,
`logix` and `eds` run both sides in one process; `adapter`, `scanner` and
`discover` work with real devices.

```sh
go run ./examples/quickstart
```

## Development

```sh
make check      # generated files, format, lint, vet, govulncheck, race tests, coverage gate, examples
make test       # tests with the race detector
make coverage-check   # combined coverage of the library packages, 90% minimum
make fuzz       # every fuzz target (FUZZTIME=30s each)
make chaos      # chaos suites, 10 times (ETHERNETIP_CHAOS_SEED repeats a run)
make stress     # parallel and stress suites, 10 times, race detector
make bench      # codec and end-to-end benchmarks
make generate   # regenerate the CIP catalog and the sample EDS package
make interop    # the interop suite (Docker)
```

Tests need nothing but Go: clients, scanners and servers run against each
other over loopback. See [TESTING.md](TESTING.md).

## Interop tests

`make interop` runs the library's originator against the reference targets
and the reference originators against the library's target, in the
containers of [otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop).
The library runs in a container on the same Docker network as the
references (I/O connections need both ends to reach each other without
NAT).

| Reference | Version | Licence | Roles tested |
|-----------|---------|---------|--------------|
| [OpENer](https://github.com/EIPStackGroup/OpENer) | master 0e1ab7e (v2.3+591) | adapted BSD | target (adapter) |
| [EIPScanner](https://github.com/nimbuscontrols/EIPScanner) | 1.3.0+33 (12c89a5) | MIT | originator (scanner) |
| [pycomm3](https://github.com/ottowayi/pycomm3) | 1.2.16 | MIT | originator (generic CIP and Logix) |
| [cpppo](https://github.com/pjkundert/cpppo) | 5.2.5 | GPL-3.0 | target (Logix simulator) and originator |
| [libplctag](https://github.com/libplctag/libplctag) | 2.7.2 | MPL-2.0 or LGPL-2.0+ | originator (Logix and generic CIP) and target (ab_server simulator) |
| [gologix](https://github.com/danomagnum/gologix) | 0.44.0-beta | MIT | originator and target (Logix tags, Class 1 I/O) |
| [pylogix](https://github.com/dmroeder/pylogix) | 1.1.6 | Apache-2.0 | originator (Logix) |
| [etherip](https://github.com/ornl-epics/etherip) | main ce0688a | EPL-1.0 | originator (Logix, generic) |
| [eip-rs (rseip)](https://github.com/Joylei/eip-rs) | main 16e2236 | MIT | originator (generic CIP and Logix) |
| [node-ethernet-ip](https://github.com/cmseaton42/node-ethernet-ip) | 2.0.0 | MIT | originator (Logix, generic) |
| [EEIP.NET](https://github.com/rossmann-engineering/EEIP.NET) | master 58b91a0 | MIT | originator (scanner: explicit, Class 1 I/O) |
| [go-ethernet-ip (loki-os)](https://github.com/loki-os/go-ethernet-ip) | master 535f797 | WTFPL | originator (generic CIP and Logix) |

The [coverage matrix](INTEROPERABILITY.md#interop-matrix) lists each
feature per reference and direction, with the features a reference does
not have marked N/A. The reference code runs in its own container only:
nothing of it is linked into this module.

## Standards, licensing and conformance

EtherNet/IP and CIP are specified by ODVA (The CIP Networks Library,
Volumes 1, 2 and 8), sold by subscription. This project does not have them:
it is built from publicly available information and the behaviour of the
independent implementations above, and every code it names is listed with
its public source in [CATALOG.md](CATALOG.md). EtherNet/IP and CIP are
trademarks of ODVA. Products that implement EtherNet/IP need an ODVA vendor
ID and the ODVA Terms of Usage; ODVA conformance requires its conformance
test. **This library is not ODVA conformance tested and makes no conformance
claim.** See [docs/STANDARDS.md](docs/STANDARDS.md).

## Limitations

- **CIP Security**: EtherNet/IP over TLS for explicit messaging only; DTLS
  for I/O and the CIP Security, EtherNet/IP Security and Certificate
  Management objects are not implemented (no DTLS in the standard library,
  no reference peer in the interop suite).
- **No routing beyond the device**: the server answers routes to its own
  slot; it does not bridge to other ports.
- **Class 2 connections, safety (CIP Safety), motion (CIP Motion), DLR,
  QoS and the File object** are not implemented.
- **Multicast** I/O, with a listen-only connection next to its owner, is
  verified against OpENer and EEIP.NET and between the library's own ends.
- **The Logix emulation** is a test tool: no programs, no tasks, no
  online edits, no alarms.
- See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the complete list.

## License

[MIT](LICENSE). The reference implementations the interop tests run are
under their own licences and are not part of this module; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
