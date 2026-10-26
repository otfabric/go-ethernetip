# Interoperability and protocol coverage

What go-ethernetip implements, how each part is tested, and the results
against the independent implementations of
[otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop).

Status legend:

- **Implemented** — in the library, with unit or end-to-end tests between
  the library's own ends.
- **Interop verified** — also passed against at least one independent
  implementation, in the [interop matrix](#interop-matrix).
- **Partial** — implemented with the restriction named.
- **Not implemented** — absent; the reason is given.

The ODVA specifications are not available to this project (see
[docs/STANDARDS.md](docs/STANDARDS.md)): behaviour follows public sources
and the reference implementations, and the codes are listed with their
sources in [CATALOG.md](CATALOG.md).

## Protocol coverage

### Encapsulation (TCP and UDP 44818)

| Feature | Originator (client) | Target (server) | Status |
|---|:-:|:-:|---|
| Header, length and boundary validation, `ReadPacket` with a size limit | ✅ | ✅ | Interop verified |
| RegisterSession / UnRegisterSession (protocol version 1, options 0) | ✅ | ✅ | Interop verified |
| NOP | — | ✅ (no answer) | Implemented |
| ListIdentity over TCP | ✅ | ✅ | Interop verified (OpENer, cpppo, pycomm3) |
| ListIdentity over UDP, unicast and broadcast; reply delay of the sender context | ✅ (`Discover`) | ✅ (`WithDiscoveryDelay`) | Interop verified (OpENer, cpppo, EIPScanner, pycomm3) |
| ListServices | ✅ | ✅ | Interop verified (OpENer) |
| ListInterfaces | ✅ | ✅ (no interfaces) | Implemented |
| SendRRData (unconnected) | ✅ | ✅ | Interop verified |
| SendUnitData (connected) | ✅ | ✅ | Interop verified (OpENer, cpppo, pycomm3) |
| Sender context correlation, several requests in flight | ✅ | ✅ (in order per session) | Implemented |
| Encapsulation status codes | ✅ (`*EncapError`) | ✅ | Implemented |
| Common packet format: null, connected and sequenced address, connected and unconnected data, identity, services, Sockaddr Info O->T and T->O | ✅ | ✅ | Interop verified |
| Encapsulation inactivity timeout (TCP/IP attribute 13) | — | ✅ | Implemented |
| EtherNet/IP over TLS (CIP Security transport, TCP 2221) | ✅ | ✅ | Implemented (no interop peer) |
| IndicateStatus, Cancel | — | answered "invalid command" | Not implemented: legacy commands |

### CIP

| Feature | Status |
|---|---|
| Elementary data types (BOOL ... STRINGI): codes, sizes, value encoding | Implemented |
| STRING, SHORT_STRING, STRING2 (UCS-2) | Implemented |
| EPATH: logical segments (class, instance, member, connection point, attribute, service; 8/16/32-bit, padded and packed), port segments (extended port and link address), electronic key (format 4, compatibility), ANSI extended symbol, simple data segment, network segments | Interop verified (16-bit segments from EIPScanner, 8-bit from the others, symbols from pycomm3 and cpppo, keys against OpENer's) |
| Message Router requests and responses, general and additional status | Interop verified |
| Multiple Service Packet | Interop verified (EIPScanner, cpppo, pycomm3 multi-tag); OpENer has none |
| Get_Attribute_Single, Set_Attribute_Single, Get_Attributes_All | Interop verified |
| Set_Attributes_All | Implemented (client); server objects define it where they have one |
| Get_Attribute_List | Implemented (client, `server.StandardObject`) |
| Reset (Identity, types 0 and 1) | Implemented |
| Unconnected_Send (routing) | Interop verified (pycomm3 `get_module_info`, cpppo routed tags; the library against cpppo) |
| Forward_Open, Large_Forward_Open, Forward_Close | Interop verified (OpENer, EIPScanner, pycomm3, cpppo) |
| Connection Manager extended status codes | Implemented; refusals interop verified against OpENer and EIPScanner |
| Fragmentation of Logix reads and writes | Interop verified (pycomm3, cpppo) |
| Get_Connection_Data, Search_Connection_Data, Get_Connection_Owner | Not implemented (diagnostic services) |

### Objects (server)

| Object | Class | Instance attributes | Services | Status |
|---|---|---|---|---|
| Identity | 0x01 | 1-7 (Get_Attributes_All), 8 | GAS, GAA, GAL, Reset | Interop verified |
| Message Router | 0x02 | 1 (object list), 2, 3 | GAS, GAA, Multiple Service Packet | Interop verified |
| Assembly | 0x04 | 3 (data), 4 (size) | GAS, SAS (output and configuration, unless owned), GAA | Interop verified |
| Connection Manager | 0x06 | 1-8 (counters) | Forward_Open, Large_Forward_Open, Forward_Close, Unconnected_Send, GAS, GAA | Interop verified |
| Port | 0xF4 | 1-4, 7 | GAS, GAA | Implemented |
| TCP/IP Interface | 0xF5 | 1-6, 8, 9, 13 (8 and 13 settable) | GAS, GAA, SAS | Implemented |
| Ethernet Link | 0xF6 | 1-3, 7-10 | GAS, GAA | Implemented |
| User objects | any | any | `server.Object` / `server.NewObject` | Implemented |
| Parameter, File, QoS, DLR, CIP Security objects | — | — | — | Not implemented |

Every class has the class attributes 1 (revision), 2 (max instance), 3
(number of instances), 6 and 7 (max attribute IDs).

### Connections

| Feature | Scanner (originator) | Server (target) | Status |
|---|:-:|:-:|---|
| Class 3 connected explicit messaging, duplicate detection by sequence count | ✅ | ✅ | Interop verified (OpENer, cpppo as targets; pycomm3 as originator) |
| Class 1 cyclic I/O, point-to-point | ✅ | ✅ | Interop verified (OpENer; EIPScanner) |
| Class 0 I/O | ✅ | ✅ | Implemented |
| Real-time formats: 32-bit run/idle header, modeless, heartbeat, zero length | ✅ | ✅ | Interop verified (header O->T, modeless T->O, heartbeats) |
| Run/idle | ✅ | ✅ | Implemented (end to end) |
| Sequence handling (encapsulation sequence, Class 1 sequence count, serial arithmetic) | ✅ | ✅ | Interop verified; chaos tested |
| Connection timeout (RPI × 4 << multiplier) and recovery | ✅ (`Reconnect`) | ✅ | Implemented (e2e: both ends) |
| Exclusive owner, input only, listen only | ✅ | ✅ | Exclusive owner and input only interop verified; listen only between the library's ends |
| T->O multicast, shared production, CIP default multicast addresses | ✅ | ✅ | Interop verified (OpENer as target) |
| Change-of-state trigger | — | ✅ | Implemented |
| Application trigger | — | Class 3 only | Partial |
| Configuration data segment | ✅ | ✅ | Implemented (e2e; the interop operations send no configuration data) |
| Electronic key check | ✅ | ✅ | Implemented |
| Sockaddr Info items (non-default I/O ports) | ✅ | ✅ | Implemented |
| Class 2, redundant owner, CIP Safety, scheduled priority enforcement | — | — | Not implemented |

### Logix extensions (vendor specific, package `logix`)

| Feature | Client | Emulation | Status |
|---|:-:|:-:|---|
| Read Tag, Write Tag (symbolic, program scope, arrays up to 3 dimensions, structure members, BOOL members) | ✅ | ✅ | Interop verified (pycomm3 and cpppo against the emulation; the client against cpppo) |
| Read/Write Tag Fragmented | ✅ | ✅ | Interop verified |
| Read-Modify-Write (bits) | ✅ | ✅ | Implemented (cpppo has none; pycomm3 not exercised) |
| Multiple tags in one Multiple Service Packet | ✅ | ✅ | Interop verified (pycomm3) |
| Instance addressing (Symbol object) | — | ✅ | Implemented |
| Tag list (Get Instance Attribute List, 0x55) | ✅ | ✅ | Interop verified (pycomm3 opens a LogixDriver on it) |
| Templates (attributes, Read Template) and UDT decoding | ✅ | ✅ | Implemented (e2e; the interop fixture has no structures) |
| Program name (0x64) | ✅ | ✅ | Interop verified (pycomm3) |

### Electronic Data Sheets

Parser (sections, entries, strings, datasets, comments), typed views of
[File], [Device], [Params] with enumerations, [Assembly], [Connection
Manager]; validation; canonical formatting; building an EDS from a
description; generation of Go code. Fuzzed. Not interop tested: there is
no machine-readable conformance corpus; the grammar follows eds_pie (MIT)
and published EDS files.

## Interop matrix

<!-- interop-matrix:begin -->
<!-- Generated by internal/cmd/genmatrix from interop/results/matrix.json. DO NOT EDIT. -->

Run of 2026-10-26T00:03:28Z against otfabric/ethernetip-interop v0.1.0.

### go-ethernetip as originator (client, scanner) against the reference targets

| Feature | OpENer | EIPScanner | pycomm3 | cpppo |
|---|:-:|:-:|:-:|:-:|
| Class 1 I/O, T->O multicast | ✅ |  |  |  |
| Class 1 I/O, exclusive owner, point-to-point | ✅ |  |  | N/A |
| Class 1 I/O, input only (heartbeat O->T) | ✅ |  |  |  |
| Class 3 connected explicit messaging | ✅ |  |  | ✅ |
| Error responses (unknown class, attribute) | ✅ |  |  |  |
| Forward_Open refusal (connection size) | ✅ |  |  |  |
| Get_Attribute_Single | ✅ |  |  | ✅ |
| Get_Attributes_All (Identity) | ✅ |  |  |  |
| Large_Forward_Open | ✅ |  |  |  |
| ListIdentity (TCP) | ✅ |  |  | ✅ |
| ListIdentity (UDP) | ✅ |  |  | ✅ |
| ListServices | ✅ |  |  |  |
| Logix Read Tag (atomic types) |  |  |  | ✅ |
| Logix Read Tag Fragmented (1200 octets) |  |  |  | ✅ |
| Logix Write Tag |  |  |  | ✅ |
| Logix tag list (0x55) and LogixDriver open |  |  |  | N/A |
| Logix tag services | N/A |  |  |  |
| Multiple Service Packet | N/A |  |  | ✅ |
| Set_Attribute_Single (assembly) | ✅ |  |  |  |
| Unconnected_Send routing | N/A |  |  |  |

### Reference originators against go-ethernetip's target (server, Logix emulation)

| Feature | OpENer | EIPScanner | pycomm3 | cpppo |
|---|:-:|:-:|:-:|:-:|
| Class 1 I/O, T->O multicast |  | N/A |  |  |
| Class 1 I/O, exclusive owner, point-to-point |  | ✅ | N/A | N/A |
| Class 1 I/O, input only (heartbeat O->T) |  | ✅ |  |  |
| Class 3 connected explicit messaging |  | N/A |  |  |
| Class 3 connected explicit messaging (Large_Forward_Open) |  |  | ✅ |  |
| Error responses (unknown class, attribute) |  |  | ✅ |  |
| Forward_Open refusal (connection size) |  | ✅ |  |  |
| Get_Attribute_Single |  |  | ✅ | ✅ |
| Get_Attribute_Single (16-bit logical segments) |  | ✅ |  |  |
| Get_Attributes_All (Identity) |  | ✅ |  |  |
| Large_Forward_Open |  | ✅ |  |  |
| ListIdentity (TCP) |  |  | ✅ | ✅ |
| ListIdentity (UDP) |  | ✅ | ✅ | ✅ |
| Logix Read Tag (atomic types) |  |  | ✅ | ✅ |
| Logix Read Tag Fragmented (1200 octets) |  |  | ✅ | ✅ |
| Logix Write Tag |  |  | ✅ | ✅ |
| Logix tag list (0x55) and LogixDriver open |  |  | ✅ |  |
| Logix tag services |  | N/A |  |  |
| Multiple Service Packet |  | ✅ |  | ✅ |
| Set_Attribute_Single (assembly) |  | ✅ | ✅ | ✅ |
| Unconnected_Send routing (backplane slot 0) |  |  | ✅ |  |

49 passed, 0 failed, 10 not applicable. N/A: the reference has the
role but not the feature. Empty: not exercised with that reference in
that direction (it lacks the role, or no case covers it yet).

Notes:

- **EIPScanner, Class 1 I/O, T->O multicast** (reference originator): EIPScanner does not join multicast groups
- **EIPScanner, Class 3 connected explicit messaging** (reference originator): EIPScanner has no SendUnitData sender
- **EIPScanner, Forward_Open refusal (connection size)** (reference originator): EIPScanner logs the refusal; the adapter reports refused
- **EIPScanner, Get_Attribute_Single (16-bit logical segments)** (reference originator): EIPScanner packs 16-bit class/instance/attribute segments
- **EIPScanner, Logix tag services** (reference originator): EIPScanner has no symbolic segments
- **EIPScanner, Multiple Service Packet** (reference originator): built by the adapter with EIPScanner's MessageRouterRequest
- **OpENer, Class 1 I/O, exclusive owner, point-to-point** (go-ethernetip originator): output 150 echoed to input 100 by the sample application
- **OpENer, Error responses (unknown class, attribute)** (go-ethernetip originator): OpENer answers 0x05 for an unknown class or instance, 0x14 for an attribute
- **OpENer, Logix tag services** (go-ethernetip originator): not a Logix controller
- **OpENer, Multiple Service Packet** (go-ethernetip originator): OpENer answers 0x08: not implemented
- **OpENer, Unconnected_Send routing** (go-ethernetip originator): OpENer answers 0x08: not implemented
- **cpppo, Class 1 I/O, exclusive owner, point-to-point** (go-ethernetip originator): cpppo has no implicit messaging
- **cpppo, Class 1 I/O, exclusive owner, point-to-point** (reference originator): cpppo has no implicit messaging
- **cpppo, Class 3 connected explicit messaging** (go-ethernetip originator): connected
- **cpppo, Logix Read Tag (atomic types)** (go-ethernetip originator): routed
- **cpppo, Logix Read Tag (atomic types)** (reference originator): through Unconnected_Send to slot 0
- **cpppo, Logix Read Tag Fragmented (1200 octets)** (go-ethernetip originator): connected
- **cpppo, Logix Read Tag Fragmented (1200 octets)** (go-ethernetip originator): routed
- **cpppo, Logix Read Tag Fragmented (1200 octets)** (reference originator): Read Tag Fragmented with byte offsets, continued by the adapter while the target answers 0x06
- **cpppo, Logix tag list (0x55) and LogixDriver open** (go-ethernetip originator): cpppo has no Symbol object tag list
- **pycomm3, Class 1 I/O, exclusive owner, point-to-point** (reference originator): pycomm3 has no implicit messaging
- **pycomm3, ListIdentity (UDP)** (reference originator): pycomm3 discover() to the adapter's address
- **pycomm3, Logix Write Tag** (reference originator): pycomm3 1.2.16 repeats the request in the message; the emulation ignores the extra octets, as Logix does
- **pycomm3, Logix tag list (0x55) and LogixDriver open** (reference originator): pycomm3 uploads the tag list on open: Unconnected_Send, Large_Forward_Open, program name, 0x55 with continuation
- **pycomm3, Unconnected_Send routing (backplane slot 0)** (reference originator): pycomm3 get_module_info(0)

Images:

- OpENer: `{"adapter":"opener","adapterVersion":"v0.1.0","upstream":"OpENer","upstreamVersion":"2.3-588","upstreamRevision":"d8820ef41ce30dda06d213438ba81c81de33ffe2","contract":"1.0"}`
- EIPScanner: `{"adapter":"eipscanner","adapterVersion":"v0.1.0","upstream":"EIPScanner","upstreamVersion":"1.3.0-33","upstreamRevision":"12c89a57ec2e7449efb1348be52af10be9ef9701","contract":"1.0"}`
- pycomm3: `{"adapter": "pycomm3", "adapterVersion": "v0.1.0", "contract": "1.0", "upstream": "pycomm3", "upstreamRevision": "36aeb19b5cb47495df9fd1caa38ce9d2f6d12ea3", "upstreamVersion": "1.2.16"}`
- cpppo: `{"adapter": "cpppo", "adapterVersion": "v0.1.0", "contract": "1.0", "upstream": "cpppo", "upstreamRevision": "f7c224bbb2389bd26d0088eeb1a93db3a5c4858f", "upstreamVersion": "5.2.5"}`
<!-- interop-matrix:end -->

## Known deviations of the references

Recorded in [docs/research/STACKS.md](docs/research/STACKS.md), with how
each is handled:

- OpENer: no Multiple Service Packet, no Unconnected_Send; a first Class 3
  request with sequence 0 is taken for a repeat (the client starts at 1);
  the first datagram of an I/O connection must not have sequence count 0
  (the producer starts at 1).
- EIPScanner: no Class 3, no multicast; sends O->T from an ephemeral port
  (the server checks only the address); packs 16-bit logical segments.
- pycomm3: sends each Write Tag twice in one message (the emulation ignores
  the extra octets, as Logix does); appends route bytes to unrouted generic
  messages.
- cpppo: closes the session on unknown tags instead of answering an error;
  leaves the continuation of fragmented reads to its caller; reports
  0.0.0.0 in ListIdentity without configuration; answers SendUnitData with
  the O->T connection ID (the client accepts either ID).
