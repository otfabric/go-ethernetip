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
