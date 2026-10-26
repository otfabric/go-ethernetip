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
| Class 0 I/O | ✅ | ✅ | Implemented (e2e) |
| Real-time formats: 32-bit run/idle header, modeless, heartbeat, zero length | ✅ | ✅ | Interop verified (header O->T, modeless T->O, heartbeats) |
| Run/idle | ✅ | ✅ | Implemented (end to end) |
| Sequence handling (encapsulation sequence, Class 1 sequence count, serial arithmetic) | ✅ | ✅ | Interop verified; chaos tested |
| Connection timeout (RPI × 4 << multiplier) and recovery | ✅ (`Reconnect`) | ✅ | Implemented (e2e: both ends) |
| Exclusive owner, input only, listen only | ✅ | ✅ | Interop verified (OpENer: listen-only next to a multicast owner on one endpoint; EIPScanner and EEIP.NET: exclusive owner, input only; gologix as target) |
| T->O multicast, shared production, CIP default multicast addresses | ✅ | ✅ | Interop verified (OpENer as target; EEIP.NET as originator) |
| Change-of-state trigger | — | ✅ | Implemented |
| Application trigger | — | Class 3 only | Partial |
| Configuration data segment | ✅ | ✅ | Interop verified (the scanner against OpENer; EIPScanner against the server) |
| Electronic key check | ✅ | ✅ | Implemented |
| Sockaddr Info items (non-default I/O ports) | ✅ | ✅ | Implemented |
| Class 2, redundant owner, CIP Safety, scheduled priority enforcement | — | — | Not implemented |

### Logix extensions (vendor specific, package `logix`)

| Feature | Client | Emulation | Status |
|---|:-:|:-:|---|
| Read Tag, Write Tag (symbolic, program scope, arrays up to 3 dimensions, structure members, BOOL members) | ✅ | ✅ | Interop verified (pycomm3 and cpppo against the emulation; the client against cpppo) |
| Read/Write Tag Fragmented | ✅ | ✅ | Interop verified |
| Read-Modify-Write (bits of integers, BOOL array elements) | ✅ | ✅ | Interop verified (pycomm3, pylogix, eip-rs, node-ethernet-ip and libplctag against the emulation; cpppo and ab_server have none) |
| Multiple tags in one Multiple Service Packet | ✅ | ✅ | Interop verified (pycomm3) |
| Instance addressing (Symbol object) | — | ✅ | Implemented |
| Tag list (Get Instance Attribute List, 0x55) | ✅ | ✅ | Interop verified (pycomm3, pylogix, libplctag, gologix, eip-rs and node-ethernet-ip against the emulation) |
| Templates (attributes, Read Template), structures and STRING | ✅ | ✅ | Interop verified (pycomm3 and eip-rs read and write structures, members and STRINGs of the emulation; node-ethernet-ip reads them; e2e for the client) |
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

Run of 2026-10-26T20:58:21Z against otfabric/ethernetip-interop v0.4.0.

### go-ethernetip as originator (client, scanner) against the reference targets

| Feature | OpENer | EIPScanner | pycomm3 | cpppo | libplctag | gologix | pylogix | etherip | eip-rs | node-ethernet-ip | EEIP.NET | loki-os go-ethernet-ip |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Class 1 I/O, T->O multicast | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Class 1 I/O, configuration data | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Class 1 I/O, exclusive owner, point-to-point | ✅ |  |  | N/A |  |  |  |  |  |  |  |  |
| Class 1 I/O, input only (heartbeat O->T) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Class 1 I/O, listen-only (multicast, next to its owner) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Class 3 connected explicit messaging | ✅ |  |  | ✅ | N/A | N/A |  |  |  |  |  |  |
| Error responses (unknown class, attribute) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Forward_Open refusal (configuration size) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Forward_Open refusal (connection size) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Forward_Open refusal (listen-only without owner) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Get_Attribute_Single | ✅ |  |  | ✅ | N/A | N/A |  |  |  |  |  |  |
| Get_Attributes_All (Identity) | ✅ |  |  |  | N/A | ✅ |  |  |  |  |  |  |
| Large_Forward_Open | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| ListIdentity (TCP) | ✅ |  |  | ✅ | N/A | ✅ |  |  |  |  |  |  |
| ListIdentity (UDP) | ✅ |  |  | ✅ | N/A | N/A |  |  |  |  |  |  |
| ListServices | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Logix Read Tag (atomic types) |  |  |  | ✅ | ✅ | ✅ |  |  |  |  |  |  |
| Logix Read Tag Fragmented (1200 octets) |  |  |  | ✅ | ✅ | N/A |  |  |  |  |  |  |
| Logix Read Tag over Class 3 |  |  |  |  | ✅ | ✅ |  |  |  |  |  |  |
| Logix Write Tag |  |  |  | ✅ | ✅ | ✅ |  |  |  |  |  |  |
| Logix bit write (Read Modify Write Tag) |  |  |  | N/A | N/A | N/A |  |  |  |  |  |  |
| Logix structure read (UDT) |  |  |  | N/A |  |  |  |  |  |  |  |  |
| Logix tag list (0x55) |  |  |  |  | N/A | N/A |  |  |  |  |  |  |
| Logix tag list (0x55) and LogixDriver open |  |  |  | N/A |  |  |  |  |  |  |  |  |
| Logix tag services | N/A |  |  |  |  |  |  |  |  |  |  |  |
| Multiple Service Packet | N/A |  |  | ✅ | N/A | N/A |  |  |  |  |  |  |
| Set_Attribute_Single (assembly) | ✅ |  |  |  |  |  |  |  |  |  |  |  |
| Unconnected_Send routing | N/A |  |  |  |  |  |  |  |  |  |  |  |

### Reference originators against go-ethernetip's target (server, Logix emulation)

| Feature | OpENer | EIPScanner | pycomm3 | cpppo | libplctag | gologix | pylogix | etherip | eip-rs | node-ethernet-ip | EEIP.NET | loki-os go-ethernet-ip |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Class 1 I/O, T->O multicast |  | N/A |  |  | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | N/A |
| Class 1 I/O, configuration data |  | ✅ |  |  | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| Class 1 I/O, exclusive owner, point-to-point |  | ✅ | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | N/A |
| Class 1 I/O, input only (heartbeat O->T) |  | ✅ |  |  | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | N/A |
| Class 1 I/O, listen-only (multicast, next to its owner) |  | N/A |  |  |  |  |  |  |  |  |  |  |
| Class 3 connected explicit messaging |  | N/A |  |  | ✅ | ✅ | N/A | N/A | ✅ | ✅ | N/A | ✅ |
| Class 3 connected explicit messaging (Large_Forward_Open) |  |  | ✅ |  |  |  |  |  |  |  |  |  |
| Error responses (unknown class, attribute) |  |  | ✅ |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Forward_Open refusal (configuration size) |  | ✅ |  |  |  |  |  |  |  |  |  |  |
| Forward_Open refusal (connection size) |  | ✅ |  |  | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | N/A |
| Get_Attribute_Single |  |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Get_Attribute_Single (16-bit logical segments) |  | ✅ |  |  |  |  |  |  |  |  |  |  |
| Get_Attributes_All (Identity) |  | ✅ |  |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Identity object (identity operation) |  |  |  |  | ✅ | N/A | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| Large_Forward_Open |  | ✅ |  |  | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | N/A |
| ListIdentity (TCP) |  |  | ✅ | ✅ | N/A | ✅ | N/A | ✅ | ✅ | ✅ | N/A | ✅ |
| ListIdentity (UDP) |  | ✅ | ✅ | ✅ | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| Logix BOOL array element write |  |  | ✅ |  | N/A | N/A | ✅ | N/A | ✅ | N/A | N/A | N/A |
| Logix Read Tag (64-bit types) |  |  |  |  | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A | ✅ |
| Logix Read Tag (atomic types) |  |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ |
| Logix Read Tag Fragmented (1200 octets) |  |  | ✅ | ✅ | ✅ | N/A | ✅ | N/A | ✅ | N/A | N/A | N/A |
| Logix STRING read and write |  |  | ✅ |  | N/A | N/A | N/A | N/A | ✅ | ✅ | N/A | N/A |
| Logix Write Tag |  |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | N/A |
| Logix Write Tag Fragmented (1200 octets) |  |  | ✅ |  | N/A | N/A | N/A | N/A | ✅ | N/A | N/A | N/A |
| Logix bit write (Read Modify Write Tag) |  |  | ✅ |  | ✅ | N/A | ✅ | N/A | ✅ | ✅ | N/A | N/A |
| Logix multiple tags in one request (read-tags) |  |  |  |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ |
| Logix structure read (UDT) |  |  | ✅ |  | N/A | N/A | N/A | N/A | ✅ | ✅ | N/A | N/A |
| Logix structure write (UDT) |  |  | ✅ |  | N/A | N/A | N/A | N/A | ✅ | ✅ | N/A | N/A |
| Logix tag list (0x55) |  |  |  |  | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | N/A | ✅ |
| Logix tag list (0x55) and LogixDriver open |  |  | ✅ |  |  |  |  |  |  |  |  |  |
| Logix tag list with structure and STRING tags |  |  | ✅ |  | N/A | N/A | N/A | N/A | ✅ | ✅ | N/A | N/A |
| Logix tag services |  | N/A |  |  |  |  |  |  |  |  |  |  |
| Multiple Service Packet |  | ✅ |  | ✅ | N/A | ✅ | N/A | N/A | ✅ | ✅ | N/A | ✅ |
| Set_Attribute_Single (assembly) |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | ✅ | ✅ | ✅ | ✅ |
| Unconnected_Send routing (backplane slot 0) |  |  | ✅ |  |  |  |  |  |  |  |  |  |

181 passed, 0 failed, 142 not applicable. N/A: the reference has the
role but not the feature. Empty: not exercised with that reference in
that direction (it lacks the role, or no case covers it yet).

Notes:

- **EEIP.NET, Class 1 I/O, configuration data** (reference originator): the adapter declares no client feature configData
- **EEIP.NET, Class 3 connected explicit messaging** (reference originator): the adapter declares no client feature class3
- **EEIP.NET, ListIdentity (TCP)** (reference originator): the adapter declares no client feature listIdentityTcp
- **EEIP.NET, Logix BOOL array element write** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix Read Tag (64-bit types)** (reference originator): the adapter has no read-tag operation
- **EEIP.NET, Logix Read Tag (atomic types)** (reference originator): the adapter has no read-tag operation
- **EEIP.NET, Logix Read Tag Fragmented (1200 octets)** (reference originator): the adapter has no read-tag operation
- **EEIP.NET, Logix STRING read and write** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix Write Tag** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix bit write (Read Modify Write Tag)** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix multiple tags in one request (read-tags)** (reference originator): the adapter has no read-tags operation
- **EEIP.NET, Logix structure read (UDT)** (reference originator): the adapter has no read-tag operation
- **EEIP.NET, Logix structure write (UDT)** (reference originator): the adapter has no write-tag operation
- **EEIP.NET, Logix tag list (0x55)** (reference originator): the adapter has no tag-list operation
- **EEIP.NET, Logix tag list with structure and STRING tags** (reference originator): the adapter has no tag-list operation
- **EEIP.NET, Multiple Service Packet** (reference originator): the adapter has no multiple-get operation
- **EIPScanner, Class 1 I/O, T->O multicast** (reference originator): EIPScanner does not join multicast groups
- **EIPScanner, Class 1 I/O, configuration data** (reference originator): a data segment at the end of EIPScanner's connection path
- **EIPScanner, Class 1 I/O, listen-only (multicast, next to its owner)** (reference originator): EIPScanner does not join multicast groups
- **EIPScanner, Class 3 connected explicit messaging** (reference originator): EIPScanner has no SendUnitData sender
- **EIPScanner, Forward_Open refusal (configuration size)** (reference originator): EIPScanner logs the refusal; the adapter reports refused
- **EIPScanner, Forward_Open refusal (connection size)** (reference originator): EIPScanner logs the refusal; the adapter reports refused
- **EIPScanner, Get_Attribute_Single (16-bit logical segments)** (reference originator): EIPScanner packs 16-bit class/instance/attribute segments
- **EIPScanner, Logix tag services** (reference originator): EIPScanner has no symbolic segments
- **EIPScanner, Multiple Service Packet** (reference originator): built by the adapter with EIPScanner's MessageRouterRequest
- **OpENer, Class 1 I/O, configuration data** (go-ethernetip originator): a data segment of 10 octets for configuration assembly 151
- **OpENer, Class 1 I/O, exclusive owner, point-to-point** (go-ethernetip originator): output 150 echoed to input 100 by the sample application
- **OpENer, Class 1 I/O, listen-only (multicast, next to its owner)** (go-ethernetip originator): listen-only connection point 153 opened while the exclusive owner's multicast production runs; both consume it on one endpoint. Closed after the owner: OpENer stops the production and drops the owner when a listen-only connection closes first
- **OpENer, Error responses (unknown class, attribute)** (go-ethernetip originator): OpENer answers 0x05 for an unknown class or instance, 0x14 for an attribute
- **OpENer, Forward_Open refusal (configuration size)** (go-ethernetip originator): OpENer answers 0x0129 (invalid configuration application path) where go-ethernetip's target answers 0x0126 (invalid configuration size)
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
- **cpppo, Logix bit write (Read Modify Write Tag)** (go-ethernetip originator): cpppo 5.2.5 rejects service 0x4E: it answers SendRRData with encapsulation status 0x0008
- **cpppo, Logix structure read (UDT)** (go-ethernetip originator): cpppo's simulator has no structure templates
- **cpppo, Logix tag list (0x55) and LogixDriver open** (go-ethernetip originator): cpppo has no Symbol object tag list
- **eip-rs, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **eip-rs, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **eip-rs, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **eip-rs, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **eip-rs, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **eip-rs, Identity object (identity operation)** (reference originator): the adapter has no identity operation
- **eip-rs, Large_Forward_Open** (reference originator): the adapter has no io operation
- **etherip, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **etherip, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **etherip, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **etherip, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **etherip, Class 3 connected explicit messaging** (reference originator): the adapter declares no client feature class3
- **etherip, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **etherip, Large_Forward_Open** (reference originator): the adapter has no io operation
- **etherip, Logix BOOL array element write** (reference originator): the adapter declares no client feature readModifyWrite
- **etherip, Logix Read Tag (64-bit types)** (reference originator): reference limitation: etherip knows no LINT or LREAL (its type lookup fails)
- **etherip, Logix Read Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature readTagFragmented
- **etherip, Logix STRING read and write** (reference originator): the adapter declares no client feature templates
- **etherip, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **etherip, Logix bit write (Read Modify Write Tag)** (reference originator): the adapter declares no client feature readModifyWrite
- **etherip, Logix structure read (UDT)** (reference originator): the adapter declares no client feature templates
- **etherip, Logix structure write (UDT)** (reference originator): the adapter declares no client feature templates
- **etherip, Logix tag list (0x55)** (reference originator): the adapter has no tag-list operation
- **etherip, Logix tag list with structure and STRING tags** (reference originator): the adapter has no tag-list operation
- **etherip, Multiple Service Packet** (reference originator): the adapter has no multiple-get operation
- **etherip, Set_Attribute_Single (assembly)** (reference originator): the adapter has no set-attribute operation
- **gologix, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **gologix, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **gologix, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **gologix, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **gologix, Class 3 connected explicit messaging** (go-ethernetip originator): the server declares no getAttributeSingle
- **gologix, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **gologix, Get_Attribute_Single** (go-ethernetip originator): the server declares no getAttributeSingle
- **gologix, Identity object (identity operation)** (reference originator): the adapter has no identity operation
- **gologix, Large_Forward_Open** (reference originator): the adapter has no io operation
- **gologix, ListIdentity (UDP)** (go-ethernetip originator): the server declares no listIdentityUdp
- **gologix, ListIdentity (UDP)** (reference originator): the adapter declares no client feature listIdentityUdp
- **gologix, Logix BOOL array element write** (reference originator): the adapter declares no client feature readModifyWrite
- **gologix, Logix Read Tag Fragmented (1200 octets)** (go-ethernetip originator): the server declares no readTagFragmented
- **gologix, Logix Read Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature readTagFragmented
- **gologix, Logix STRING read and write** (reference originator): the adapter declares no client feature templates
- **gologix, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **gologix, Logix bit write (Read Modify Write Tag)** (go-ethernetip originator): the server declares no readModifyWrite
- **gologix, Logix bit write (Read Modify Write Tag)** (reference originator): the adapter declares no client feature readModifyWrite
- **gologix, Logix structure read (UDT)** (reference originator): the adapter declares no client feature templates
- **gologix, Logix structure write (UDT)** (reference originator): the adapter declares no client feature templates
- **gologix, Logix tag list (0x55)** (go-ethernetip originator): the server declares no tagList
- **gologix, Logix tag list with structure and STRING tags** (reference originator): the adapter declares no client feature templates
- **gologix, Multiple Service Packet** (go-ethernetip originator): the server declares no multipleService
- **libplctag, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **libplctag, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **libplctag, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **libplctag, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **libplctag, Class 3 connected explicit messaging** (go-ethernetip originator): the server declares no getAttributeSingle
- **libplctag, Error responses (unknown class, attribute)** (reference originator): over Class 3: libplctag 2.7.2 builds unconnected requests without their route path
- **libplctag, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **libplctag, Get_Attribute_Single** (go-ethernetip originator): the server declares no getAttributeSingle
- **libplctag, Get_Attribute_Single** (reference originator): over Class 3: libplctag 2.7.2 builds unconnected requests without their route path
- **libplctag, Get_Attributes_All (Identity)** (go-ethernetip originator): the server declares no getAttributesAll
- **libplctag, Get_Attributes_All (Identity)** (reference originator): over Class 3: libplctag 2.7.2 builds unconnected requests without their route path
- **libplctag, Large_Forward_Open** (reference originator): the adapter has no io operation
- **libplctag, ListIdentity (TCP)** (go-ethernetip originator): the server declares no listIdentityTcp
- **libplctag, ListIdentity (TCP)** (reference originator): the adapter has no list-identity operation
- **libplctag, ListIdentity (UDP)** (go-ethernetip originator): the server declares no listIdentityUdp
- **libplctag, ListIdentity (UDP)** (reference originator): the adapter has no list-identity operation
- **libplctag, Logix BOOL array element write** (reference originator): reference limitation: libplctag sends Bits[37] as element 37 of the DWORD array; its own form is Bits[1].5
- **libplctag, Logix STRING read and write** (reference originator): the adapter declares no client feature templates
- **libplctag, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **libplctag, Logix bit write (Read Modify Write Tag)** (go-ethernetip originator): the server declares no readModifyWrite
- **libplctag, Logix structure read (UDT)** (reference originator): the adapter declares no client feature templates
- **libplctag, Logix structure write (UDT)** (reference originator): the adapter declares no client feature templates
- **libplctag, Logix tag list (0x55)** (go-ethernetip originator): the server declares no tagList
- **libplctag, Logix tag list with structure and STRING tags** (reference originator): the adapter declares no client feature templates
- **libplctag, Multiple Service Packet** (go-ethernetip originator): the server declares no getAttributeSingle
- **libplctag, Multiple Service Packet** (reference originator): the adapter has no multiple-get operation
- **libplctag, Set_Attribute_Single (assembly)** (reference originator): over Class 3: libplctag 2.7.2 builds unconnected requests without their route path
- **loki-os go-ethernet-ip, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, Identity object (identity operation)** (reference originator): the adapter has no identity operation
- **loki-os go-ethernet-ip, Large_Forward_Open** (reference originator): the adapter has no io operation
- **loki-os go-ethernet-ip, ListIdentity (UDP)** (reference originator): the adapter declares no client feature listIdentityUdp
- **loki-os go-ethernet-ip, Logix BOOL array element write** (reference originator): the adapter declares no client feature readModifyWrite
- **loki-os go-ethernet-ip, Logix Read Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature readTagFragmented
- **loki-os go-ethernet-ip, Logix STRING read and write** (reference originator): the adapter declares no client feature templates
- **loki-os go-ethernet-ip, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **loki-os go-ethernet-ip, Logix Write Tag** (reference originator): reference limitation: go-ethernet-ip writes a tag only whole (all its elements, with the dimension bits in the type), not elements of an array
- **loki-os go-ethernet-ip, Logix bit write (Read Modify Write Tag)** (reference originator): the adapter declares no client feature readModifyWrite
- **loki-os go-ethernet-ip, Logix structure read (UDT)** (reference originator): the adapter declares no client feature templates
- **loki-os go-ethernet-ip, Logix structure write (UDT)** (reference originator): the adapter declares no client feature templates
- **loki-os go-ethernet-ip, Logix tag list with structure and STRING tags** (reference originator): the adapter declares no client feature templates
- **node-ethernet-ip, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Large_Forward_Open** (reference originator): the adapter has no io operation
- **node-ethernet-ip, Logix BOOL array element write** (reference originator): reference limitation: node-ethernet-ip sends Bits[37] as element 37 of the DWORD array
- **node-ethernet-ip, Logix Read Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature readTagFragmented
- **node-ethernet-ip, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **pycomm3, Class 1 I/O, exclusive owner, point-to-point** (reference originator): pycomm3 has no implicit messaging
- **pycomm3, ListIdentity (UDP)** (reference originator): pycomm3 discover() to the adapter's address
- **pycomm3, Logix BOOL array element write** (reference originator): pycomm3 writes Bits[N] with Read Modify Write on the DWORD holding it
- **pycomm3, Logix Write Tag Fragmented (1200 octets)** (reference originator): pycomm3 splits a write larger than its connection size into Write Tag Fragmented (0x53)
- **pycomm3, Logix Write Tag** (reference originator): pycomm3 1.2.16 repeats the request in the message; the emulation ignores the extra octets, as Logix does
- **pycomm3, Logix bit write (Read Modify Write Tag)** (reference originator): pycomm3 writes Flags.N with service 0x4E
- **pycomm3, Logix structure read (UDT)** (reference originator): BOOL members in a hidden host SINT, an INT array and a nested STRING
- **pycomm3, Logix structure write (UDT)** (reference originator): a whole structure, then one member
- **pycomm3, Logix tag list (0x55) and LogixDriver open** (reference originator): pycomm3 uploads the tag list on open: Unconnected_Send, Large_Forward_Open, program name, 0x55 with continuation
- **pycomm3, Logix tag list with structure and STRING tags** (reference originator): pycomm3 uploads the Motor template (Get_Attribute_List and Read Template on class 0x6C) on open
- **pycomm3, Unconnected_Send routing (backplane slot 0)** (reference originator): pycomm3 get_module_info(0)
- **pylogix, Class 1 I/O, T->O multicast** (reference originator): the adapter has no io operation
- **pylogix, Class 1 I/O, configuration data** (reference originator): the adapter has no io operation
- **pylogix, Class 1 I/O, exclusive owner, point-to-point** (reference originator): the adapter has no io operation
- **pylogix, Class 1 I/O, input only (heartbeat O->T)** (reference originator): the adapter has no io operation
- **pylogix, Class 3 connected explicit messaging** (reference originator): the adapter declares no client feature class3
- **pylogix, Forward_Open refusal (connection size)** (reference originator): the adapter has no io operation
- **pylogix, Large_Forward_Open** (reference originator): the adapter has no io operation
- **pylogix, ListIdentity (TCP)** (reference originator): the adapter declares no client feature listIdentityTcp
- **pylogix, Logix STRING read and write** (reference originator): the adapter declares no client feature templates
- **pylogix, Logix Write Tag Fragmented (1200 octets)** (reference originator): the adapter declares no client feature writeTagFragmented
- **pylogix, Logix structure read (UDT)** (reference originator): the adapter declares no client feature templates
- **pylogix, Logix structure write (UDT)** (reference originator): the adapter declares no client feature templates
- **pylogix, Logix tag list with structure and STRING tags** (reference originator): the adapter declares no client feature templates
- **pylogix, Multiple Service Packet** (reference originator): the adapter has no multiple-get operation

Images:

- OpENer: `{"adapter":"opener","adapterVersion":"v0.4.0","upstream":"OpENer","upstreamVersion":"2.3-588","upstreamRevision":"d8820ef41ce30dda06d213438ba81c81de33ffe2","contract":"1.0"}`
- EIPScanner: `{"adapter":"eipscanner","adapterVersion":"v0.4.0","upstream":"EIPScanner","upstreamVersion":"1.3.0-33","upstreamRevision":"12c89a57ec2e7449efb1348be52af10be9ef9701","contract":"1.0"}`
- pycomm3: `{"adapter": "pycomm3", "adapterVersion": "v0.4.0", "contract": "1.0", "upstream": "pycomm3", "upstreamRevision": "36aeb19b5cb47495df9fd1caa38ce9d2f6d12ea3", "upstreamVersion": "1.2.16"}`
- cpppo: `{"adapter": "cpppo", "adapterVersion": "v0.4.0", "contract": "1.0", "upstream": "cpppo", "upstreamRevision": "f7c224bbb2389bd26d0088eeb1a93db3a5c4858f", "upstreamVersion": "5.2.5"}`
- libplctag: `{"adapter":"libplctag","adapterVersion":"v0.4.0","upstream":"libplctag","upstreamVersion":"2.7.2","upstreamRevision":"7712ed7f1ee05ba0ebfca641b3f5c43da52a66ed","contract":"1.0"}`
- gologix: `{"adapter":"gologix","adapterVersion":"v0.4.0","contract":"1.0","upstream":"gologix","upstreamRevision":"647a0b87b756d42e37ac0f65c5762dc89036152c","upstreamVersion":"0.44.0-beta"}`
- pylogix: `{"adapter": "pylogix", "adapterVersion": "v0.4.0", "contract": "1.0", "upstream": "pylogix", "upstreamRevision": "193b6c7b0c601619223ee53587abd821d3b344c1", "upstreamVersion": "1.1.6"}`
- etherip: `{"adapter":"etherip","adapterVersion":"v0.4.0","upstream":"etherip","upstreamVersion":"1.0-67","upstreamRevision":"ce0688ae51be5652ec200fbe389667b36a638323","contract":"1.0"}`
- eip-rs: `{"adapter":"eiprs","adapterVersion":"v0.4.0","contract":"1.0","upstream":"rseip","upstreamRevision":"16e2236afb65acc9c82ebdcfbdcbba72e93b3887","upstreamVersion":"0.3.1-2"}`
- node-ethernet-ip: `{"adapter":"nodeeip","adapterVersion":"v0.4.0","upstream":"node-ethernet-ip","upstreamVersion":"2.0.0","upstreamRevision":"4743b077abd3cc8826d511acde8f890372826e16","contract":"1.0"}`
- EEIP.NET: `{"adapter":"eeip","adapterVersion":"v0.4.0","upstream":"EEIP.NET","upstreamVersion":"1.6.0","upstreamRevision":"58b91a0c8e30227b1b97a637635d147a2a9655dc","contract":"1.0"}`
- loki-os go-ethernet-ip: `{"adapter":"lokieip","adapterVersion":"v0.4.0","contract":"1.0","upstream":"go-ethernet-ip","upstreamRevision":"535f79752f63a4122c37c7f0f9b95ece01a8f7b4","upstreamVersion":"0.0.0-20221229063210-535f797"}`
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
  the extra octets, as Logix does, also for BOOL members); appends route
  bytes to unrouted generic messages; sends an 8-octet AND mask in
  Read-Modify-Write whatever the size (the extra octets are ignored);
  reads a template member type other than plain BOOL (0x00C1) for a BOOL
  member as a template ID (the emulation sends plain BOOL, as Logix); and
  addresses BOOL arrays by DWORD, expecting the tag list to report them as
  DWORD arrays (the emulation does, as Logix).
- OpENer: refuses configuration data of the wrong size with 0x0129, and a
  listen-only connection whose path lacks the configuration point with
  0x012F; when a listen-only connection is closed before its owner, OpENer
  stops the shared multicast production and drops the owner (whose
  Forward_Close then finds no connection, 0x0107). The interop case closes
  the owner first; against the library's target the owner keeps running
  (e2e).
- cpppo: closes the session on unknown tags instead of answering an error;
  leaves the continuation of fragmented reads to its caller; reports
  0.0.0.0 in ListIdentity without configuration; answers SendUnitData with
  the O->T connection ID (the client accepts either ID).
- libplctag 2.7.2: builds unconnected generic requests without the route
  path of their Unconnected_Send (its attribute requests are tested over
  Class 3); sends a BOOL array element as element N of the DWORD array
  (its own form is `Bits[1].5`). Its ab_server has no ListIdentity, no
  attributes and no tag list, and refuses a RegisterSession with a non-zero
  sender context.
- gologix: its client always connects (Large_Forward_Open); its server
  answers ListServices with the wrong command, malformed
  Get_Attribute_Single replies and a tag list without the requested
  attributes, and does not limit replies to the connection size.
- pylogix: reads the undocumented Template attribute 3 and loops on a
  template read that returns no data (the emulation refuses a read past the
  end); ListIdentity by broadcast only.
- etherip: no LINT or LREAL; decodes the identity's product code by summing
  its octets; no fragmented services.
- node-ethernet-ip: no Unconnected_Send; writes a whole structure with the
  template instance ID instead of the structure handle (refused 0x2107);
  BOOL array elements as element N.
- EEIP.NET: no ListIdentity over TCP or Class 3; always sends a
  configuration segment and a T->O socket address item.
- go-ethernet-ip (loki-os): no UDP, no timeouts of its own; does not check
  the status of RegisterSession, Forward_Open or a write; writes a tag only
  whole (scalar tags only); no fragmented services.

All are recorded, with what the adapters do about them, in
[ethernetip-interop's CAPABILITIES.md](https://github.com/otfabric/ethernetip-interop/blob/main/docs/CAPABILITIES.md).
