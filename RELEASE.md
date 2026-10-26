# go-ethernetip Releases

## v0.2.0

**Date:** 2026-10-26
**Previous release:** v0.1.0

## Summary

More interoperability: listen-only connections, configuration data, Logix
bit writes, structures and STRING verified against the references
(otfabric/ethernetip-interop v0.2.0: 63 cases pass, 0 fail, 13 N/A, up
from 49), and the defects those cases found fixed. A feature comparison
with the four reference stacks, a chaos monkey, more end-to-end tests.

## Changes

### Fixes

- **implicit**: several multicast connections of one endpoint can consume
  one production (an owner and its listen-only connections); before, the
  second Open failed with "connection ID in use".
- **implicit**: an endpoint bound to one address sends multicast from, and
  joins groups on, that address's interface instead of the default
  route's; a group is left on the interface it was joined on (on Linux,
  leaving one joined on a given interface failed silently, and joining it
  again failed with "address already in use").
- **logix**: template definitions give a BOOL member the plain BOOL type
  (0x00C1), its bit in the info word, as Logix does; pycomm3 read the old
  encoding as a template ID and could not open the controller.
- **logix**: the emulation addresses BOOL arrays by DWORD (`Bits[1]` is
  bits 32 to 63) and lists them as DWORD arrays, as Logix does and pycomm3
  and libplctag expect. **Behaviour change**: an index into a BOOL array
  of the emulation used to count bits.
- **logix**: a Write Tag to a BOOL member ignores trailing octets, as for
  the other types (pycomm3 repeats the request).
- **client**: with `WithTLS` and no `ServerName`, the certificate is
  verified against the host dialed, as `tls.Dial` does; before, the
  handshake failed unless `ServerName` or `InsecureSkipVerify` was set.

### Additions

- `implicit.WithMulticastInterface`, `scanner.WithMulticastInterface`.
- `ethernetip.ConnectionInfo.Group`: the T->O multicast address.

### Tests and docs

- Interop: configuration data (scanner to OpENer, EIPScanner to the
  server), listen-only next to a multicast owner (OpENer), refusals for
  configuration size and listen-only without owner, pycomm3 bit writes,
  BOOL array writes, structure reads and writes, STRING, Write Tag
  Fragmented, and the tag list with structures.
- End to end: listen-only, Class 0, TLS (explicit, Class 3, untrusted
  certificate), discovery, three adapters on one scanner endpoint; a
  seeded chaos monkey mixing explicit, Class 3, Logix and Class 1
  operations and client churn through a faulty proxy.
- README: a feature comparison with OpENer, EIPScanner, pycomm3 and cpppo.

---

## v0.1.0

**Date:** 2026-10-26
**Previous release:** none

## Summary

The first release: a pure Go EtherNet/IP and CIP implementation with an
explicit messaging client, an I/O scanner, an adapter server, the Rockwell
Logix tag services with an emulation, and Electronic Data Sheet tooling,
tested against OpENer, EIPScanner, pycomm3 and cpppo
(otfabric/ethernetip-interop v0.1.0).

## Changes

### Protocol

- **Encapsulation**: all session and list commands over TCP, ListIdentity,
  ListServices and ListInterfaces over UDP, SendRRData and SendUnitData,
  the common packet format with every item in use, status codes, size
  limits, inactivity timeout; EtherNet/IP over TLS.
- **CIP**: data types, EPATH in padded and packed form, requests and
  responses, Multiple Service Packet, Unconnected_Send routing,
  Forward_Open, Large_Forward_Open, Forward_Close; a generated catalog of
  classes, services, general and Connection Manager statuses, data types,
  device types and vendors with their public sources.
- **Client**: unconnected and routed explicit messaging, Class 3
  connections, typed attribute helpers, discovery, auto-reconnect, metrics.
- **Scanner**: Class 0/1 connections, point-to-point and multicast,
  exclusive owner, input only, listen only, run/idle, initial output and
  idle start, reconnect.
- **Server**: Identity, Message Router, Assembly, Connection Manager, Port,
  TCP/IP Interface and Ethernet Link objects; user objects; Class 0/1/3
  target connections with ownership rules, shared multicast production,
  change-of-state production; limits.
- **logix**: tag reads and writes with fragmentation, bit writes, tag lists,
  templates, UDT decoding; `TagServer` emulation.
- **eds**: parser, validation, formatter, builder, Go code generator.

### Tests

- Unit, end-to-end, chaos (TCP and UDP faults, forged datagrams), stress,
  leak checks, fuzz targets for every decoder, benchmarks; combined
  coverage above 90%.
- Interop against otfabric/ethernetip-interop v0.1.0: OpENer, EIPScanner,
  pycomm3, cpppo.

---
