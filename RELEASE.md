# go-ethernetip Releases

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
