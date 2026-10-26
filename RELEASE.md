# go-ethernetip Releases

## v0.3.2

**Date:** 2026-10-26
**Previous release:** v0.3.1

## Summary

Interop qualified against otfabric/ethernetip-interop v0.5.0, whose OpENer
image follows OpENer's master (2.3-591, `0e1ab7e`; the new upstream commits
only change OpENer's own CI). No change to the library's code.

## Changes

- **Interop**: the twelve reference images of ethernetip-interop v0.5.0,
  pinned by digest; the matrix is unchanged.
- **README**: the OpENer version compared.

---

## v0.3.1

**Date:** 2026-10-26
**Previous release:** v0.3.0

## Summary

Interop with a twelfth independent stack, loki-os's go-ethernet-ip
(otfabric/ethernetip-interop v0.4.0, pinned by digest): 184 cases pass,
0 fail, 146 N/A. No change to the library's code.

## Changes

- **Interop**: go-ethernet-ip (loki-os) by its declared capabilities: 11
  cases pass; Logix Write Tag N/A (it writes a tag only whole).
- **README**: one comparison table of go-ethernetip and all twelve
  reference stacks.
- **Tests**: `TestChaosExplicit` polls for recovery with a deadline; the
  scanner tests' shared configuration has a 64-RPI timeout (flaky on loaded
  macOS Intel runners before).

---

## v0.3.0

**Date:** 2026-10-26
**Previous release:** v0.2.1

## Summary

Seven more independent stacks in the interop suite: libplctag, gologix,
pylogix, etherip, eip-rs, node-ethernet-ip and EEIP.NET
(otfabric/ethernetip-interop v0.3.0), in both directions where they have
the role, with a capability-driven suite that runs every case a stack
declares. The new peers found three defects in the server and the Logix
emulation, fixed here.

## Changes

### Fixes

- **logix**: Template attribute 4 is sized so that reading the definition
  takes attribute 4 × 4 − 23 octets, as Rockwell's *Logix 5000 Controllers
  Data Access* (1756-PM020) specifies; it was − 21, and pylogix,
  node-ethernet-ip and libplctag read 2 octets short (the last member name
  truncated). The client reads − 23 octets too. A Read Template starting at
  or past the end is refused (pylogix looped forever on an empty success).
- **server, logix**: a request on a Class 3 connection carries the
  connection's reply budget (`server.Request.MaxReply`: its T->O size less
  the sequence count and the reply header); Logix tag replies keep within it
  with a partial transfer. Before, a 300-DINT read on a 504-octet connection
  answered 1228 octets, which libplctag could not take.
- **server**: a Multiple Service Packet may carry up to 1000 services (was
  200, refused with 0x02); node-ethernet-ip sends about 220 Read Tag
  requests in one Large_Forward_Open packet.

### Tests

- Interop: libplctag, gologix, pylogix, etherip, eip-rs, node-ethernet-ip
  and EEIP.NET against the library's target (adapter, logix and
  logix-structures fixtures), and the library's originator against
  libplctag's ab_server and gologix. Cases run by the stacks' declared
  capabilities; documented limits of a stack are recorded N/A with the
  reason. The matrix covers eleven references.
- README: the comparison covers the seven new stacks.

---

## v0.2.1

**Date:** 2026-10-26
**Previous release:** v0.2.0

## Summary

A fix of the adapter server: ListIdentity over UDP could be off at random.

## Changes

### Fixes

- **server**: `Listen` binds the UDP socket of the explicit port (ListIdentity
  over UDP) before the I/O endpoint. An I/O endpoint on an ephemeral port
  (`WithIOAddress("host:0")`) could take the explicit port's number
  (Windows hands out the same numbers for TCP and UDP); the UDP socket then
  failed to bind and the server answered ListIdentity over TCP only, with
  only a warning in the log, so discovery found nothing. When the I/O
  address is unusable, `Listen` now also releases the UDP socket.

### Tests

- `TestListenUDPBeforeIO`: explicit and I/O address on the same port; the
  explicit UDP socket keeps it, `Listen` reports the I/O endpoint, and both
  ports are released.
- The chaos monkey's invariants: a write whose reply was lost may be
  applied after later writes (its request can arrive late from a dying
  connection); such values, and the bits of unconfirmed bit writes, stay
  possible. The monkey had flagged a correct late arrival as an error.
- The scanner's API test allows a longer stall on loaded runners and
  reports the connection state when the input does not arrive.

---

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
