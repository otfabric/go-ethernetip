# Standards, licensing and provenance

## The specifications

EtherNet/IP and CIP are specified by ODVA in The CIP Networks Library:
Volume 1 (CIP), Volume 2 (EtherNet/IP adaptation), Volume 8 (CIP
Security), and others. As of 2026 ODVA sells them by annual subscription
under its Terms of Usage; editions current in April 2026 were Volume 1
v3.40 and Volume 2 v1.36. **This project has no access to them** and does
not reproduce them.

The implementation is built from:

- the behaviour of independent open-source implementations: OpENer
  (adapted BSD), EIPScanner (MIT), pycomm3 (MIT), cpppo (GPL-3.0, used only
  in its own container for testing), studied as references, with no code
  copied;
- public documents: Rockwell Automation's *Logix 5000 Controllers Data
  Access* (1756-PM020) for the Logix services, IANA's port registry (44818,
  2222, 2221), vendor documentation of CIP Security ports;
- the codes recorded per entry in [CATALOG.md](../CATALOG.md).

Where public information is missing, the library follows what the
references accept and says so (the notes of
[INTEROPERABILITY.md](../INTEROPERABILITY.md) and
[research/STACKS.md](research/STACKS.md)). Behaviour that only the
specification defines and no reference exercises is not invented: such
features are listed as not implemented.

## ODVA licensing and conformance

- A product that implements EtherNet/IP needs an ODVA vendor ID and must
  comply with the ODVA Terms of Usage; OpENer's licence states the same.
  The library's default vendor ID 0xFFFF marks an unregistered originator;
  set your own (`client.WithOriginator`, `server.WithIdentity`).
- Conformance requires ODVA's conformance test at an ODVA test service
  provider. **go-ethernetip is not conformance tested and makes no
  conformance or certification claim.** The interop results show behaviour
  against four independent implementations, nothing more.
- EtherNet/IP, CIP and CIP Security are trademarks of ODVA.

These are unresolved obligations for whoever ships a product built on the
library; they do not restrict the use of this MIT-licensed code.

## CIP Security

Public sources (IANA, ODVA's published overview of CIP Security phase 1,
vendor documentation) establish: EtherNet/IP over TLS on TCP 2221 for
explicit messaging, DTLS on UDP 2221 for I/O, and the objects CIP Security
(0x5D), EtherNet/IP Security (0x5E) and Certificate Management (0x5F), with
Authority (0x60), Password Authenticator (0x61), Certificate Authenticator
(0x62) and Ingress Egress (0x63) in later phases.

Implemented: the TLS transport (`client.WithTLS`, `server.WithTLS`), with
the security of `crypto/tls`. Not implemented: DTLS (the Go standard
library has none and the module has no dependencies), the security objects
and their configuration model (Volume 8 not available; no reference peer in
the interop suite). The class codes are in the catalog so that the objects
can be added as `server.Object`s later without changes elsewhere.
