// SPDX-License-Identifier: MIT

// Package ethernetip is the module root of a pure Go implementation of
// EtherNet/IP and the Common Industrial Protocol (CIP), the industrial
// Ethernet protocol of ODVA used by programmable controllers, I/O adapters,
// drives and sensors.
//
// Applications import the subpackages:
//
//   - [github.com/otfabric/go-ethernetip/client]: the originator of explicit
//     messages: sessions, unconnected and connected (Class 3) messaging,
//     Forward_Open and Forward_Close, routing through Unconnected_Send,
//     Multiple Service Packet, discovery with ListIdentity
//   - [github.com/otfabric/go-ethernetip/scanner]: the originator of Class 1
//     (and Class 0) implicit I/O connections: cyclic UDP exchange with
//     sequence handling, run/idle, timeouts and recovery
//   - [github.com/otfabric/go-ethernetip/server]: the target (adapter): the
//     Message Router with the Identity, Message Router, Assembly, Connection
//     Manager, Port, TCP/IP Interface and Ethernet Link objects, explicit and
//     implicit connections, user-defined objects
//   - [github.com/otfabric/go-ethernetip/logix]: Rockwell Automation Logix
//     extensions (vendor specific, not CIP): symbolic tag reads and writes,
//     fragmentation, tag lists, templates and UDTs; on the client and,
//     emulated, on the server
//   - [github.com/otfabric/go-ethernetip/eds]: Electronic Data Sheets: parser,
//     validation, writer and the Go code generator behind ethernetipctl eds
//   - [github.com/otfabric/go-ethernetip/cip]: the CIP codec: data types,
//     EPATHs, messages, the Connection Manager services, the catalog of codes
//   - [github.com/otfabric/go-ethernetip/encap]: the encapsulation codec:
//     headers, commands, the common packet format
//   - [github.com/otfabric/go-ethernetip/implicit]: the codec and the UDP
//     endpoint of implicit (I/O) messages, shared by scanner and server
//
// This package holds what they share: the sentinel and typed errors, the
// [Logger] and [Metrics] interfaces and the [State] of sessions and
// connections.
//
// Docs: README.md, API.md (public API), ARCHITECTURE.md, ERRORS.md (error
// semantics), OBSERVABILITY.md (logging and metrics), INTEROPERABILITY.md
// (coverage and interop results), SECURITY.md, CONTRIBUTING.md, CATALOG.md
// (codes and their provenance), RELEASE.md (changelog).
package ethernetip

// The catalog of CIP codes, cip/catalog.json, generates cip/catalog_gen.go
// and CATALOG.md; the sample EDS generates eds/internal/sampledevice.
//go:generate go run ./internal/cmd/gencatalog
//go:generate go run ./internal/cmd/gensample
