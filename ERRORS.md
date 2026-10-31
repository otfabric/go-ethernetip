# Error semantics

Functions return errors that match the sentinels of the root package with
`errors.Is`, wrapped with detail, or typed errors that carry the peer's
answer, matched with `errors.As`. A bare `errors.New` never leaves a public
function.

## Sentinels

| Sentinel | Meaning | Typical cause |
|---|---|---|
| `ErrClosed` | the client, connection, scanner or server was closed by the application | a call after `Close` |
| `ErrNotConnected` | no registered session | a request after the session was lost, without `WithAutoReconnect` |
| `ErrConnectFailed` | the session could not be established | dial refused, TLS handshake, RegisterSession refused (with an `*EncapError`) |
| `ErrConnectionLost` | the TCP connection ended during a request | peer closed, reset, write failed |
| `ErrTimeout` | no answer within the request's deadline (the earlier of the context's and `WithTimeout`); an I/O connection's consumed data stopped | silent peer; I/O timeout |
| `ErrProtocol` | the peer violated the protocol | reply to another service, malformed reply, a Forward_Open reply for another triad, packet above `WithMaxPacket` |
| `ErrSession` | encapsulation-level refusal | every `*EncapError` matches it |
| `ErrBusy` | a limit was reached | reserved for limits reported locally |
| `ErrUnsupported` | the peer does not support the service or attribute, or the platform lacks a feature | `*CIPError` with status 0x08 or 0x14; `*EncapError` invalid command; multicast on an unsupported OS |
| `ErrInvalidOption` | an option or argument cannot be used | bad option values, paths that do not encode, values that do not fit |

A cancelled context returns `context.Canceled` (not `ErrTimeout`); a
deadline returns an error matching both `ErrTimeout` and
`context.DeadlineExceeded`.

## Sentinels of the subpackages

These packages stand alone (a decoder, a file parser), so their input errors
are their own. The client and server turn a bad frame into `ErrProtocol` or a
CIP status; the sentinels below reach code that calls the packages directly.

| Sentinel | Meaning | Typical cause |
|---|---|---|
| `cip.ErrTruncated` | data ends before the structure it encodes | a decoder given a short buffer |
| `cip.ErrMalformed` | data that does not encode a valid structure | an unknown segment type, an inconsistent length, an out-of-range value |
| `cip.ErrTooLarge` | a value too large for the field that carries its size | a path above 255 words, a string longer than its length prefix allows, a Multiple Service Packet above 65535 services, a connection size that needs Large_Forward_Open |
| `eds.ErrSyntax` | text that is not an EDS file; every `*eds.SyntaxError` matches it and adds the position | `eds.Parse` on a file with a broken section or entry |
| `logix.ErrTagName` | a tag name that does not parse | `logix.ParseTag` |
| `logix.ErrType` | a value used with a type it does not have | `Value` accessors on another type, a template's data that does not fit the structure |

## Typed errors

**`*ethernetip.CIPError`** — a CIP response whose general status is not
success: `Service`, `Path` (of the request), `Status` (`cip.GeneralStatus`),
`Extended` (the additional status words as sent) and `Data` (data that came
with the error). For general status 0x01 the first extended word is a
`cip.ConnectionStatus` of the Connection Manager, named in the message:

```text
ethernetip: Forward_Open @6/1: connection failure (0x01), extended 0x0127 (invalid O->T size) 0x0026
```

Methods that return a response return it **together with** the error, so
that the data of partial transfers (0x06), Get_Attribute_List errors (0x0A)
and embedded service errors (0x1E) is not lost. `client.ResponseError(req,
resp)` turns an embedded response of a Multiple Service Packet into an
error. `ethernetip.StatusOf(err)` returns the general status.

**`*ethernetip.EncapError`** — an encapsulation status other than success:
`Command` and `Status` (`encap.Status`: invalid command 0x01, insufficient
memory 0x02, incorrect data 0x03, invalid session handle 0x64, invalid
length 0x65, unsupported protocol 0x69).

## Errors the server answers

| Situation | Answer |
|---|---|
| unknown class, instance | 0x05 path destination unknown |
| unknown attribute | 0x14 attribute not supported |
| service not supported | 0x08 |
| set of a read-only attribute | 0x0E |
| set data too short / too long | 0x13 / 0x15 |
| output assembly owned by an I/O connection | 0x0C object state conflict |
| malformed path | 0x04 path segment error; a path that runs past the message 0x26 |
| Forward_Open refusals | 0x01 with the extended status of [CATALOG.md](CATALOG.md) (0x0100 duplicate triad, 0x0106 ownership conflict, 0x0109/0x0127/0x0128 sizes, 0x0112 RPI, 0x0113 out of connections, 0x0114-0x0116 electronic key, 0x0117/0x012A/0x012B paths, 0x0119 listen-only without producer, 0x0311 port, 0x0315 segment, ...) |
| Forward_Close of an unknown connection | 0x01 / 0x0107 |
| Unconnected_Send to a route that is not this slot | 0x01 / 0x0311 with the remaining path size |
| Logix: unknown tag; index beyond the end; wrong type | 0x05; 0xFF / 0x2105; 0xFF / 0x2107 |
| encapsulation: no session, wrong handle | status 0x64 |
| encapsulation: malformed common packet format | status 0x03 |
| encapsulation: unknown command | status 0x01 |
| encapsulation: packet above `WithMaxPacket` | status 0x65, then the connection is closed |
| encapsulation: options not zero | discarded without answer |
