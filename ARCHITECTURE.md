# Architecture

## Layers and packages

```
            application
  ┌──────────┬──────────┬──────────┬─────────┐
  │  client  │ scanner  │  server  │  logix  │   roles
  └────┬─────┴────┬─────┴────┬─────┴────┬────┘
       │          │          │          │
  ┌────┴──────────┴──────────┴──────────┴────┐
  │    cip  (messages, EPATH, Connection     │   CIP
  │          Manager services, catalog)      │
  ├──────────────────────┬───────────────────┤
  │ encap (TCP 44818:    │ implicit (UDP     │   EtherNet/IP
  │ header, CPF, items)  │ 2222: I/O)        │
  └──────────────────────┴───────────────────┘
  eds: Electronic Data Sheets, independent of the network
```

| Package | Responsibility | Depends on |
|---|---|---|
| `cip` | CIP data types, EPATH segments (padded and packed), requests and responses, Multiple Service Packet, Forward_Open/Large/Close, Unconnected_Send, Identity, the generated catalog (classes, services, statuses, data types, device types, vendors) | — |
| `encap` | Encapsulation header and commands, `ReadPacket` over a stream, common packet format and its items (identity, services, sockaddr, sequenced and connected address) | `cip` |
| `implicit` | I/O datagram codec, real-time formats, an `Endpoint` (one UDP socket, dispatch by connection ID, multicast membership) and the `Connection` runtime (production at the RPI, consumption with sequence checks and watchdog) | `cip`, `encap`, root |
| `client` | Explicit originator: session, request correlation, routing, Class 3 connections, Forward_Open/Close, discovery | `cip`, `encap`, root |
| `scanner` | I/O originator: Forward_Open of Class 0/1 connections over a `client.Client`, an `implicit.Connection` per connection, reconnect | `client`, `implicit` |
| `server` | Target: sessions, Message Router, standard objects, Connection Manager, Class 0/1/3 target connections | `cip`, `encap`, `implicit` |
| `logix` | Logix tag services (client over a `client.Doer`), templates, UDT decoding; `TagServer` emulation plugged into `server` | `client`, `server`, `cip` |
| `eds` | EDS parser, typed views, validation, formatter, builder, Go generator | `cip` |
| root `ethernetip` | Sentinel and typed errors, `Logger` family, `Metrics` family, `State` | `cip`, `encap` |

Vendor extensions stay in `logix`: `cip`, `client` and `server` know
nothing of Logix beyond a `server.SymbolHandler` hook for symbolic paths
and the catalog entries marked *vendor*.

## Goroutines

**Client.** One goroutine per session reads packets and dispatches them:
replies to unconnected requests by sender context (a 64-bit counter), Class
3 replies by connection ID and sequence count. Callers block in `Do` on a
buffered channel; `WithMaxPending` bounds the requests in flight with a
semaphore. Writes are serialised by a mutex. When the read loop ends, every
pending request fails with the session's error and its Class 3 connections
end.

**Server.** `Serve` accepts connections; each TCP connection has one
goroutine that reads, handles and answers its packets in order, so requests
of one session are never reordered. The UDP explicit socket has one
goroutine. Object handlers run on the session goroutine; objects must be
safe for concurrent use across sessions. Class 3 connections have an
inactivity timer (`time.AfterFunc`).

**I/O.** An `implicit.Endpoint` has one goroutine per socket that receives
datagrams and calls the consuming connection synchronously (`OnData` must
not block). Each `implicit.Connection` has one goroutine that produces at
its RPI, on `Trigger` (change of state) and runs the watchdog, which the
receive path resets through a channel: the timer is owned by that
goroutine alone.

**Scanner.** One `implicit.Connection` per I/O connection; a reconnect
goroutine only while reopening after a timeout.

Every goroutine is tied to a `Close`: `Client.Close`, `Server.Close`,
`Scanner.Close`, `IO.Close`, `Endpoint.Close`. The e2e suite checks after
all its tests that no goroutine or file descriptor is left.

## Protocol machines

**Session (client).** dial → RegisterSession (answered before the reader
starts) → connected → on error disconnected; `WithAutoReconnect` reconnects
on the next request.

**Forward_Open (server).** decode → triad unique → connection limit →
route prefix is this slot → path: electronic key (vendor, device type,
product code, revision with compatibility), network segments, class,
instance/points, data segment → RPI range → transport class: 3 (Message
Router path, point-to-point) or 0/1 (assembly points: config, O->T, T->O;
sizes with the real-time format overhead; owner rules: one exclusive owner
per output assembly, input-only heartbeats, listen-only only beside a
multicast producer) → IDs (O->T chosen by the target; T->O the
originator's, or the shared multicast production's) → reply with Sockaddr
Info items (O->T when the I/O port is not 2222, T->O for multicast). Each
refusal is general status 0x01 with the extended status of the catalog.

**I/O connection.** produce every RPI: encapsulation sequence +1 always,
Class 1 sequence count +1 when the data or run/idle changes; consume: drop
wrong source address, wrong size, old encapsulation sequence (serial
arithmetic); deliver when the sequence count is newer; reset the watchdog
on every accepted datagram; timeout after RPI × 4 << multiplier.

## Defensive decoding

Every decoder works on a byte slice through `cip.Reader`, whose first
short read sets a sticky error, or checks lengths before slicing. Counts in
messages (items, services, segments, attributes, tags) are compared with
the octets that carry them before anything is allocated, and are bounded
(`encap.MaxItems`, the 255-word path limit, 256 path segments, 200 embedded
services, `WithMaxPacket` for whole packets). Fuzz targets cover every
decoder and the server's dispatch of Logix requests; the corpus seeds are
in `testdata/fuzz`.
