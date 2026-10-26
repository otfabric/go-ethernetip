# Observability

## Logging

Logging is silent by default. Clients, scanners, servers and I/O endpoints
take a `ethernetip.Logger` (`WithLogger`):

- `Logger` — `Debugf`, `Infof`, `Warnf`, `Errorf`; `NopLogger()`,
  `NewStdLogger(*log.Logger)`.
- `FieldLogger` — adds `With` and the `...KV` methods; when the logger
  implements it, every entry is a constant message with fields
  (`component`, `remote`, `session`, `connection`, `ot`, `to`, `error`, ...)
  instead of a formatted line.
- `ContextLogger` — context-aware entries, for trace identifiers.
- `NewSlogLogger(handler)` / `NewSlogFieldLogger(handler)` wrap a
  `log/slog` handler and implement all three.

Messages are constant strings ("session registered", "connection opened",
"Forward_Open refused", "I/O connection timed out", ...): filter on them.
Debug entries are only built when the handler is enabled for debug.

## Metrics

`WithMetrics(m)` takes an `ethernetip.Metrics`: `OnConnect`, `OnDisconnect`,
`OnPacketSent`, `OnPacketReceived` (encapsulation command and size) and
`OnDecodeError`. Embed `ethernetip.NopMetrics` to implement only what you
need. A value that also implements:

- `ethernetip.RequestMetrics` (client) gets `OnRequest` and
  `OnRequestDone` with the service, duration and error of every explicit
  request;
- `ethernetip.ServerMetrics` (server) gets `OnHandled` (service, general
  status, duration), `OnConnectionOpened` and `OnConnectionClosed` (with
  `ErrTimeout` for timeouts, nil for Forward_Close);
- `ethernetip.IOMetrics` (server, I/O endpoints) gets `OnIOSent`,
  `OnIOReceived` and `OnIODropped` with the reason ("unknown connection",
  "wrong source", "wrong size", "old encapsulation sequence", "malformed").

Callbacks run on the protocol goroutines: they must be safe for concurrent
use and must not block.

## State

`Client.State()` and `IO.State()` return `ethernetip.State`
(disconnected, connecting, connected, timed-out); `WithStateHandler` and
`IOConfig.OnState` report changes. `IO.Stats()` and
`implicit.Connection.Stats()` count datagrams sent, received, dropped and
duplicated. The server exposes `Sessions()`, `Connections()` (IDs, triad,
RPIs, path) and the Connection Manager's counters (instance 1, attributes 1
to 8: open requests, format, resource and other rejects, close requests and
rejects, connection timeouts), readable over the network.
