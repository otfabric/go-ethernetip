# Implicit messaging (I/O)

An I/O connection carries a target's assembly data cyclically over UDP: the
originator (scanner) sends O->T (its outputs, the target's consumed data),
the target sends T->O (its inputs) at the requested packet interval (RPI).

```go
s, _ := scanner.New(c)              // binds UDP :2222
io, err := s.Open(ctx, scanner.IOConfig{
    ConfigInstance: 151,            // 0 for none (still sent as instance 0); ConfigData sends configuration
    OutputInstance: 150, OutputSize: 32,
    InputInstance:  100, InputSize:  32,
    RPI: 10 * time.Millisecond,
})
```

## Sizes and formats

Sizes are application data sizes. The Forward_Open connection size adds
the Class 1 sequence count (2 octets) and, for the 32-bit run/idle header
format, 4 octets. Defaults match what targets commonly expect (OpENer,
Rockwell adapters): O->T with the run/idle header, T->O modeless. Override
with `OutputFormat` / `InputFormat`. An O->T size of 0 means a heartbeat
(input-only and listen-only connection points).

## Connection types

| Connection | OutputInstance | Notes |
|---|---|---|
| Exclusive owner | the output assembly | one per output assembly; the target refuses a second (0x0106) |
| Input only | the target's input-only heartbeat point | many may share the inputs |
| Listen only | the listen-only heartbeat point, `Multicast: true` | needs an existing multicast connection to the same input (0x0119) |

`Multicast: true` asks for the inputs by multicast; the scanner joins the
group the target returns in its Sockaddr Info item (`IO.Info().Group`). An
owner and its listen-only connections may run on one scanner (one
endpoint): they share the production's connection ID and each receives
every datagram. OpENer wants the listen-only path to name the owner's
configuration point too.

Multicast is received by an endpoint bound to the wildcard address (the
default, `:2222`); an endpoint bound to a unicast address receives no
multicast on most systems. Groups are joined on the interface of
`scanner.WithMulticastInterface` (or `implicit.WithMulticastInterface`),
else on the bound address's interface, else on the system's choice (the
default route's).

## Actual packet intervals

The scanner produces and watches at the actual packet intervals of the
target's Forward_Open reply, which may differ from the requested RPI. It
refuses a reply (`ErrProtocol`, and closes the connection again with
Forward_Close) whose T->O interval is 0 or whose O->T interval is below
max(O->T RPI / 4, min(RPI, 100 µs)), and in the same way a reply whose
O->T connection ID is 0. O->T data of a point-to-point connection goes to
the target's address, at the port of the reply's Sockaddr Info O->T item
when it has one; another address in that item is ignored.

The two floors on the O->T interval are `IOConfig` fields. `OTAPIDivisor`
(default 4) bounds how much more often than asked the scanner produces: the
floor is the O->T RPI divided by it. `MinOTAPI` (default 100 µs, or the RPI
when that is shorter) bounds the rate of production whatever the RPI.
Zero keeps the default, a positive value replaces it, a negative value
disables that floor; an O->T interval of 0 is refused in any case.

## Timeouts and recovery

The consumer of each direction times out after RPI × 4 << multiplier
(`TimeoutMultiplier`, default 0: four RPIs). Without `Reconnect` the IO
ends (`Done` closes, `Err` matches `ErrTimeout`); with `Reconnect` the
scanner closes the old connection and sends Forward_Open again with
backoff, keeping `SetOutput`, `Input` and the callbacks. The backoff has
equal jitter: before each attempt the scanner waits a delay drawn at
random from [d/2, d], where d starts at `MinDelay` (100 ms) and doubles
after each failed attempt up to `MaxDelay` (10 s), so that scanners that
lose a target at the same moment do not retry in step.

`OnState` runs on the goroutine that changes the state: the caller of
`Open`, the connection's own goroutines (timeout, reopening) or the
caller of `Close`. It must not block; it may call the methods of the `IO`
and of its `Scanner`, `Close` included, with or without `Reconnect`. A
`Close` called from `OnState` returns without waiting for the goroutine
it runs on. Once the connection is closed, its own goroutines report no
further state.

`OnInput` (the endpoint's `OnData`) and `implicit.Config.Produce` may
call `Close` too: `IO.Close`, `Scanner.Close` (which closes the scanner's
own endpoint), `Connection.Close` and `Endpoint.Close` return without
waiting for the goroutine they are called on, which ends when the
callback returns, and wait for the other goroutines; what a `Produce`
call that called `Close` returns is not sent. A `Close` on another
goroutine waits for an `OnData`, `OnInput` or `Produce` call in progress.
A callback that does not return normally is logged at Error level with
its stack: a `Produce` call sends nothing at that interval, the next one
is called at the next; after `OnData` or `OnInput` the endpoint goes on
with the next datagram; after `OnState` the state change stands.

## Sequence numbers

Every datagram has an encapsulation sequence number, incremented each
time; Class 1 adds a sequence count, incremented when the data (or
run/idle) changes. Consumers drop datagrams with an older encapsulation
number (duplicates, reordering) and deliver data only when the sequence
count is newer. The chaos tests drop, duplicate and reorder datagrams and
check that no older value is ever delivered.

## Server side

A `server.Server` serves I/O connections to its assemblies. The output
assembly gets the consumed data (`Assembly.OnWrite`, `Data`, `Run`);
`SetData` on an input assembly changes what is produced (and triggers
change-of-state connections). Multicast productions are shared by every
connection to the same input, at the CIP default multicast addresses of the
server's IP (TCP/IP Interface attribute 9).
