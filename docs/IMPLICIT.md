# Implicit messaging (I/O)

An I/O connection carries a target's assembly data cyclically over UDP: the
originator (scanner) sends O->T (its outputs, the target's consumed data),
the target sends T->O (its inputs) at the requested packet interval (RPI).

```go
s, _ := scanner.New(c)              // binds UDP :2222
io, err := s.Open(ctx, scanner.IOConfig{
    ConfigInstance: 151,            // optional; ConfigData sends configuration
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
group the target returns in its Sockaddr Info item.

## Timeouts and recovery

The consumer of each direction times out after RPI × 4 << multiplier
(`TimeoutMultiplier`, default 0: four RPIs). Without `Reconnect` the IO
ends (`Done` closes, `Err` matches `ErrTimeout`); with `Reconnect` the
scanner closes the old connection and sends Forward_Open again with
backoff, keeping `SetOutput`, `Input` and the callbacks.

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
