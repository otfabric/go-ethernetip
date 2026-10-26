# Explicit messaging

## Unconnected

`Client.Do(ctx, cip.Request{...})` sends a request in SendRRData to the
target's Message Router and returns the response. Helpers cover the common
services:

| Method | Service |
|---|---|
| `GetAttributeSingle(ctx, class, instance, attribute)` | 0x0E |
| `SetAttributeSingle(ctx, class, instance, attribute, value)` | 0x10 |
| `GetAttributesAll(ctx, class, instance)` | 0x01 |
| `SetAttributesAll(ctx, class, instance, data)` | 0x02 |
| `GetAttributeList(ctx, class, instance, ids, sizes)` | 0x03 |
| `Reset(ctx, class, instance, type)` | 0x05 |
| `Identity(ctx)` | 0x01 on @1/1, decoded |
| `MultipleService(ctx, reqs)` | 0x0A on @2/1 |

Paths: `cip.AttributePath(cip.ClassIdentity, 1, 7)`, `cip.ObjectPath(...)`,
or `cip.ParsePath("@1/1/7")` / `cip.ParsePath("20 01 24 01 30 07")`.
Object-specific services take their code (`cip.Service(0x4B)`) and data.

A status other than success comes back as the response *and* a
`*ethernetip.CIPError`.

## Routing

A target behind a gateway (a ControlLogix chassis behind its EtherNet/IP
module) is reached with a route path: `client.WithRoute(r)` sends every
unconnected request as Unconnected_Send with that route, and prefixes the
connection path of every Forward_Open. `cip.ParseRoute("1/0")` is port 1
(backplane), slot 0; `"1/0,2/192.168.2.20"` goes on through port 2 to a
node by its address. `DoRoute` overrides the route for one request.

## Connected (Class 3)

`Client.OpenConnection(ctx, client.ConnectionOptions{...})` opens a Class 3
connection to the Message Router with Forward_Open (`Large: true` for sizes
above 511 octets, Large_Forward_Open). The returned `*client.Conn` has the
same helpers; requests go in SendUnitData with a sequence count, one at a
time. The target closes the connection after `Timeout` without a request
(default 60 s): send something periodically or reopen it. `Conn.Close`
sends Forward_Close.

## Several requests in flight

`client.WithMaxPending(n)` lets n unconnected requests of different
goroutines be outstanding on the session; replies are matched by sender
context. Most targets handle requests one at a time in order, which still
saves the round trips of the network.

## Discovery

`client.Discover` sends exactly one ListIdentity datagram (to a broadcast
address or one device) and collects replies until `Wait`. `MaxDelay` asks
devices to spread their replies. `client.ListIdentity(ctx, addr)` asks one
device. `Client.ListIdentity`, `ListServices`, `ListInterfaces` ask over the
session's TCP connection.
