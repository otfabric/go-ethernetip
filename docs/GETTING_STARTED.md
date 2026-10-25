# Getting started

```sh
go get github.com/otfabric/go-ethernetip
go run github.com/otfabric/go-ethernetip/examples/quickstart@latest
```

1. **Find devices**: `client.Discover(ctx, client.DiscoverOptions{Address:
   "192.168.1.255"})` sends one ListIdentity datagram to the subnet's
   broadcast address and returns who answered, with identity and address.
2. **Talk to one**: `client.Dial(ctx, "192.168.1.10")`, then
   `Identity`, `GetAttributeSingle`, `SetAttributeSingle`,
   `GetAttributesAll`, `MultipleService`, or `Do` with any `cip.Request`.
   See [EXPLICIT.md](EXPLICIT.md).
3. **Exchange I/O**: `scanner.New(client)` and `Open` with the assemblies
   of the device (from its EDS: [EDS.md](EDS.md)). See
   [IMPLICIT.md](IMPLICIT.md).
4. **Be a device**: `server.New`, `AddAssembly`, `ListenAndServe`. See
   [OBJECTS.md](OBJECTS.md).
5. **Logix controllers**: [LOGIX.md](LOGIX.md).

Every call takes a `context.Context`; set deadlines there or with
`client.WithTimeout`. Close what you open: `Client.Close`,
`Scanner.Close`, `IO.Close`, `Conn.Close`, `Server.Close`.

Ports: TCP 44818 (explicit messaging), UDP 44818 (ListIdentity), UDP 2222
(I/O), TCP 2221 (EtherNet/IP over TLS). A scanner binds UDP 2222 on the
host, where targets send their inputs; only one process per host can.
