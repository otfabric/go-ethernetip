# Public API

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/otfabric/go-ethernetip).
This page lists the entry points with their concurrency, ownership and
timeout rules.

## Conventions

- **Contexts**: every network call takes a `context.Context`. Request
  waits end at the earlier of the context's deadline and the client's
  `WithTimeout` (5 s by default). A cancelled context returns
  `context.Canceled`; a deadline returns an error matching
  `ethernetip.ErrTimeout`.
- **Concurrency**: `client.Client`, `client.Conn`, `scanner.Scanner`,
  `scanner.IO`, `server.Server`, `server.Assembly`, `server.StandardObject`,
  `implicit.Endpoint`, `implicit.Connection`, `logix.Client` and
  `logix.TagServer` are safe for concurrent use. Codec values (`cip.Request`,
  `cip.Path`, ...) are plain values.
- **Callbacks** (`OnWrite`, `OnInput`, `OnData`, `OnState`, metrics, state
  handlers) run on library goroutines: they must not block, and slices
  passed to them are valid only during the call.
- **Ownership**: byte slices returned by decoders alias their input unless
  documented otherwise; values returned by clients (`Response.Data`,
  attribute values) are owned by the caller.
- **Closing**: everything with a `Close` must be closed; `Close` is
  idempotent.

## Root package `ethernetip`

| Symbol | |
|---|---|
| `ErrClosed`, `ErrNotConnected`, `ErrConnectFailed`, `ErrConnectionLost`, `ErrTimeout`, `ErrProtocol`, `ErrSession`, `ErrBusy`, `ErrUnsupported`, `ErrInvalidOption` | sentinels ([ERRORS.md](ERRORS.md)) |
| `CIPError`, `EncapError`, `StatusOf` | the peer's answers |
| `Logger`, `FieldLogger`, `ContextLogger`, `NopLogger`, `NewStdLogger`, `NewSlogLogger`, `NewSlogFieldLogger` | logging ([OBSERVABILITY.md](OBSERVABILITY.md)) |
| `Metrics`, `NopMetrics`, `RequestMetrics`, `ServerMetrics`, `IOMetrics`, `ConnectionInfo` | metrics |
| `State` | disconnected, connecting, connected, timed-out |

## `client`

| Symbol | |
|---|---|
| `New(addr, opts...)`, `Dial(ctx, addr, opts...)` | a client of a target (port 44818, 2221 with TLS) |
| `WithTimeout`, `WithRoute`, `WithMaxPending`, `WithMaxPacket`, `WithAutoReconnect`, `WithOriginator`, `WithTLS`, `WithDialer`, `WithLogger`, `WithMetrics`, `WithStateHandler` | options |
| `Client.Connect`, `Close`, `State`, `Session`, `Addr`, `RemoteAddr`, `LocalAddr` | session |
| `Client.Do`, `DoRoute` | any explicit request (`cip.Request` → `cip.Response`) |
| `GetAttributeSingle`, `SetAttributeSingle`, `GetAttributesAll`, `SetAttributesAll`, `GetAttributeList`, `Reset`, `Identity`, `MultipleService`, `ResponseError` | services |
| `ListIdentity`, `ListServices`, `ListInterfaces` | over the session |
| `ForwardOpen`, `ForwardClose`, `NewTriad`, `NewConnectionID` | Connection Manager |
| `OpenConnection(ctx, ConnectionOptions)` → `*Conn` | Class 3; `Conn.Do`, the same service helpers, `Info`, `Close` |
| `Doer` | `Do(ctx, cip.Request)`: `*Client` and `*Conn` |
| `Discover(ctx, DiscoverOptions)`, `ListIdentity(ctx, addr)`, `Device` | UDP discovery |

## `scanner`

| Symbol | |
|---|---|
| `New(client, opts...)` with `WithLocalAddr`, `WithEndpoint`, `WithLogger` | a scanner of the client's target |
| `Scanner.Open(ctx, IOConfig)` → `*IO`; `Scanner.Close(ctx)`, `Endpoint` | I/O connections |
| `IOConfig` | instances, sizes, RPIs, formats, class 0, multicast, timeout multiplier, large, key, `Reconnect`, `OnInput`, `OnState` |
| `IO.SetOutput`, `SetRun`, `Input`, `State`, `Err`, `Done`, `Info`, `Stats`, `Close` | one connection |

## `server`

| Symbol | |
|---|---|
| `New(opts...)` | a target with the standard objects |
| `WithIdentity`, `WithIOAddress`, `WithSlot`, `WithMaxSessions`, `WithMaxConnections`, `WithMaxPacket`, `WithInactivityTimeout`, `WithRPIRange`, `WithRunIdleHeader`, `WithDiscoveryDelay`, `WithInterface`, `WithResetHandler`, `WithTLS`, `WithLogger`, `WithMetrics` | options |
| `ListenAndServe`, `Listen` + `Serve`, `UseListeners`, `Close`, `Addr`, `UDPAddr`, `IOAddr` | lifecycle |
| `AddAssembly` → `*Assembly` (`SetData`, `Data`, `Run`, `OnWrite`, `Size`, `Kind`, `Instance`); `Assembly(instance)` | assemblies |
| `RegisterObject`, `Object`, `Classes`, `HandleSymbols`, `Identity`, `SetIdentityStatus`, `Sessions`, `Connections` | objects and state |
| `Object`, `SymbolHandler`, `Request`, `NewObject` → `*StandardObject` (`AddInstance`, `RemoveInstance`, `Instance`, `SetClassAttribute`, `HandleService`), `Instance.SetAttribute`, `Attribute`, `ServiceFunc` | the object model ([docs/OBJECTS.md](docs/OBJECTS.md)) |

## `logix` (vendor specific)

`NewClient(doer, WithMaxData)` with `Read`, `Write`, `WriteBit`,
`ReadMany`, `ListTags`, `Template`, `DecodeStruct`, `ProgramName`;
`ParseTag`; `Value` (`Int`, `Uint`, `Float`, `Bool`, `Text`) with `Ints`,
`Floats`, `Strings`; `Template`, `Member`, `Field`, `SymbolType`;
`NewTagServer(WithProgramName, WithMaxReply)` with `AddTag`,
`AddStructTag`, `AddTemplate`, `Get`, `Set`, `OnWrite`, `Attach`. See
[docs/LOGIX.md](docs/LOGIX.md).

## `eds`

`Parse`, `ParseString`, `File` (`Section`, `Device`, `Params`,
`Assemblies`, `Connections`, `Format`), `Validate`, `Issue`, `Build`,
`Spec`, `GenerateGo`, `GenerateOptions`, `ParseEPATH`, `FormatEPATH`. See
[docs/EDS.md](docs/EDS.md).

## Codecs: `cip`, `encap`, `implicit`

`cip`: `Reader` and `Append*`, `Path` and its segments, `ParsePath`,
`ParseRoute`, `Request`, `Response`, `EncodeMultipleService`,
`SplitMultiple`, `ForwardOpen`, `ForwardOpenReply`, `ConnectionFailure`,
`ForwardClose`, `UnconnectedSend`, `NetworkParams`, `TransportTrigger`,
`Ticks`, `ConnectionTimeout`, `Identity`, and the generated catalog
(`Class...`, `Service...`, `Status...`, `ConnStatus...`, `Type...`,
`DeviceType...`, `VendorName`).

`encap`: `Header`, `Packet`, `Decode`, `ReadPacket`, `Command`, `Status`,
`Item` and `AppendCPF`/`DecodeCPF`, `RRData`, `Register`, `Sockaddr`,
`IdentityItem`, `ServiceItem`, `SequencedAddress`, `ConnectedAddress`.

`implicit`: `Message`, `Decode`, `Payload`, `AppendPayload`, `SplitPayload`,
`Format`, `SeqNewer`; `Listen`/`NewEndpoint` → `*Endpoint` (`Open` →
`*Connection`, `LocalAddr`, `Close`); `Config`, `Stats`.

## Stability

The API is v0: it may change in minor versions until v1.0.0, with every
change in [RELEASE.md](RELEASE.md).
