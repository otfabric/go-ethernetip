# The CIP object model on the server

A `server.Server` routes every explicit request to an `Object` by the
class of its path. The standard objects are registered by `server.New`:
Identity (0x01), Message Router (0x02), Assembly (0x04), Connection Manager
(0x06), Port (0xF4), TCP/IP Interface (0xF5), Ethernet Link (0xF6). See
[INTEROPERABILITY.md](../INTEROPERABILITY.md#objects-server) for their
attributes and services.

## Your own objects

`server.NewObject(class, revision)` builds a `*server.StandardObject`:

```go
o := server.NewObject(0x64, 1)
in := o.AddInstance(1)
var speed uint16
in.SetAttribute(1, server.Attribute{
    Get: func() []byte { return cip.AppendUint16(nil, speed) },
    Set: func(d []byte) cip.GeneralStatus {
        if len(d) != 2 { return cip.StatusNotEnoughData }
        speed = binary.LittleEndian.Uint16(d)
        return cip.StatusSuccess
    },
    InGetAll: true,
})
o.HandleService(0x4B, func(ctx context.Context, r *server.Request) cip.Response {
    return cip.Response{Data: []byte{1}}
})
srv.RegisterObject(o)
```

The class attributes 1, 2, 3, 6 and 7 are maintained;
Get_Attribute_Single, Set_Attribute_Single, Get_Attributes_All (attributes
with `InGetAll`, by ID) and Get_Attribute_List work on the attributes. The
attribute functions and services run on session goroutines, concurrently:
make them safe for concurrent use.

Anything else implements `server.Object` (`Class()`, `ServeCIP(ctx,
*server.Request) cip.Response`): `Request` carries the decoded instance,
attribute, the rest of the path, the originator's address and whether the
request came on a Class 3 connection. Requests whose path starts with a
symbol go to the `SymbolHandler` set with `HandleSymbols` (the Logix
emulation uses it).

## Assemblies

`AddAssembly(instance, kind, size)` with `AssemblyInput` (produced),
`AssemblyOutput` (consumed; one exclusive owner), `AssemblyConfig`
(Forward_Open configuration data), `AssemblyInputOnly` and
`AssemblyListenOnly` (heartbeat connection points of size 0). Attribute 3
is the data, settable for output and configuration assemblies unless an I/O
connection owns them (0x0C).
