# Rockwell Logix tag services

These services are **vendor-specific extensions** of CIP implemented by
Rockwell Automation Logix controllers (ControlLogix, CompactLogix,
GuardLogix) and compatible devices. Generic EtherNet/IP devices do not have
them. They live in package `logix`, apart from the CIP packages.

## Client

`logix.NewClient(doer)` works over a `*client.Client` (unconnected; usually
`WithRoute(cip.ParseRoute("1/0"))` to reach slot 0) or a `*client.Conn`
(Class 3, `ConnectionOptions{Large: true}` with `WithMaxData(3900)`, as
Logix programming tools do).

| Method | Service |
|---|---|
| `Read(ctx, tag, count)` | Read Tag 0x4C, then Read Tag Fragmented 0x52 while the controller answers partial transfer |
| `Write(ctx, tag, value)` | Write Tag 0x4D, or Write Tag Fragmented 0x53 above the maximum data |
| `WriteBit(ctx, "Flags.3", size, set)` | Read-Modify-Write 0x4E |
| `ReadMany(ctx, tags)` | Read Tag in Multiple Service Packets |
| `ListTags(ctx, program)` | Get Instance Attribute List 0x55 on the Symbol object, with continuation |
| `Template(ctx, id)`, `DecodeStruct(ctx, id, value)` | Template object attributes and Read Template; UDT decoding |
| `ProgramName(ctx)` | Program Name object 0x64 |

Tag names: `Tag`, `Program:Main.Tag`, `Tag[3]`, `Tag[1,2]`,
`Tag.Member[2].Sub`, and `Tag.5` for bit 5 (`WriteBit`). Values:
`logix.Ints(cip.TypeDINT, 1, 2)`, `logix.Floats(cip.TypeREAL, 1.5)`,
`logix.Strings("text")` (the predefined STRING structure); read back with
`Int`, `Uint`, `Float`, `Bool`, `Text`. BOOL arrays are DWORDs.

## Emulation

`logix.NewTagServer()` holds tags (`AddTag`, `AddStructTag`,
`AddTemplate`, `Set`, `Get`, `OnWrite`) and `Attach(srv)` serves them:
symbolic and instance addressing, fragmentation on element boundaries,
Read-Modify-Write, the tag list with continuation, templates, the program
name. pycomm3's `LogixDriver` and cpppo's client work against it (see the
interop matrix). Write Tag ignores octets after the data, as controllers
do: pycomm3 1.2.16 sends its write requests twice in one message.

It is a test tool: no programs, tasks, modes, alarms or access control.
