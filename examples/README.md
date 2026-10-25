# Examples

Runnable programs. The first four start both sides in one process and exit
by themselves (`make examples` runs them); the others talk to real devices.

| Example | What it shows |
|---------|---------------|
| [quickstart](quickstart) | adapter and client: identity, attributes, Multiple Service Packet, Class 3 |
| [io](io) | Class 1 I/O between a scanner and an adapter |
| [logix](logix) | Logix tag list, reads and writes against the emulation (or a controller, read-only) |
| [eds](eds) | parse, validate and generate Go from an EDS file |
| [adapter](adapter) | a standalone adapter with OpENer's sample layout |
| [scanner](scanner) | a standalone scanner for that layout |
| [discover](discover) | ListIdentity to a broadcast address |

```sh
go run ./examples/quickstart
```
