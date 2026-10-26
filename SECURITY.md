# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-ethernetip`, please report
it responsibly. **Do not open a public GitHub issue for security
vulnerabilities.** Email **security@otfabric.io**, or open a private
advisory on GitHub (the [Security](https://github.com/otfabric/go-ethernetip/security)
tab → **Advisories** → **Report a vulnerability**), with a description, the
steps to reproduce (ideally a minimal program or test), the affected
versions and the impact you see.

We acknowledge reports within 48 hours and aim to provide a fix or
mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Security Considerations

### EtherNet/IP without protection

Plain EtherNet/IP has no authentication and no encryption. Anyone who can
reach a target on TCP 44818 can read and write its attributes and open I/O
connections that drive outputs; anyone who can send UDP datagrams to port
2222 from the originator's address with a fresher sequence number can
replace output data; anyone on the path can read and alter the traffic.

- **Keep EtherNet/IP on isolated, trusted networks** (cell/area zones);
  never expose 44818 or 2222 to the Internet.
- **Use EtherNet/IP over TLS** for explicit messaging across untrusted
  networks (`client.WithTLS`, `server.WithTLS`, port 2221), or a VPN.
  I/O (UDP) has no protection in this library: DTLS is not implemented.
- The server checks the source **address** of O->T datagrams (not the
  port: originators send from any port). That stops other hosts, not
  spoofing on the same network.

### TLS

`WithTLS` takes a standard `*tls.Config`, used as given. Set `MinVersion`
to TLS 1.2 or later; for mutual authentication set `ClientAuth:
tls.RequireAndVerifyClientCert` with `ClientCAs` on the server and
`Certificates` on the client. This is the TLS transport of CIP Security;
the CIP Security objects (0x5D, 0x5E, 0x5F) and their configuration are not
implemented, and the library makes no CIP Security conformance claim.

### Writes and resets

The library sends what it is asked to; it has no notion of a safe write.
Applications and tools should confirm writes, resets and I/O connections
that drive outputs (ethernetipctl requires `--yes`). An exclusive owner
connection replaces the outputs of the device: open one only where you own
the process.

### Resource limits

The server bounds what a peer can make it hold:

- packets above `WithMaxPacket` (4096 octets by default) close the
  session; sessions are limited by `WithMaxSessions` (64), connections by
  `WithMaxConnections` (128); idle TCP connections close after the
  encapsulation inactivity timeout (120 s);
- every count in a message (items, services, segments, attributes, tag
  list entries) is checked against the octets that carry it before memory
  is allocated, and bounded; the fuzz targets check this, and found two
  defects fixed before the first release (a crash on a malformed Multiple
  Service Packet, unbounded recursion in a self-referencing Logix
  template);
- replies are written with a deadline, so a peer that stops reading loses
  its session instead of blocking the server;
- I/O datagrams from other addresses, of the wrong size, with old
  sequence numbers or unknown connection IDs are dropped (and counted).

### Dependencies

`go-ethernetip` has **no dependencies** outside the Go standard library.
`make vuln` runs govulncheck; CI runs it on every push.
