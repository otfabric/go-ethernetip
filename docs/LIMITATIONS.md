# Known limitations

| Area | Limitation | Why |
|---|---|---|
| CIP Security | TLS transport only; no DTLS, no security objects | no DTLS in the standard library; Volume 8 not available; no reference peer |
| Routing | the server answers only routes to its own slot (port 1, `WithSlot`); no bridging | a gateway is out of scope |
| Connections | no Class 2, no redundant owner, scheduled priority not enforced, application-triggered I/O not produced on demand (change of state is) | no reference exercises them |
| Connection Manager | no Get_Connection_Data, Search_Connection_Data, Get_Connection_Owner | diagnostic services, not needed by originators |
| Objects | no Parameter, File, QoS, DLR, LLDP, Time Sync objects on the server | out of the first release's scope; add them as `server.Object` |
| I/O | one scanner per host on UDP 2222 (unless targets honour a Sockaddr Info item); originator and target must reach each other without NAT | the protocol sends I/O to the originator's address at 2222 |
| I/O security | the server filters O->T datagrams by source address only; a host on the same network that spoofs the originator can inject data | EtherNet/IP I/O is unauthenticated without DTLS |
| Class 1 delivery | `OnData` may be called once more while `Close` runs | a callback lock would deadlock callbacks that call `Close` |
| Multicast | needs `IP_ADD_MEMBERSHIP` (Unix, Windows); TTL is the system default | stdlib only |
| ListIdentity over UDP | the server's reply delay applies only when `WithDiscoveryDelay` is set | without IP_PKTINFO the server cannot tell broadcast from unicast |
| Logix emulation | tags and templates only: no programs, tasks, modes, alarms, access control; templates are what you give it | a test tool |
| Logix client | no CIP Generic MSG, no alarm/event, no program-scoped tag write by instance | not needed for tag access |
| EDS | the connection bit masks are exposed raw, not interpreted; generated scanner configurations use the default real-time formats | the EDS specification is not available |
| Conformance | not ODVA conformance tested | see [STANDARDS.md](STANDARDS.md) |
