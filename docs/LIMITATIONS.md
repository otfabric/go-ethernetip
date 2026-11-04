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
| ListIdentity over UDP | the server's reply delay applies only when `WithDiscoveryDelay` is set; at most 256 delayed replies wait at once, later requests go unanswered | without IP_PKTINFO the server cannot tell broadcast from unicast; the bound keeps a request flood from piling up timers |
| Server limits | at most 2 × `WithMaxSessions` + 16 TCP connections, registered or not; `WithMaxConnections` at most 65535; one originator address may hold them all unless `WithMaxConnectionsPerOriginator` is set (originators behind one NAT address share that limit); Class 3 replies are bounded by the connection's T->O size and a Class 3 request larger than its O->T size is still served; the class attributes Max Instance and Number of Instances, and the Message Router's class list, saturate at 0xFFFF | unregistered connections must be bounded too; those attributes are UINTs while instance IDs are 32-bit |
| Logix emulation | tags and templates only: no programs, tasks, modes, alarms, access control; templates are what you give it, with at most 65535 members | a test tool; the member count attribute is a UINT |
| Logix client | no CIP Generic MSG, no alarm/event, no program-scoped tag write by instance; a fragmented read stops at 16 MiB or 65536 fragments, a write above 16 MiB is refused, a template definition above 1 MiB is refused | not needed for tag access; replies are untrusted input |
| EDS | the connection bit masks are exposed raw, not interpreted; generated scanner configurations use the default real-time formats | the EDS specification is not available |
| EDS sizes | an assembly member above `8*eds.MaxAssemblySize` bits (524280) is rejected, and `GenerateGo` writes no struct for an assembly whose members add up to more than `eds.MaxAssemblySize` octets | the assembly size field is 16 bits; EDS files are untrusted input |
| Conformance | not ODVA conformance tested | see [STANDARDS.md](STANDARDS.md) |
