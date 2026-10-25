# Independent stacks: what they send and accept

Research notes from reading the sources of the four interoperability
references (no code of theirs is copied into this module). They drive the
server's tolerance rules and the interop adapters in
[otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop).

## EIPScanner 1.3.0 (+33, C++, MIT, (c) 2019 Aleksey Timin)

- Builds on Debian trixie, g++ 14, CMake (`-DCMAKE_POLICY_VERSION_MINIMUM=3.5`
  on CMake 4). Libraries `EIPScanner` (shared) and `EIPScannerS` (static);
  headers rooted at `include/EIPScanner`.
- Explicit messaging: always SendRRData, Null Address + Unconnected Data; never
  Unconnected_Send. `EPath` packs **16-bit logical segments** by default
  (`21 00 lo hi`), 8-bit with `MessageRouter(true)`: a target must accept both.
- No Multiple Service helper (build it by hand), no symbolic segments, no
  routing.
- Discovery: ListIdentity datagram to a configurable address and port
  (unicast works); replies capped at 504 octets.
- `IdentityObject` always sends Get_Attributes_All to `@1/1`.
- Forward_Open 0x54 / Large_Forward_Open 0x5B to `@6/1`; NCP size is the
  application size: the library adds 2 (sequence count) and 4 (32-bit header
  when the real-time format flag is set).
- **No Class 3 connected explicit messaging**, no SendUnitData. **No
  multicast**. Class 0/1 point-to-point only.
- I/O: binds **INADDR_ANY:2222** (hard-coded) after the first Forward_Open; it
  sends no T->O sockaddr item, so the target sends T->O to the originator's IP
  at 2222. O->T goes **from an ephemeral port** to the O->T sockaddr item of the
  reply if present (0.0.0.0 replaced by the session host), else host:2222. A
  target must not filter on the source port.
- O->T: sequenced address (32-bit sequence incremented per send), CIP sequence
  count incremented on **every** packet, run/idle header always Run.
- T->O parse order bug: reads the 32-bit header before the sequence count; use
  modeless T->O (no header), the usual format.
- Timeout multiplier >= 6 overflows to 0 in the library: use 0..5.
- Connection paths must have even length. Forward_Close sends tick/timeout 0/0.
- A T->O datagram whose size differs from the NCP size is dropped with a log
  line; a non-zero encapsulation status throws.

## pycomm3 1.2.16 (Python, MIT, (c) 2020 Ian Ottoway)

- `open()`: RegisterSession (v1, options 0). Forward_Open happens lazily:
  Large_Forward_Open 0x5B first (size 4000, NCP `0x42000FA0`), on any failure
  Forward_Open 0x54 (size 500, NCP `0x43F4`); tick 0x0A, ticks 0x05, multiplier
  7, RPI 0x00204001, transport 0xA3, path `[route] 20 02 24 01`
  (LogixDriver: `01 00 20 02 24 01`). Only the O->T connection ID of the reply
  is used.
- Connected: SendUnitData with exactly A1 (4) + B1 (UINT sequence + CIP);
  replies parsed at **fixed offsets**: the reply must carry exactly these two
  items, in this order, address length 4.
- Unconnected: SendRRData, Null + B2, timeout 10. Reply parsed at fixed
  offsets; data taken at status+2 (successful replies must have extended
  status size 0).
- `generic_message(connected=False, unconnected_send=False)` with the default
  `route_path=True` **appends the route** (`00 00`, or `01 00 01 00`) after the
  request data: a server sees 2..4 trailing octets.
- `unconnected_send=True`: Unconnected_Send to `@6/1`, `0A 05 <len> <msg>
  [pad] <size> 00 <route>`; reply expected to be the embedded reply.
- `list_identity()`: ListIdentity over **TCP**. `discover()`: UDP to
  `(addr, 44818)`; unicast works.
- LogixDriver `open()`: TCP ListIdentity; Unconnected_Send (route `01 00`) of
  Get_Attributes_All `@1/1`; connected Get_Attributes_All on **class 0x64
  instance 1** (program name, STRING: UINT length + chars) — `open()` raises if
  it fails; with `init_tags`, 0x55 on class 0x6B (attributes 1,2,3,5,6,8[,10]
  for major revision >= 18) with 0x06 continuation, templates via 0x03 and 0x4C
  on 0x6C. Revision major >= 21 switches to instance addressing
  (`20 6B 25 00 <id>`) for tags from the list.
- `read()` / `write()` need the tag definition (`init_tags=True` or injected
  `_tags`); otherwise "Tag doesn't exist" without sending.
- Read Tag 0x4C, Read Fragmented 0x52 (status 0x06 until the last), Write
  0x4D, Write Fragmented 0x53, Read-Modify-Write 0x4E for bits (AND mask always
  sent with 8 octets: read N of each, ignore the rest), Multiple Service Packet
  0x0A to `@2/1` for several tags (a top-level 0x1E is accepted).
- 32-bit logical segments use format bits 11 (0x23...) — only for ids > 65535.
- Logix STRING = struct (`A0 02 <handle>`, DINT LEN + 82 SINT, size 88,
  template `ASCIISTRING82`, handle usually 0x0FCE).

## OpENer master (v2.3-588, C, adapted BSD, (c) 2009 Rockwell Automation)

- Licence adds: products implementing EtherNet/IP need ODVA's Terms of Usage.
- Build: `cmake -DOpENer_PLATFORM=POSIX -DBUILD_SHARED_LIBS=OFF source`;
  Debian `build-essential cmake libcap-dev` (runtime `libcap2`). Binary
  `src/ports/POSIX/OpENer`, one argument: the interface name (`eth0`); it
  waits for an IPv4 address, reads gateway from `/proc/net/route` and DNS from
  `/etc/resolv.conf` (else IP stays 0). NV data under `./nvdata/`.
- Identity: vendor 1, device type 12, product code 65001, revision 2.3,
  serial 123456789, name "OpENer PC".
- Objects: Identity (attrs 1-7; GAS, GAA, Reset types 0/1, Get/Set_Attribute_List;
  no Set_Attribute_Single), Message Router (instance without attributes),
  Assembly (attr 3 r/w, 4 r; GAS/SAS only), Connection Manager (GAS, GAA,
  0x54, 0x5B, 0x4E, 0x56, 0x57; 0x5A never replies), TCP/IP rev 4 (attrs 1-13),
  Ethernet Link (attrs 1-11, GetAndClear 0x4C), QoS 0x48. Unknown class or
  instance -> 0x05; unknown service -> 0x08.
- **No Unconnected_Send (0x08), no Multiple Service Packet (0x08)**.
- Sample app assemblies: input 100 (32 B), output 150 (32 B), config 151
  (10 B), heartbeat input-only 152, listen-only 153, explicit 154 (32 B).
  Exclusive owner `20 04 24 97 2C 96 2C 64` [+ `80 05 <10 B>`]; input only O->T
  152; listen only O->T 153. Output 150 is copied to input 100. Sizes: O->T
  38 (32+2+4), T->O 34 (32+2, modeless); wrong size -> 0x0127/0x0128.
- Class 3 path must be exactly `20 02 24 01` (else 0x0315). Max 6 explicit,
  1 exclusive owner, 3 input-only, 3 listen-only connections, 20 sessions.
- RPI not checked; production rounded up to 10 ms. Timeout = O->T RPI(ms) <<
  (2 + multiplier); first timeout at least 10 s.
- T->O multicast supported (originator on same subnet, else 0x01/0x081B);
  listen-only needs a multicast producer (0x0119). O->T multicast broken.
- O->T: 32-bit run/idle header expected; encapsulation sequence must increase
  (SEQ_GT32); CIP sequence starting at 0 — a first packet with sequence 0 is
  dropped; source IP must match the originator (port not checked). T->O sent
  to the TCP peer's IP at 2222 (or the T->O sockaddr item): **scanner and
  OpENer must be on the same Docker network, no NAT**.
- Electronic key format 4 only; zero fields are wildcards.
- Encapsulation: TCP NOP (no reply), ListServices ("Communications", v1, flags
  0x0120), ListIdentity, ListInterfaces (0 items), Register/UnRegister,
  SendRRData, SendUnitData. UDP: ListServices/ListIdentity/ListInterfaces.
  Broadcast ListIdentity replies delayed randomly up to MaxResponseDelay from
  the sender context (default 2000 ms); unicast immediate. Session handles
  1..20; registering twice on a socket -> status 0x01; non-zero options ->
  dropped silently; idle TCP closes after 120 s; explicit size 512 B max.
- Class 3: first request with sequence 0 is treated as a duplicate: start at 1.

## cpppo 5.2.5 (Python, GPL-3.0, Dominion Research & Development)

- `pip install cpppo==5.2.5` (core imports only `greenery<3`); runs on Python
  3.12-3.14. Its own Dockerfile is Python 2: do not reuse.
- Server: `python -m cpppo.server.enip -a 0.0.0.0:44818 [--no-config -c f.cfg]
  [-S | --route-path 1/0] TAG...`; tags `Name=TYPE[n]` (BOOL SINT USINT INT UINT
  DINT UDINT LINT ULINT REAL LREAL SSTRING STRING), explicit CIP address
  `Name@cls/ins/att=TYPE[n]` (e.g. `IN@0x04/100/3=SINT[32]`). Identity via INI
  `[Identity]` (Vendor Number, Device Type, Product Code Number, Product Revision
  as one 16-bit value, Status Word, Serial Number, Product Name, State). Use
  `--no-config -c` for determinism. Defaults: 1756-L61, vendor 1, type 14, code 54.
- Supports: Register/UnRegister, ListServices (flags 0x20), ListInterfaces (0),
  ListIdentity TCP+UDP, SendRRData, SendUnitData; Read Tag 0x4C, Write 0x4D,
  Read Fragmented 0x52 (only inside Unconnected_Send or connected — a bare 0x52
  in SendRRData is parsed as Unconnected_Send), Write Fragmented 0x53, GAA, GAL
  0x03, GAS, SAS (data must be exactly the attribute size), MSP 0x0A,
  Forward_Open/Large/Close, Unconnected_Send. Class 3 yes; Class 1 no.
- Not supported: Read-Modify-Write, 0x55 tag list, templates 0x6C, Reset,
  32-bit logical segments, electronic key (Forward_Open with 0x34 -> 0x08), bit
  addressing, UDT members. Multi-dimensional index silently reduced.
- Errors: out of range -> 0xFF / 0x2105; wrong type -> 0xFF / 0x2107; GAS/SAS
  unknown attribute -> 0x08; **unknown tag / class / unsupported service: an
  encapsulation header with status 0x08 and the TCP session is closed** (not a
  CIP error). Read > ~488 B -> 0x06.
- Quirks: ListIdentity reports port 44818 always and the IP of its config
  (0.0.0.0 with `--no-config`); SendUnitData replies carry the O->T ID (not
  T->O) in item 0xA1; Forward_Open echoes the proposed T->O ID; tag names are
  case-insensitive.
- Clients: `python -m cpppo.server.enip.client -a host [-i ListIdentity] [-s
  ListServices] [-u UDP] [-S] [-c connected] [-m MSP] Tag[0-3]=(DINT)1,2
  @cls/ins/att`; `python -m cpppo.server.enip.get_attribute '@1/1/7'
  '@4/100/3=(SINT)1,2'`; importable as a Python API (`client.connector`), the
  basis of our cpppo client adapter.
