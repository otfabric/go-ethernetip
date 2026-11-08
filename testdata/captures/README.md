# Recorded EtherNet/IP traffic of real devices

Network captures between real Rockwell devices (a 1756-L63 ControlLogix
controller behind its EtherNet/IP module, a 1756-ENBT/A) and Rockwell
software (RSLinx, RSLogix 5000, FactoryTalk), and captures of unidentified
targets. go-ethernetip's tests decode every recorded message, encode it
back, run the client against the recorded replies, run the Logix client's
template and bit-write requests against them, and send the recorded
requests to the server, comparing its answers with the devices'. This is
evidence from real devices, recorded by others: not a test against a live
device and not a conformance claim.

[manifest.json](manifest.json) is the machine-readable inventory (source,
revision, original path, URL, SHA256, size, recording date, evidence class,
devices, peers, operations, limitations, how the file is held);
[coverage.json](coverage.json) the machine-readable report of what each
recorded exchange verifies.

## Evidence classes

| Class | Meaning |
|---|---|
| A | physical-device traffic, the device identified by its own answers in the recording (Identity object or ListIdentity) |
| B | physical-device origin credibly documented, not verified from the traffic |
| C | recorded traffic of unknown device origin |
| D | simulated, generated or hand-crafted traffic |

Only A and B support a statement about real devices. C files are parser
and replay regression material.

## Sources, terms and what is committed

| Source | Revision | Terms | Here |
|---|---|---|---|
| [EmreEkin/ICS-Pcaps](https://github.com/EmreEkin/ICS-Pcaps), `Ethernet_IP/` | `0ffbf023afb4e39373228b54851bb4a1f33a3ab8` | no licence file, no statement on reuse | **excerpts only** |
| [cisagov/icsnpp-enip](https://github.com/cisagov/icsnpp-enip), `testing/traces/` | `3fbd32e3d2838d5e2bcd6c9ed79f036d23a0642e` | BSD-3-Clause, © 2023 Battelle Energy Alliance, LLC ([THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)) | raw, byte-identical |
| [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools), `pcaps/EthernetIP/` | `bcb93ee1cdf395a457cc08f639cf29aab5975f01` | CC-BY-4.0 (repository licence) | the small files raw, byte-identical; `EthernetIP-CIP.pcap` as an excerpt (its README names CloudShark capture 76038eaa4a3b as its source, whose terms are not stated) |
| [ICS Defense PCAP archive](https://icsdefense.net/en/pcap) | — | not stated | not used: its list is rendered in the browser, no EtherNet/IP file could be retrieved without it |

**Judgement to revisit:** public availability is not permission to
redistribute. Where no licence or publisher statement permits it, this
repository does not commit the raw file. It commits an *excerpt*
(`excerpts/<source>/<file>.json`): the encapsulation messages of the file,
without the Ethernet, IP and TCP headers, with repeated exchanges left
out (and for long recordings at most a few exchanges per request shape).
Each excerpt names the raw file's SHA256. The owner may decide that the
excerpts are not needed (and fetch the raw files in CI) or that the raw
files may be committed after all.

`make captures-fetch` downloads the raw files of the excerpts into
`.cache/` (git-ignored), checking SHA256 and size; `make captures-check`
fails when an excerpt is not what its raw file gives; `make
captures-extended` runs every capture test on the raw files instead of the
excerpts (build tag `captures`). Only `captures-fetch` uses the network;
`make test` reads only what is committed.

[SHA256SUMS](SHA256SUMS) covers every committed capture and excerpt
(`shasum -a 256 -c SHA256SUMS` in this directory).

## Devices

Read from the devices' own answers.

| Device | Identity | Seen in |
|---|---|---|
| 1756-L63/A ControlLogix controller, slot 0 | vendor 1, device type 0x0E, product code 56, revision 15.4, serial 0x0014CD8A, name "1756-L63/A L6x_15_31", status 0x3160 (download capture frame 222, through Unconnected_Send port 1 link 0) | `ControlLogix_Logix5000_download_upload_run`, `ControlLogix_FactoryTalk_HMI` (the same address, originator serial and status three minutes earlier) |
| its EtherNet/IP module, 10.92.18.17 | not read in the recording (no ListIdentity, no Identity of the module); ListServices "Communications", capabilities 0x0120 | the same |
| 1756-ENBT/A | vendor 1, device type 0x0C, product code 58, revision 4.3, serial 0x00524D8E, status 0x0030, state 3, 10.1.1.164 (ListIdentity reply) | `enip_cip_example` frame 372, `enip_test` frame 7 |

Originators: RSLinx for RSLogix 5000 and FactoryTalk (vendor 0x004D,
Rockwell Software; originator serials 0x11FA6145 and 0x21217FA7), a
Rockwell originator (vendor 1, serial 0x0013F522) opening a Class 1
connection, an HMI sending symbolic bit writes to four Logix-like targets.

## Files

Messages: encapsulation messages (one or more per frame) and I/O
datagrams, equal to what Wireshark 4.6 decodes (`tshark -Y enip -T fields
-e enip.command`, one per command; `-Y udp.port==2222` for I/O), except
ENIP_CIP-CM, see below.

| File | Class | Here | Messages | What it holds |
|---|:-:|---|---:|---|
| `ics-pcaps/ControlLogix_Logix5000_download_upload_run.pcap` | A | excerpt | 346 | RSLinx and the 1756-L63: command 0x0001, ListServices, ListInterfaces, RegisterSession; through Unconnected_Send the Identity object, its attributes 0x65/0x66, the Message Router's class list, Program Name; Class 3 Forward_Open/Forward_Close; connected Get_Attribute_List and Multiple Service Packets of Logix objects; class 0x0334 refused with 0x05 |
| `ics-pcaps/ControlLogix_FactoryTalk_HMI.pcap` | A | excerpt | 272 | FactoryTalk/RSLinx and the 1756-L63 on Class 3 connections (the capture starts inside the first): Template object (COUNTER, TIMER: Get_Attributes_All, Read Template), Read_Modify_Write_Tag by instance, Identity status, RSLinx-private class 0xB2 |
| `ics-pcaps/ENIP_CIP-CM.pcap` | C | excerpt | 21 | ListServices, RegisterSession, Class 1 Forward_Open (10 ms, O->T point-to-point, T->O multicast, Assembly 6/2/1) with Sockaddr Info items; frame 5 is a 1460-octet retransmission of 14 earlier Forward_Open requests (tshark, which does not dissect it, counts 8 messages) |
| `iti-ics-security-tools/EthernetIP-CIP.pcap` | C | excerpt | 8,799 | an HMI and four Logix-like targets: symbolic Read_Modify_Write_Tag in Multiple Service Packets, class 0xAC, class 0x72 |
| `icsnpp-enip/enip_cip_example.pcap` | A (ListIdentity), C (rest) | raw | 269 + 398 I/O | ListIdentity of the 1756-ENBT/A over TCP; Get_Attribute_List browsing of a Logix-like target; Set_Attribute_List of Time Sync; 398 Class 1 datagrams on 24 connections |
| `icsnpp-enip/multiple_service_packet_cip.pcapng` | C | raw | 1 | a Multiple Service Packet request (from enip_cip_example) |
| `icsnpp-enip/set_attribute_single_service_cip.pcapng` | C | raw | 1 | Set_Attribute_Single in an 802.1Q-tagged frame, nanosecond time stamps |
| `iti-ics-security-tools/cip-eth-set-2.pcap` | C | raw | 1 | a Set_Attribute_Single reply |
| `iti-ics-security-tools/cip-multiple-1.pcap`, `-2.pcap` | C | raw | 1 each | a Multiple Service Packet request and its reply |
| `iti-ics-security-tools/cip_start_plc.pcap`, `cip_stop_plc.pcap`, `cip_unlock_cpu.pcap` | C | raw | 1 each | Start, Stop and 0x4C to class 0x8E, without reply |
| `iti-ics-security-tools/enip_test.pcap` | A | raw | 2 | the 1756-ENBT/A's ListIdentity over TCP |

## Extraction

`internal/capture` reads classic pcap and pcapng (Ethernet, 802.1Q,
IPv4; microsecond and nanosecond time stamps), reassembles each TCP
direction in sequence order (retransmissions and overlaps dropped, each
byte credited to the earliest frame that carried it), splits the stream
into encapsulation messages, resynchronises after a gap or a mid-stream
start, and keeps UDP 44818 and UDP 2222 datagrams. It pairs a request with
its reply by command and sender context, or for SendUnitData by CIP
sequence count. It reads the header and the common packet format itself,
independently of package `encap`.

## Comparison rules

Fields a peer chooses itself are not compared byte for byte; everything
else is.

| Field | Rule |
|---|---|
| session handle | the target's: the replay uses the one granted |
| sender context, SendRRData timeout, CIP sequence count | the originator's: the client replay sends its own, the target answers with them |
| Forward_Open: O->T connection ID; T->O ID of a multicast connection | the target's: normalized; later requests use the replay's |
| Forward_Open / Forward_Close: triad, T->O ID of a point-to-point connection, priority/tick and timeout ticks | the originator's: normalized in the client replay |
| Sockaddr Info items of a Forward_Open reply, socket address of a ListIdentity reply | the server's sockets and configuration: normalized |

## How the tests use them

| Test | Checks |
|---|---|
| `internal/capture` | the reader's counts equal Wireshark's; pairing (same command and context, sequence count echoed); manifest, SHA256SUMS, excerpts and coverage.json consistent; with `-tags captures` the excerpts equal what the raw files give |
| `encap` `TestCapture*` | every message decodes, its header equals the independent reading, it and its CPF encode back to the recorded octets; ListIdentity of the 1756-ENBT/A, ListServices, ListInterfaces and RegisterSession decode to the recorded values; the SendRRData timeout is echoed by the recorded targets; every truncation and a length one too long are refused |
| `cip` `TestCapture*` | every request, response, Multiple Service Packet part, Unconnected_Send and its embedded request, Forward_Open, Forward_Close and their replies decode and encode back byte for byte; replies answer their requests part by part; the 1756-L63's identity; RSLinx's Class 3 and the Class 1 Forward_Open against Wireshark's decode; 16-bit segments kept; malformed variants refused |
| `implicit` `TestCaptureClass1IO` | 398 Class 1 datagrams decode and encode back; per connection the encapsulation sequence number advances by one and the sequence count never goes back |
| `client` `TestCaptureReplay*` | the client against the recorded replies, where a request no recorded originator sent fails the test: RegisterSession, ListServices, ListInterfaces, Identity and Get_Attribute_List through the route RSLinx uses, a Class 3 connection with RSLinx's parameters, a connected request and Forward_Close; ListIdentity of the 1756-ENBT/A; the Class 1 Forward_Open and its Sockaddr Info items |
| `logix` `TestCapture*` | the Logix client reads the 1756-L63's COUNTER and TIMER templates with RSLogix 5000's Read Template requests; `WriteBit` encodes every recorded bit write byte for byte and takes the replies; the emulation answers the recorded Multiple Service Packets of bit writes byte for byte |
| `server` `TestCapture*` | the recorded requests sent to the server (with the 1756-L63's or the 1756-ENBT/A's identity): every request it supports is answered as the device did, the known differences below are pinned; a Class 1 Forward_Open with the recorded assemblies; 300 seeded mutated streams of the recorded requests (cut, wrong lengths, flipped octets, duplicated, reordered) never stop the server |

## Known differences of the server

| Request | Device | Server | Why |
|---|---|---|---|
| encapsulation command 0x0001 | an item naming the module | status 0x0001, invalid command | the command is not public |
| Identity attributes 0x65, 0x66 | values | 0x14 per attribute | vendor-specific attributes |
| Message Router Get_Attributes_All | its 43 classes only | its own classes, then attributes 2 and 3 | the server's object list; the optional attributes |
| Rockwell-private and Logix objects (0x64, 0x68 to 0x8E, 0xAC, 0xB2) | values | 0x05 or 0x08 | the server does not hold them; the Logix emulation holds tags and templates only |
| Forward_Close of a connection opened before the capture | success | 0x01 / 0x0107 | its state is not in the recording |
| Template object Get_Attributes_All | handle, members, an unidentified attribute, words, size | not implemented | the third attribute is not identified |
| Template definition | "COUNTER" | "Name;n…" | firmware 15.4 omits the suffix; the emulation keeps it (pycomm3 and eip-rs read it) |
| T->O multicast group of a Class 1 connection | 239.192.5.128 | the ODVA default allocation (239.192.5.96 for host 36 of a /24) | the target's mask and multicast configuration are not in the recording |

## Adding a capture

Add its line to manifest.json (class, storage `raw` only with permission
to redistribute), commit a raw file under `<source>/` or run `make
captures-excerpts`, add its line to SHA256SUMS and the tables above, and
its expected counts to `internal/capture` (cross-check with tshark).
