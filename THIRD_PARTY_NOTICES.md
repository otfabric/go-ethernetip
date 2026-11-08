# Third-party notices

go-ethernetip contains no third-party source code. It uses the following
material as data, with attribution.

## pycomm3 — vendor list

`cip/vendors.json` (and the generated `cip.VendorName` table) is the
list of CIP vendor IDs and names that ODVA publishes, as carried by
pycomm3 1.2.16 (`pycomm3/cip/status_info.py`, `_VENDORS`).

> The MIT License (MIT)
>
> Copyright (c) 2020 Ian Ottoway
>
> Permission is hereby granted, free of charge, to any person obtaining a
> copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to permit
> persons to whom the Software is furnished to do so, subject to the
> following conditions:
>
> The above copyright notice and this permission notice shall be included
> in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
> OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
> NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
> USE OR OTHER DEALINGS IN THE SOFTWARE.

## Recorded traffic (testdata/captures)

The tests read network captures recorded by others; sources, revisions and
checksums are in [testdata/captures/README.md](testdata/captures/README.md)
and `testdata/captures/manifest.json`. They are test data, not part of the
built library.

- `testdata/captures/icsnpp-enip/`: three files of
  [cisagov/icsnpp-enip](https://github.com/cisagov/icsnpp-enip)
  (`testing/traces/`, revision 3fbd32e), unchanged.

  > BSD 3-Clause License
  >
  > Copyright (c) 2023, Battelle Energy Alliance, LLC
  >
  > Redistribution and use in source and binary forms, with or without
  > modification, are permitted provided that the following conditions are met:
  >
  > 1. Redistributions of source code must retain the above copyright notice, this
  >    list of conditions and the following disclaimer.
  >
  > 2. Redistributions in binary form must reproduce the above copyright notice,
  >    this list of conditions and the following disclaimer in the documentation
  >    and/or other materials provided with the distribution.
  >
  > 3. Neither the name of the copyright holder nor the names of its
  >    contributors may be used to endorse or promote products derived from
  >    this software without specific prior written permission.
  >
  > THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  > AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  > IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  > DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  > FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  > DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  > SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  > CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  > OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  > OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

- `testdata/captures/iti-ics-security-tools/`: seven files of
  [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools)
  (`pcaps/EthernetIP/`, revision bcb93ee), unchanged, under the
  repository's licence, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- `testdata/captures/excerpts/`: the EtherNet/IP messages, without link,
  IP and TCP headers, of four files whose raw form is not redistributed
  here: three of [EmreEkin/ICS-Pcaps](https://github.com/EmreEkin/ICS-Pcaps)
  (no licence stated) and `EthernetIP-CIP.pcap` of ITI/ICS-Security-Tools
  (from CloudShark capture 76038eaa4a3b, terms not stated).

## Sources of the CIP catalog

`cip/catalog.json` records, per code, the public source it was checked
against: OpENer (adapted BSD licence, (c) Rockwell Automation), pycomm3
(MIT), eds_pie (MIT, (c) 2021 Omid Kompani) and Rockwell Automation's
public Logix 5000 Data Access manual. Only facts (codes and their names)
are taken; no text or code of these projects is reproduced. See
[CATALOG.md](CATALOG.md).

## EDS grammar

The EDS parser follows the grammar as eds_pie implements it and as public
EDS files use it. No eds_pie code or data is included.

## Reference implementations

The interop suite runs OpENer, EIPScanner, pycomm3 and cpppo in the
containers of otfabric/ethernetip-interop. They are not part of this
module and are under their own licences.

## Trademarks

EtherNet/IP, CIP, CIP Security and ODVA are trademarks of ODVA, Inc. Logix,
ControlLogix and CompactLogix are trademarks of Rockwell Automation, Inc.
