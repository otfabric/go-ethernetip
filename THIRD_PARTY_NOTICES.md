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
