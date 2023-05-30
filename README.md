# OpenWEC

OpenWEC is a free and open source (GPLv3) implementation of a Windows Event Collector server running on GNU/Linux and written in Rust.

OpenWEC collects Windows event logs from a Linux machine without the need for a third-party local agent running on Windows machines.

OpenWEC implements the Windows Event Forwarding protocol ([MS-WSMV](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-WSMV/%5BMS-WSMV%5D.pdf)), which is derived from WS-Management ([DSP0226](https://www.dmtf.org/sites/default/files/standards/documents/DSP0226_1.0.0.pdf)). The same protocol is used by the built-in Windows Event Forwarding plugin. As it speaks the same protocol, OpenWEC can be used with the built-in Windows Event Forwarding plugin. Only the source-initiated mode (Push) is supported for now.

OpenWEC is composed of two binaries:
- `openwecd`: OpenWEC server
- `openwec`: OpenWEC CLI, used to manage the OpenWEC server

The OpenWEC configuration is read from a file (by default `/etc/openwec.conf.toml`). See available parameters in [openwec.conf.sample.toml](openwec.conf.sample.toml).
Subscriptions and their parameters are stored in a [database](doc/database.md) and can be managed using `openwec` (see [CLI](doc/cli.md) documentation).

# Documentation

- [Getting started](doc/getting_started.md)
- [Command Line Interface](doc/cli.md)
- [Database](doc/database.md)
- [Subscription query](doc/query.md)
- [Outputs](doc/outputs.md)
- [Output formats](doc/formats.md)
- [How does OpenWEC works ?](doc/how_it_works.md)
- [WEF protocol analysis](doc/protocol.md)
- [Monitoring](doc/monitoring.md)
- [Known issues](doc/issues.md)
- [Talk at SSTIC 2023 (in french)](https://www.sstic.org/2023/presentation/openwec/)

# Contributing

Any contribution is welcome, be it code, bug report, packaging, documentation or translation.

# License

OpenWEC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

OpenWEC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with OpenWEC. If not, see the gnu.org web site.
