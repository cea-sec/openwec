# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `max_elements` subscription parameter (#185)
- Add an optional Prometheus endpoint that exposes metrics (#190)
- Optionally wrap TCP stream in a TLS session in TCP driver (#203)
- Support for SPNEGO authentication (#307)

## Changed

- Rework subscription filters (#186) (**Warning: this require a databatase migration**)
- In formats `Json`, `Nxlog` and `RawJson`, `OpenWEC.Principal` is replaced by `OpenWEC.Client` (#186)
- In `Files` driver, `{principal}` is replaced by `{client}` in `path` config (#186)
- In access log pattern, `{X(principal)}` is replaced by `{X(client)}` (#186)

## Removed

- Subscription filters can no longer be created nor edited using the cli (#186)

## [v0.3.0]

### Added

- Multiple Kafka output drivers that connect to the same Kafka cluster can use a single Kafka client (#155)

### Changed

- Files output drivers use a single thread (for all outputs) to write to files. Multiple Files outputs can write to the same file (which was not safe before) (#155)
- A garbage collector runs regularly to close unused opened files (#155)
- Files output driver is now configured using a unique `path` value which can be customized using variables. **Warning: this require a databatase migration**. (#156)

### Fixed

- Added a 'WWWW-Authenticate' header when sending a HTTP response with status 401 (#154)

### Deprecated

- Using commands to manage subscriptions and there outputs is deprecated and will be removed in future releases. Use subscription configuration files instead. (#156)

## [0.2.1]

### Added

- Add a Dockerfile (#126)

### Changed

- Use multiplexed connections for Redis driver (#127)

## [0.2.0]

### Added

- Add OpenWEC node name (if configured) in JSON format output (#2)
- Make ContentFormat of subscriptions configurable (#1)
- Add IgnoreChannelError option to subscriptions (#6)
- Add Kerberos principals filter to subscriptions (#18)
- Add a setting to configure `heartbeats_queue_size` (#37)
- Add Tls support for encryption and authentication (#36)
- Add support for output events to redis list (#45)
- Add TCP keepalive settings (with sensible defaults) in server settings (#56)
- Add support for output events to unix domain socket (#60)
- Add configuration files for subscriptions coming with two openwec cli subcommands (`subscriptions load` and `subscriptions skell`)
- Add `cli.read_only_subscriptions` setting to disable the cli features which edit subscriptions (except `subscriptions load`)
- Add `RawJson` format which enables to retrieve events in raw format while also getting the metadata added by OpenWEC
- Add the subscription revision in OpenWEC events metadata
- Add `locale` and `data_locale` subscriptions parameters
- Add support for Proxy Protocol to allow openwec to be used behind a layer 4 load
balancer whilst preserving the client IP address and port.
- Add Nxlog format (#124)

### Changed

- Server log responses payload in TRACE level (#37)
- Remove `OperationID` from responses because we don't support "Robust Connection" (#37)
- Clear in-memory subscriptions when a SIGHUP signal is received, resulting in all file descriptors used by subscriptions being closed (#37)
- `heartbeats_queue_size` now defaults to 2048 instead of 32 (#37)
- **Breaking change**: Keytab file path must be specified only once for all collectors (using Kerberos authentication)
- A malformed event will no longer stop the event stream (for a computer/subscription) because formatters are not allowed to fail. In problematic cases, some work is done to try to recover the raw data of the event, and an `OpenWEC.Error` field is added (in the JSON formatter) to help catch the problem (#47)
- **Breaking change**: Split access and server logs. Configuration file format has been updated. (#52)
- Ensure that openwecd shutdowns gracefully even if hyper server is not responding (#65)
- Improve the logging of failed Kerberos authentications: missing authorization header warning is now in DEBUG level (#65)
- Rework output drivers and output formats architecture
- Change the outputs storage format in database
- Rework the import/export format to enable compatibility between OpenWEC versions
- Each subscription has now two "versions": a public one sent to clients (derived from subscription parameters) and a private one used for synchronization between openwec nodes

### Fixed

- Fixed an issue that could result in an inconsistent state when a client unexpectedly closes an HTTP connection.

## [0.1.0] - 2023-05-30

Initial commit containing most of the desired features. The project is still under heavy development and production use without a backup solution should be avoided.
