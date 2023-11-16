# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add OpenWEC node name (if configured) in JSON format output (#2)
- Make ContentFormat of subscriptions configurable (#1)
- Add IgnoreChannelError option to subscriptions (#6)
- Add Kerberos principals filter to subscriptions (#18)
- Add a setting to configure `heartbeats_queue_size` (#37)
- Add Tls support for encryption and authentication (#36)
- Add support for output events to redis list (#45)

### Changed

- Server log responses payload in TRACE level (#37)
- Remove `OperationID` from responses because we don't support "Robust Connection" (#37)
- Clear in-memory subscriptions when a SIGHUP signal is received, resulting in all file descriptors used by subscriptions being closed (#37)
- `heartbeats_queue_size` now defaults to 2048 instead of 32 (#37)
- **Breaking change**: Keytab file path must be specified only once for all collectors (using Kerberos authentication)
- A malformed event will no longer stop the event stream (for a computer/subscription) because formatters are not allowed to fail. In problematic cases, some work is done to try to recover the raw data of the event, and an `OpenWEC.Error` field is added (in the JSON formatter) to help catch the problem (#47)
- **Breaking change**: Split access and server logs. Configuration file format has been updated. (#52)
- Ensure that openwecd shutdowns gracefully even if hyper server is not responding
- Improve the logging of failed Kerberos authentications: missing authorization header warning is now in DEBUG level

### Fixed

- Fixed an issue that could result in an inconsistent state when a client unexpectedly closes an HTTP connection.

## [0.1.0] - 2023-05-30

Initial commit containing most of the desired features. The project is still under heavy development and production use without a backup solution should be avoided.
