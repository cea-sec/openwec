# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

##  [Unreleased]

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
- `heartbeats_queue_size` now defauts to 2048 instead of 32 (#37)

## [0.1.0] - 2023-05-30

Initial commit containing most of the desired features. The project is still under heavy development and production use without a backup solution should be avoided.
