# Monitoring OpenWEC

## Liveness statistics

You should monitor OpenWEC to be sure that at any time you receive events from all your Windows machines.

You can do that using `openwec stats`.

For each subscription, you will retrieve:
* subscription name
* subscription URI
* subscription UUID
* `since`: `now - heartbeat_interval`
* `active_machines_count`: count of machines for which at least one event has been received since `since`
* `alive_machines_count`: count of machines for which at least one heartbeat has been received since `since`
* `total_machines_count`: count of machines that have sent at least one event once.

You may filter the output to only one subscription using `--subscription`.

Two output formats are available: `text` (default) and `json` (use `--format`).

## Heartbeats

You may want to retrieve heartbeats data for a subscription (`--subscription`) or/and a hostname (`--hostname`) or/and an IP address (`--address`). For example, let's say we want to retrieve heartbeats data for `192.168.1.0` and subscription `my-test-subscription`.

```bash
$ openwec heartbeats -a 192.168.1.0 -s my-test-subscription
```

Two formats are available: `text` (default) and `json` (`--format`).
