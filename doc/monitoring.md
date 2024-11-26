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

## Prometheus-compatible endpoint

OpenWEC can expose a Prometheus-compatible endpoint with multiple metrics.

### Configuration

This feature is **disabled** by default.

Metrics collection and publication can be enabled in the OpenWEC settings (see `monitoring` section of [openwec.conf.sample.toml](../openwec.conf.sample.toml)).

### Available metrics

| **Metric** | **Type** | **Labels** | **Description** |
|---|---|---|---|
| `openwec_input_events_total` | `Counter` | `subscription_uuid`, `subscription_name`, `machine` (optional*) | The total number of events received by openwec |
| `openwec_input_event_bytes_total` | `Counter` | `subscription_uuid`, `subscription_name`, `machine` (optional*) | The total size of all events received by openwec |
| `openwec_input_messages_total` | `Counter` | `action` (one of `"enumerate"`, `"heartbeat"`, `"events"`) | The total number of messages received by openwec |
| `openwec_input_event_parsing_failures_total` | `Counter` | `subscription_uuid`, `subscription_name`, `type` | The total number of event parsing failures |
| `openwec_http_requests_total` | `Counter` | `uri`, `code` | The total number of HTTP requests handled by openwec |
| `openwec_http_request_duration_seconds` | `Histogram` | `uri` | Histogram of response duration for HTTP requests |
| `openwec_http_request_body_network_size_bytes_total` | `Counter` | `uri`, `machine` (optional*) | The total size of all http requests body received by openwec |
| `openwec_http_request_body_real_size_bytes_total` | `Counter` | `uri`, `machine` (optional*) | The total size of all http requests body received by openwec after decryption and decompression |
| `openwec_output_driver_failures_total` | `Counter` | `subscription_uuid`, `subscription_name`, `driver` | The total number of output driver failures |
| `openwec_output_format_failures_total` | `Counter` | `subscription_uuid`, `subscription_name`, `format` | The total number of output format failures |

> [!WARNING]  
> Enabling the `machine` labels may cause a **huge** increase in metric cardinality!