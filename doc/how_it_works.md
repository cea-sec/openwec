# How does it work ?

## Windows Event Forwarding

The following is a quick summary of the Windows Event Forwarding protocol in source-initiated mode (more specifically, WSMAN *Events* mode). A more detailed analysis is available [here](protocol.md).

Basically, a Windows host is configured (using a GPO, for example) to enumerate active [*subscriptions*](subscription.md) from a *collector* server. Each *subscription* is made to retrieve a specific set of events (defined by a [*query*](query.md)). The Windows host then sends the corresponding events to the endpoint defined in the *subscription*. All this information is exchanged using SOAP over HTTP(S).

Two transport protocols are available:
* Kerberos/HTTP (port 5985): SOAP messages are authenticated and encrypted using Kerberos and sent over HTTP. This is mainly used in Active Directory environments.
* HTTPS (port 5986): SOAP messages are authenticated and encrypted using HTTPS. Each Windows machine must have a valid client certificate.

## Subscriptions

Subscriptions are the heart of the Windows Event Forwarding protocol and thus of openwec :smile:.

A subscription consists mainly of
* a name
* a query (XPath filter): only events matching this query will be sent
* a URI: if set, only computers enumerating using this URI will receive this subscription. This allows you to have different subscriptions for different sets of machines (OUs). *This is exclusive to OpenWEC.
* a boolean specifying whether you want to retrieve existing events or only new ones (defaults to only new ones).

In OpenWEC, a subscription must be associated with at least one [*output*](outputs.md) that answers the question "*where should openwec put collected events and in what format?*".

See the [documentation page about subscriptions](subscription.md) for more information.

## Outputs

Each output is composed of two elements: a **driver** and a **format**.


### Drivers

Drivers answer the question "*what should openwec do with collected events*".

Currently there are several supported drivers:
* `Files`: Events are stored in files in a tree architecture. You need to provide some information, such as the base path.
* `TCP`: Events are sent to a TCP server. You must specify a host and port.
* `Kafka`: Events are sent in a Kafka topic. You need to specify the name of the Kafka topic and the usual Kafka settings such as *bootstrap servers*.
* `UnixDatagram`: Events are sent in a Unix domain socket.
* `Redis`: Events are sent in a Redis Queue.

## Formats

The OpenWEC server can parse each event and format it. There are several formatters available:
* `Raw`: as its name suggests, it does nothing to the events. It just writes raw XML data. *Warning: each event may contain EOL characters which are neither filtered nor transformed*.
* `Json`: format events in Json. Json schema is documented [there](formats.md). When using the `Json` formatter, OpenWEC parses XML events and is able to add useful data such as the Kerberos principal or the IP address that sent the event.
* `RawJson`: encapsulates the raw XML data in a json document. OpenWEC does not parse the XML event, but can still add useful metadata such as the Kerberos principal or the IP address that sent the event.

## Bookmarks

To achieve reliable delivery of events, Windows Event Forwarding uses a *bookmark* mechanism. A bookmark is a pointer to a location in the event stream of a Windows computer. The log forwarding service of a Windows computer sends a new bookmark with each event delivery. The *collector* server is responsible for persisting these *bookmarks* for each subscription and sending them during subscription enumeration. The Windows computer then sends all available events that match the *subscription* *query* since the last *bookmark*.

When a subscription is created or a new computer starts sending its events, there are no bookmarks. The collector can choose to receive either all existing events matching filters and new events, or only new events (see `read_existing_events` parameter).

OpenWEC needs a way to store these *bookmarks*: a database!

## Database

OpenWEC supports the use of two database storage systems:
* SQLite (on disk)
* PostgreSQL

You need to configure one of them to run OpenWEC. *Subscriptions*, *bookmarks* and *heartbeats* are all stored in the database.

SQLite is great for testing and simple environments.

For redundancy and/or scaling, you will need to set up multiple OpenWEC nodes in different availability zones. To do this you will need to use an external database storage backend such as PostgreSQL. Note that OpenWEC's PostgreSQL client is optimised for use with [CockroachDB](https://github.com/cockroachdb/cockroach).

## Heartbeats

To be able to distinguish between a lack of events and an outage, Windows machines are required to send real events periodically (see the `heartbeat_interval` parameter), or *heartbeats* if no events match.

For each tuple `(subscription, host)`, OpenWEC stores several datetimes in its database:
* First event received
* Last event received
* Last heartbeat received

This allows OpenWEC to display a summary of active (real event received "recently"), alive (heartbeat received "recently") and dead (nothing received "recently") hosts.
