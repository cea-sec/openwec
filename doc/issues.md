# Known issues

## Adding a new source to an existing query

### Behavior

When a source is added to the query of a subscription, machines send all existing events of this source regardless of the `read_existing_events` parameter. This behavior might create a huge network trafic (for example if you add the "Security" source...).

### Explanation

The behavior of "Bookmarks" is explained in DSP0226 10.2.6.

When a subscription is created, there are no existing bookmarks for it. If `read_existing_event` parameter is set, OpenWEC sends the reserved bookmark `http://schemas.dmtf.org/wbem/wsman/1/wsman/bookmark/earliest`:
> If a subscription is received with this bookmark, the event source replays all possible events that match the filter and any events that subsequently occur for that event source.

Otherwise, we don't send any bookmarks :
> The absence of any bookmark means "begin at the next available event".

Let's suppose that the subscription query is updated __and__ we have existing bookmarks for this subscription. On a host enumeration, OpenWEC sends its stored bookmark. However, this bookmark will not contain information for the newly added sources. Windows event forwarder seems to interpret this lack of information as "replay all possible events that match the filter" for these sources.

### Solution

There is no known solutions. Users need to be aware of this behavior, which may be acceptable if the added source is "small", or rather create a brand new subscription with the new query (and maybe lose events during the transition).

## Hunting rogue Windows Event Forwarder

### Goal

We would like to prevent a rogue machine, legitimately authenticated, to send events concerning other machines. Indeed, this could be used by an attacker to create fake events and maybe mislead defenders.

### TLDR

This seems difficult to achieve by OpenWEC.

For now, the best we can do is to add metadata in the events that are formatted in JSON (raw formatter means _raw_, so no additions allowed):
- `OpenWEC.IpAddress`: contains the IP address of the machine who sent the event
- `OpenWEC.Principal`: contains the Kerberos principal of the machine who sent the event

These informations may be post-processed later to search for "rogue" events.

### Lack of link between events "Computer" and Kerberos principal

The field `Computer` of an event seems to contain the `dNSHostName` or the Netbios name of the machine. During experiments, we have seen events with the two types of values for the same machine. In addition, we could not find any specifications of the content of this field.

Furthermore, the Kerberos principal does not contain this information. It could be guessed by an heuristic that `MACHINE$@WINDOMAIN.LOCAL` should have a `Hostname` value of `machine.windomain.local` or `MACHINE`, but this is not reliable. We could use the Active Directory database to find the object of the computer and retrieve its `dNSHostName` attribute, but it would be costly and bring with it many other problems and undesirable behaviours.

### Intermediate Windows Event log forwarder

In some environments, machines may send their events to an intermediate Windows Event Collector which would forward them to OpenWEC. In this situation, the forwarder, authenticated with his principal, would send events of other machines.

To support this, we would need to enable users to configure a list of Kerberos principal with the ability to "impersonate" other machines (a little bit like unconstrained delegation in AD).

# What is missing?

## Limit subscriptions to a subset of machines

The Microsoft implementation allows subscriptions to be set for a group of machines. The only "clean" way to do this is to parse the PAC contained in the machine's Kerberos service ticket, but this does not appear to be supported by GSSAPI. Alternatively, OpenWEC implements filters using the Kerberos principal names of machines, allowing you to allow or deny a set of principals to "see"/"use" a subscription.

In any case, it won't work with an intermediate forwarder.

## TLS support

Windows clients support TLS for authentication and encryption. This is not currently supported by OpenWEC, but it should. For now OpenWEC only supports authentication and encryption with Kerberos. There are two possibilities in order to add the TLS support:
- implement TLS support within OpenWEC web server (powered by `hyper`).
- use a reverse proxy which handles TLS and then send cleartext messages to OpenWEC service.
