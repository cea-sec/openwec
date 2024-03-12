# Event filter query

Each subscription requires an event filter query. It defines the events to be collected within that subscription.

The event filter query syntax is [documented by Microsoft](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events).


Note that in OpenWEC an event filter query must be in the following format:
```xml
<QueryList>
    <Query Id="0">[query]</Query>
    ...
</QueryList>
```

## Example

```xml
<QueryList>
    <Query Id="0" Path="Application">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
```

## Known limitations

### Retrieving all channels

In some cases, you may want to retrieve events from all existing channels for each client without having to explain them. However, this does not seem to be possible using event filter queries.

We recommend that you generate a list of the channels available in your environment by other means and set your event filter query accordingly.

### Editing the query of an existing subscription

When editing the query of an existing subscription, **you should not add a new channel**. If you do, for each client for which OpenWEC has a bookmark, you will retrieve all existing events for the newly added channel **regardless** of the subscription's `read_existing_events` parameter. You have two (bad) options:
* Either accept that you will retrieve a lot of events (the number depends on the added channel).
* Either delete all existing bookmarks for this subscription. If you do this, you will probably lose logs.

This is because a bookmark already exists for the client, so it will be sent when the client enumerates the subscription. However, this bookmark does not contain the newly added channel. Therefore, the Windows client (strangely) assumes that you want to retrieve all its events, including the existing ones, regardless of the `read_existing_events` setting.

### Query size

It seems that event filter queries must retrieve events from a maximum of 256 different channels.

If your query contains more channels, it will be considered invalid by Windows clients.

### Channel permissions

The Windows Event Log Forwarder runs as `NETWORK SERVICE` within the `WinRM` service. This means that **by default** the forwarder is not authorised to read all channels (e.g. `Security`).

If you want to collect event logs from these channels (you should!), you must either add the `WinRM service` (SID) to the local `Event Log Readers` group of each Windows client, or authorise the `WinRM service` (SID) to read these channels. Alternatively you can do the same with the `NETWORK SERVICE` account.

If the event log forwarder does not have permission to read a channel selected in an event filter query, it will still send events according to the rest of the query. Therefore, **you must ensure that the Windows Event Log Forwarder is allowed to read all the channels selected in the event filter query BEFORE enabling the subscription**.

If you don't, the client will send bookmarks without the forbidden channels. This means that if the forwarder is later allowed to read events in one of these channels, it will send all existing events in that channel, regardless of the `read_existing_event` subscription parameter. In the case of `Security` this can represent a lot of data, causing the network to become congested and the OpenWEC server to use the CPU heavily.
