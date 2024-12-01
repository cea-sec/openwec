use common::{
    database::Db,
    encoding::decode_utf16le,
    settings::Settings,
    subscription::{
        ContentFormat, FilesConfiguration, KafkaConfiguration, ClientFilterOperation,
        RedisConfiguration, SubscriptionData, SubscriptionMachineState, SubscriptionOutput,
        SubscriptionOutputDriver, SubscriptionOutputFormat, TcpConfiguration,
        UnixDatagramConfiguration,
    },
};
use roxmltree::{Document, Node};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufReader, Read},
    path::Path,
    str::FromStr,
    time::SystemTime,
};
use uuid::Uuid;

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::ArgMatches;
use log::{debug, info, warn};
use std::io::Write;

use crate::{
    config,
    skell::{get_full_skell_content, get_minimal_skell_content},
    utils::{self, confirm},
};

enum ImportFormat {
    OpenWEC,
    Windows,
}

pub async fn run(db: &Db, matches: &ArgMatches, settings: &Settings) -> Result<()> {
    match matches.subcommand() {
        Some(("new", matches)) => {
            check_subscriptions_ro(settings)?;
            new(db, matches).await?;
        }
        Some(("show", matches)) => {
            show(db, matches).await?;
        }
        Some(("edit", matches)) => {
            check_subscriptions_ro(settings)?;
            edit(db, matches).await?;
        }
        Some(("export", matches)) => {
            deprecated_cli_warn();
            export(db, matches).await?;
        }
        Some(("import", matches)) => {
            check_subscriptions_ro(settings)?;
            import(db, matches).await?;
        }
        Some(("delete", matches)) => {
            check_subscriptions_ro(settings)?;
            delete(db, matches).await?;
        }
        Some(("machines", matches)) => {
            machines(db, matches).await?;
        }
        Some(("duplicate", matches)) => {
            check_subscriptions_ro(settings)?;
            duplicate(db, matches).await?;
        }
        Some(("enable", matches)) => {
            check_subscriptions_ro(settings)?;
            set_enable(db, matches, true).await?;
        }
        Some(("disable", matches)) => {
            check_subscriptions_ro(settings)?;
            set_enable(db, matches, false).await?;
        }
        Some(("reload", matches)) => {
            reload(db, matches).await?;
        }
        Some(("load", matches)) => {
            load(db, matches).await?;
        }
        Some(("skell", matches)) => {
            skell(db, matches).await?;
        }
        _ => {
            list(db, matches).await?;
        }
    }
    Ok(())
}

async fn list(db: &Db, matches: &ArgMatches) -> Result<()> {
    let enabled = *matches.get_one::<bool>("enabled").unwrap_or(&false);
    let disabled = *matches.get_one::<bool>("disabled").unwrap_or(&false);
    if enabled && disabled {
        bail!("Enabled and disabled both set");
    }

    for subscription in db
        .get_subscriptions()
        .await
        .context("Failed to retrieve subscriptions from database")?
    {
        if enabled && subscription.enabled()
            || (disabled && !subscription.enabled())
            || (!disabled && !enabled)
        {
            println!("{}", subscription.short());
        }
    }
    Ok(())
}

async fn show(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscription = find_subscription(db, matches)
        .await
        .context("Failed to retrieve subscription from database")?;

    println!("{}", subscription);
    Ok(())
}

async fn duplicate(db: &Db, matches: &ArgMatches) -> Result<()> {
    let source = find_subscription(db, matches)
        .await
        .context("Failed to retrieve subscription from database")?;

    let mut new = source.clone();
    new.update_uuid();
    new.set_enabled(false);
    new.set_name(
        matches
            .get_one::<String>("name")
            .expect("Required by clap")
            .to_string(),
    );
    db.store_subscription(&new).await?;

    Ok(())
}

async fn export(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscriptions = if matches.contains_id("subscription") {
        vec![find_subscription(db, matches)
            .await
            .context("Failed to find subscription")?]
    } else {
        db.get_subscriptions()
            .await
            .context("Failed to retrieve subscriptions from database")?
    };

    let res = common::models::export::serialize(&subscriptions)?;
    println!("{}", res);
    Ok(())
}

fn get_query_channels(root: Node) -> Result<HashSet<String>> {
    let mut channels = HashSet::new();
    if !root.has_tag_name("QueryList") {
        bail!(
            "Expected root element to be QueryList, found {:?}",
            root.tag_name()
        )
    }
    for query_node in root.children() {
        if !query_node.has_tag_name("Query") {
            continue;
        }
        for select_node in query_node.children() {
            if !select_node.has_tag_name("Select") {
                continue;
            }
            channels.insert(
                select_node
                    .attribute("Path")
                    .ok_or_else(|| {
                        anyhow!(
                            "Could not find Path attribute in Select node: {:?}",
                            select_node
                        )
                    })?
                    .to_owned(),
            );
        }
    }
    Ok(channels)
}

fn update_query_check(old_query: &str, new_query: &str) -> Result<bool> {
    let old_doc = Document::parse(old_query).context("Failed to parse old query")?;
    let old_query_channels = get_query_channels(old_doc.root_element())
        .context("Failed to get channels of old query")?;

    let new_doc = Document::parse(new_query).context("Failed to parse new query")?;
    let new_query_channels = get_query_channels(new_doc.root_element())
        .context("Failed to get channels of new query")?;

    if new_query_channels.is_subset(&old_query_channels) {
        Ok(true)
    } else {
        let diff = new_query_channels.difference(&old_query_channels);
        println!("The new query contains new channels:");
        for channel in diff {
            println!("- {}", channel);
        }
        println!("Because there is no bookmarks stored for these channels, you will receive all existing events for them (ignoring the read_existing_events configuration). Depending of the channels, it may cause a huge network trafic.");
        Ok(utils::confirm(
            "Do you want to ignore this warning and continue?",
        ))
    }
}

fn check_query_size(query: &str) -> Result<bool> {
    let doc = Document::parse(query).context("Failed to parse query")?;
    let channels = get_query_channels(doc.root_element())?;

    // Windows clients seem to not like queries selecting more than 256 channels
    if channels.len() > 256 {
        println!("The query selects more than 256 channels and will probably not work on Windows clients.");
        Ok(utils::confirm(
            "Do you want to ignore this warning and continue?",
        ))
    } else {
        Ok(true)
    }
}

async fn edit(db: &Db, matches: &ArgMatches) -> Result<()> {
    let mut subscription = find_subscription(db, matches).await?;
    if let Some(("outputs", matches)) = matches.subcommand() {
        outputs(&mut subscription, matches).await?;
    }
    if let Some(("filter", matches)) = matches.subcommand() {
        edit_filter(&mut subscription, matches).await?;
    }
    if let Some(query) = matches.get_one::<String>("query") {
        let mut file = File::open(query)?;
        let mut new_query = String::new();
        file.read_to_string(&mut new_query)?;

        // Check the new query size
        if !check_query_size(&new_query).context("Failed to check query size")? {
            println!("Aborted");
            return Ok(());
        }

        // We try to establish if the new query add sources compared to the
        // old one.
        // In that case, we warn the user that it can lead to "read_existing_event"
        // being set to true for all these new sources.
        if !update_query_check(subscription.query(), &new_query)
            .context("Failed to compare old and new queries")?
        {
            println!("Aborted");
            return Ok(());
        }

        debug!(
            "Update query from {} to {}",
            subscription.query(),
            new_query
        );
        subscription.set_query(new_query);
    }

    if let Some(name) = matches.get_one::<String>("rename") {
        debug!("Update name from {} to {}", subscription.name(), name);
        subscription.set_name(name.to_owned());
    }

    if matches.contains_id("uri") {
        if let Some(uri) = matches.get_one::<String>("uri") {
            debug!(
                "Update uri from {:?} to {:?}",
                subscription.uri(),
                Some(uri)
            );
            subscription.set_uri(Some(uri.to_string()));
        } else {
            subscription.set_uri(None);
        }
    }

    if let Some(heartbeat_interval) = matches.get_one::<u32>("heartbeat-interval") {
        debug!(
            "Update heartbeat_interval from {} to {}",
            subscription.heartbeat_interval(),
            heartbeat_interval
        );
        subscription.set_heartbeat_interval(*heartbeat_interval);
    }
    if let Some(connection_retry_count) = matches.get_one::<u16>("connection-retry-count") {
        debug!(
            "Update connection_retry_count from {} to {}",
            subscription.connection_retry_count(),
            connection_retry_count
        );
        subscription.set_connection_retry_count(*connection_retry_count);
    }
    if let Some(connection_retry_interval) = matches.get_one::<u32>("connection-retry-interval") {
        debug!(
            "Update connection_retry_interval from {} to {}",
            subscription.connection_retry_interval(),
            connection_retry_interval
        );
        subscription.set_connection_retry_interval(*connection_retry_interval);
    }
    if let Some(max_time) = matches.get_one::<u32>("max-time") {
        debug!(
            "Update max_time from {} to {}",
            subscription.max_time(),
            max_time
        );
        subscription.set_max_time(*max_time);
    }
    if let Some(max_envelope_size) = matches.get_one::<u32>("max-envelope-size") {
        debug!(
            "Update max_envelope_size from {} to {}",
            subscription.max_envelope_size(),
            max_envelope_size
        );
        subscription.set_max_envelope_size(*max_envelope_size);
    }
    if let Some(true) = matches.get_one::<bool>("enable") {
        // Check that this subcription has outputs
        if subscription.outputs().is_empty() {
            bail!("Subscription must have at least one outputs configured to be enabled");
        }
        debug!("Update enable from {} to true", subscription.enabled());
        subscription.set_enabled(true);
    } else if let Some(true) = matches.get_one::<bool>("disable") {
        debug!("Update enable from {} to true", subscription.enabled());
        subscription.set_enabled(false);
    }
    if let Some(content_format) = matches.get_one::<String>("content-format") {
        let content_format_t =
            ContentFormat::from_str(content_format).context("Parse content-format argument")?;
        debug!(
            "Update content_format from {} to {}",
            subscription.content_format().to_string(),
            content_format_t.to_string()
        );
        subscription.set_content_format(content_format_t);
    }
    if let Some(ignore_channel_error) = matches.get_one::<bool>("ignore-channel-error") {
        debug!(
            "Update ignore_channel_error from {} to {}",
            subscription.ignore_channel_error(),
            ignore_channel_error,
        );
        subscription.set_ignore_channel_error(*ignore_channel_error);
    }

    if matches.contains_id("locale") {
        if let Some(locale) = matches.get_one::<String>("locale") {
            debug!(
                "Update locale from {:?} to {:?}",
                subscription.locale(),
                Some(locale)
            );
            subscription.set_locale(Some(locale.to_string()));
        } else {
            subscription.set_locale(None);
        }
    }

    if matches.contains_id("data-locale") {
        if let Some(data_locale) = matches.get_one::<String>("data-locale") {
            debug!(
                "Update data-locale from {:?} to {:?}",
                subscription.data_locale(),
                Some(data_locale)
            );
            subscription.set_data_locale(Some(data_locale.to_string()));
        } else {
            subscription.set_locale(None);
        }
    }

    info!(
        "Saving subscription {} ({})",
        subscription.name(),
        subscription.uuid()
    );
    db.store_subscription(&subscription).await?;
    Ok(())
}

async fn new(db: &Db, matches: &ArgMatches) -> Result<()> {
    let mut file = File::open(
        matches
            .get_one::<String>("query")
            .expect("Required by clap"),
    )?;
    let mut query = String::new();
    file.read_to_string(&mut query)?;

    // Check the new query size
    if !check_query_size(&query).context("Failed to check query size")? {
        println!("Aborted");
        return Ok(());
    }

    let content_format = ContentFormat::from_str(
        matches
            .get_one::<String>("content-format")
            .expect("Defaulted by clap"),
    )?;

    let mut subscription = SubscriptionData::new(
        matches.get_one::<String>("name").expect("Required by clap"),
        &query,
    );
    subscription
        .set_uri(matches.get_one::<String>("uri").cloned())
        .set_enabled(false)
        .set_read_existing_events(
            *matches
                .get_one::<bool>("read-existing-events")
                .expect("defaulted by clap"),
        )
        .set_content_format(content_format)
        .set_ignore_channel_error(
            *matches
                .get_one::<bool>("ignore-channel-error")
                .expect("Defaulted by clap"),
        );

    if let Some(heartbeat_interval) = matches.get_one::<u32>("heartbeat-interval") {
        subscription.set_heartbeat_interval(*heartbeat_interval);
    }

    if let Some(connection_retry_count) = matches.get_one::<u16>("connection-retry-count") {
        subscription.set_connection_retry_count(*connection_retry_count);
    }

    if let Some(connection_retry_interval) = matches.get_one::<u32>("connection-retry-interval") {
        subscription.set_connection_retry_interval(*connection_retry_interval);
    }

    if let Some(max_time) = matches.get_one::<u32>("max-time") {
        subscription.set_max_time(*max_time);
    }

    if let Some(max_envelope_size) = matches.get_one::<u32>("max-envelope-size") {
        subscription.set_max_envelope_size(*max_envelope_size);
    }

    debug!(
        "Subscription that is going to be inserted: {:?}",
        subscription
    );
    db.store_subscription(&subscription).await?;
    println!(
        "Subscription {} has been created successfully. \
        You need to configure its outputs using `openwec subscriptions edit {} outputs add --help`. \
        When you are ready, you can enable it using `openwec subscriptions edit {} --enable",
        subscription.name(), subscription.name(), subscription.name()
    );
    Ok(())
}

async fn import(db: &Db, matches: &ArgMatches) -> Result<()> {
    let format: ImportFormat = match matches
        .get_one::<String>("format")
        .expect("defaulted by clap")
    {
        x if x == "openwec" => ImportFormat::OpenWEC,
        x if x == "windows" => ImportFormat::Windows,
        _ => bail!("Invalid import format"),
    };
    let file = File::open(matches.get_one::<String>("file").expect("Required by clap"))?;
    let reader = BufReader::new(file);

    let mut subscriptions =
        match format {
            ImportFormat::OpenWEC => import_openwec(reader)
                .context("Failed to import subscriptions using OpenWEC format")?,
            ImportFormat::Windows => import_windows(reader)
                .context("Failed to import subscriptions using Windows format")?,
        };

    let count = subscriptions.len();
    while let Some(mut subscription) = subscriptions.pop() {
        // Imported subscriptions are disabled. They must be enabled manually afterward.
        subscription.set_enabled(false);

        debug!("Store {:?}", subscription);
        db.store_subscription(&subscription)
            .await
            .context("Failed to store subscription")?;
    }

    match count {
        0 => println!("No subscription have been imported."),
        1 => println!("1 subscription has been imported. You may want to enable it using `openwec subscriptions edit <name> --enable`."),
        n => println!("{} subscriptions have been imported. They need to be enabled one by one using `openwec subscriptions edit <name> --enable`.", n),
    }
    Ok(())
}

fn import_openwec(mut reader: BufReader<File>) -> Result<Vec<SubscriptionData>> {
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer)?;

    common::models::export::parse(&buffer)
}

fn import_windows(mut reader: BufReader<File>) -> Result<Vec<SubscriptionData>> {
    let mut content_bytes = Vec::new();
    reader.read_to_end(&mut content_bytes)?;
    let content = decode_utf16le(content_bytes)?;
    let doc = Document::parse(content.as_str())?;
    let root = doc.root_element();
    ensure!(
        root.has_tag_name((
            "http://schemas.microsoft.com/2006/03/windows/events/subscription",
            "Subscription"
        )),
        "Invalid subscription format"
    );

    // We initialize subscription data with empty name and query
    // They will be overwritten later
    let mut data = SubscriptionData::new("", "");

    for node in root.children() {
        if node.has_tag_name("SubscriptionId") && node.text().is_some() {
            data.set_name(node.text().map(String::from).unwrap());
        } else if node.has_tag_name("SubscriptionType") && node.text().is_some() {
            ensure!(
                node.text().map(String::from).unwrap() == "SourceInitiated",
                "Invalid subscription format: SubscriptionType must be SourceInitiated"
            );
        } else if node.has_tag_name("Uri") && node.text().is_some() {
            ensure!(
                node.text().map(String::from).unwrap()
                    == "http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog",
                "Invalid subscription Uri"
            );
        } else if node.has_tag_name("Delivery") {
            ensure!(
                node.attribute("Mode").unwrap_or_default() == "Push",
                "Invalid delivery mode (should be push)"
            );
            for delivery_node in node.children() {
                if delivery_node.has_tag_name("Batching") {
                    for batching_node in delivery_node.children() {
                        if batching_node.has_tag_name("MaxLatencyTime")
                            && batching_node.text().is_some()
                        {
                            data.set_max_time(batching_node.text().unwrap().parse::<u32>()?);
                        }
                    }
                } else if delivery_node.has_tag_name("PushSettings") {
                    for settings in delivery_node.children() {
                        if settings.has_tag_name("Heartbeat") && settings.has_attribute("Interval")
                        {
                            data.set_heartbeat_interval(
                                settings.attribute("Interval").unwrap().parse::<u32>()?,
                            );
                        }
                    }
                }
            }
        } else if node.has_tag_name("Query") && node.text().is_some() {
            data.set_query(node.text().map(String::from).unwrap());
        } else if node.has_tag_name("ReadExistingEvents") && node.text().is_some() {
            data.set_read_existing_events(node.text().unwrap().parse()?);
        } else if node.has_tag_name("ContentFormat") && node.text().is_some() {
            let content_format = ContentFormat::from_str(node.text().unwrap())?;
            data.set_content_format(content_format);
        }
    }

    Ok(vec![data])
}
async fn delete(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscription = find_subscription(db, matches).await?;

    if !*matches.get_one::<bool>("yes").expect("defaulted by clap")
        && !confirm(&format!(
            "Are you sure that you want to delete \"{}\" ({}) ?",
            subscription.name(),
            subscription.uuid()
        ))
    {
        return Ok(());
    }
    db.delete_subscription(&subscription.uuid_string()).await
}

async fn edit_filter(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    let mut filter = subscription.client_filter().clone();
    match matches.subcommand() {
        Some(("set", matches)) => {
            let op_str = matches
                .get_one::<String>("operation")
                .ok_or_else(|| anyhow!("Missing operation argument"))?;

            let op_opt = ClientFilterOperation::opt_from_str(op_str)?;
            filter.set_operation(op_opt.clone());

            if let Some(op) = op_opt {
                let mut princs = HashSet::new();
                if let Some(identifiers) = matches.get_many::<String>("principals") {
                    for identifier in identifiers {
                        princs.insert(identifier.clone());
                    }
                }
                if op == ClientFilterOperation::Only && princs.is_empty() {
                    warn!("'{}' filter has been set without principals making this subscription apply to nothing.", op)
                }
                filter.set_targets(princs)?;
            }
        }
        Some(("princs", matches)) => match matches.subcommand() {
            Some(("add", matches)) => {
                filter.add_target(
                    matches
                        .get_one::<String>("principal")
                        .ok_or_else(|| anyhow!("Missing principal"))?,
                )?;
            }
            Some(("delete", matches)) => {
                filter.delete_target(
                    matches
                        .get_one::<String>("principal")
                        .ok_or_else(|| anyhow!("Missing principal"))?,
                )?;
            }
            Some(("set", matches)) => match matches.get_many::<String>("principals") {
                Some(identifiers) => {
                    let mut princs = HashSet::new();
                    for identifier in identifiers {
                        princs.insert(identifier.clone());
                    }
                    filter.set_targets(princs)?;
                }
                None => {
                    bail!("No principals to set")
                }
            },
            _ => {
                bail!("Nothing to do");
            }
        },
        _ => {
            bail!("Nothing to do");
        }
    }
    subscription.set_client_filter(filter);

    Ok(())
}
async fn outputs(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    info!(
        "Loading subscription {} ({})",
        subscription.name(),
        subscription.uuid()
    );
    match matches.subcommand() {
        Some(("add", matches)) => {
            outputs_add(subscription, matches)
                .await
                .context("Failed to add output")?;
        }
        Some(("delete", matches)) => {
            outputs_delete(subscription, matches)
                .await
                .context("Failed to delete output")?;
        }
        Some(("enable", matches)) => {
            outputs_enable(subscription, matches)
                .await
                .context("Failed to delete output")?;
        }
        Some(("disable", matches)) => {
            outputs_disable(subscription, matches)
                .await
                .context("Failed to delete output")?;
        }
        _ => {
            outputs_list(subscription);
        }
    }
    Ok(())
}

async fn outputs_add(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    let format: SubscriptionOutputFormat = SubscriptionOutputFormat::from_str(
        matches
            .get_one::<String>("format")
            .ok_or_else(|| anyhow!("Missing format argument"))?,
    )?;
    let output = match matches.subcommand() {
        Some(("tcp", matches)) => SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::Tcp(outputs_add_tcp(matches)?),
            true,
        ),
        Some(("redis", matches)) => SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::Redis(outputs_add_redis(matches)?),
            true,
        ),
        Some(("kafka", matches)) => SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::Kafka(outputs_add_kafka(matches)?),
            true,
        ),
        Some(("files", matches)) => SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::Files(outputs_add_files(matches)?),
            true,
        ),
        Some(("unixdatagram", matches)) => SubscriptionOutput::new(
            format,
            SubscriptionOutputDriver::UnixDatagram(outputs_add_unix_datagram(matches)?),
            true,
        ),
        _ => {
            bail!("Missing output type")
        }
    };
    subscription.add_output(output);
    Ok(())
}

fn outputs_add_tcp(matches: &ArgMatches) -> Result<TcpConfiguration> {
    let addr = matches
        .get_one::<String>("addr")
        .ok_or_else(|| anyhow!("Missing IP address"))?;
    let port = matches
        .get_one::<u16>("port")
        .ok_or_else(|| anyhow!("Missing TCP port"))?;

    info!("Adding TCP output: {}:{}", addr, port);
    Ok(TcpConfiguration::new(addr.clone(), *port))
}

fn outputs_add_redis(matches: &ArgMatches) -> Result<RedisConfiguration> {
    let addr = matches
        .get_one::<String>("addr")
        .ok_or_else(|| anyhow!("Missing Redis server address"))?;

    let list = matches
        .get_one::<String>("list")
        .ok_or_else(|| anyhow!("Missing Redis list"))?;

    info!("Adding Redis output: address: {}, list {}", addr, list);
    Ok(RedisConfiguration::new(addr.clone(), list.clone()))
}

fn outputs_add_kafka(matches: &ArgMatches) -> Result<KafkaConfiguration> {
    let topic = matches
        .get_one::<String>("topic")
        .ok_or_else(|| anyhow!("Missing Kafka topic"))?;

    let options = matches.get_many::<String>("options").unwrap().enumerate();

    let mut options_hashmap = HashMap::new();
    let mut key = String::new();
    for (index, elt) in options {
        if index % 2 == 0 {
            elt.clone_into(&mut key);
        } else {
            options_hashmap.insert(key.clone(), elt.to_owned());
        }
    }

    info!(
        "Adding Kafka output with topic \"{}\" and the following options: {:?}",
        topic, options_hashmap
    );

    Ok(KafkaConfiguration::new(topic.clone(), options_hashmap))
}

fn outputs_add_files(matches: &ArgMatches) -> Result<FilesConfiguration> {
    let path = matches
        .get_one::<String>("path")
        .ok_or_else(|| anyhow!("Missing files path"))?
        .to_owned();

    let config = FilesConfiguration::new(path);
    info!("Adding Files output with config {:?}", config);
    Ok(config)
}

fn outputs_add_unix_datagram(matches: &ArgMatches) -> Result<UnixDatagramConfiguration> {
    let path = matches
        .get_one::<String>("path")
        .ok_or_else(|| anyhow!("Missing UnixDatagram path"))?
        .to_owned();

    info!("Adding UnixDatagram output: {}", path);
    Ok(UnixDatagramConfiguration::new(path))
}

async fn outputs_delete(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    let index = matches
        .get_one::<usize>("index")
        .ok_or_else(|| anyhow!("Missing index"))?;
    let output = subscription
        .outputs()
        .get(*index)
        .ok_or_else(|| anyhow!("index out of range"))?;
    if !*matches.get_one::<bool>("yes").expect("defaulted by clap")
        && !confirm(&format!(
            "Are you sure that you want to delete output: ({}) ?",
            output,
        ))
    {
        return Ok(());
    }
    subscription
        .delete_output(*index)
        .context("Failed to delete output")?;
    Ok(())
}

async fn outputs_enable(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    let index = matches
        .get_one::<usize>("index")
        .ok_or_else(|| anyhow!("Missing index"))?;
    subscription
        .set_output_enabled(*index, true)
        .context("Failed to enable output")?;
    Ok(())
}

async fn outputs_disable(subscription: &mut SubscriptionData, matches: &ArgMatches) -> Result<()> {
    let index = matches
        .get_one::<usize>("index")
        .ok_or_else(|| anyhow!("Missing index"))?;
    let output = subscription
        .outputs()
        .get(*index)
        .ok_or_else(|| anyhow!("index out of range"))?;
    if !*matches.get_one::<bool>("yes").expect("defaulted by clap")
        && !confirm(&format!(
            "Are you sure that you want to disable output : ({}) ?",
            output,
        ))
    {
        return Ok(());
    }
    subscription
        .set_output_enabled(*index, false)
        .context("Failed to enable output")?;
    Ok(())
}

fn outputs_list(subscription: &SubscriptionData) {
    if subscription.outputs().is_empty() {
        println!(
            "Subscription {} does not have any outputs configured yet.",
            subscription.name()
        );
    } else {
        for (index, output) in subscription.outputs().iter().enumerate() {
            println!("{}: {}", index, output);
        }
    }
}

async fn machines(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscription = find_subscription(db, matches)
        .await
        .context("Failed to retrieve subscriptions from database")?;
    let interval = matches
        .get_one::<u32>("interval")
        .cloned()
        .unwrap_or_else(|| subscription.heartbeat_interval()) as i64;
    let now: i64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        .try_into()?;
    let start_heartbeat_interval = now - interval;

    let state = if *matches
        .get_one::<bool>("active")
        .expect("defaulted by clap")
    {
        Some(SubscriptionMachineState::Active)
    } else if *matches.get_one::<bool>("alive").expect("defaulted by clap") {
        Some(SubscriptionMachineState::Alive)
    } else if *matches.get_one::<bool>("dead").expect("defaulted by clap") {
        Some(SubscriptionMachineState::Dead)
    } else {
        None
    };

    let machines = db
        .get_machines(&subscription.uuid_string(), start_heartbeat_interval, state)
        .await
        .context("Failed to retrieve machines for subscription")?;

    for machine in machines {
        println!("{}:{}", machine.ip(), machine.name());
    }
    Ok(())
}

async fn set_enable(db: &Db, matches: &ArgMatches, value: bool) -> Result<()> {
    let mut subscriptions = find_subscriptions(db, matches).await?;

    let mut to_store = Vec::new();
    for subscription in subscriptions.iter_mut() {
        // Check that this subcription has outputs
        if value && subscription.outputs().is_empty() {
            warn!(
                "Subscription {} must have at least one outputs configured to be enabled",
                subscription.name()
            );
            continue;
        }

        subscription.set_enabled(value);
        to_store.push(subscription.clone());
    }

    if to_store.is_empty() {
        bail!("Nothing to store, check previous warnings");
    }

    for subscription in to_store {
        db.store_subscription(&subscription)
            .await
            .context("Failed to store subscription in db")?;
        if value {
            println!("+ Subscription {} has been enabled", subscription.name());
        } else {
            println!("+ Subscription {} has been disabled", subscription.name());
        }
    }

    Ok(())
}

async fn reload(db: &Db, matches: &ArgMatches) -> Result<()> {
    let mut subscriptions = find_subscriptions(db, matches).await?;

    for subscription in subscriptions.iter_mut() {
        subscription.update_internal_version();
        db.store_subscription(subscription)
            .await
            .context("Failed to store subscription in db")?;
        println!("+ Subscription {} has been reloaded", subscription.name());
    }

    Ok(())
}

async fn load(db: &Db, matches: &ArgMatches) -> Result<()> {
    let path = matches
        .get_one::<String>("path")
        .ok_or_else(|| anyhow!("Missing argument path"))?;
    let keep = matches.get_one::<bool>("keep").expect("Defaulted by clap");
    let yes = matches.get_one::<bool>("yes").expect("Defaulted by clap");
    let revision = matches.get_one::<String>("revision");

    let path_obj = Path::new(path);
    if !path_obj.exists() {
        bail!("Path {} does not exist", path_obj.display());
    }

    if path_obj.is_file() && !keep && !yes && !confirm(&format!("Are you sure that you want to remove all existing subscriptions to keep the only one described in {}? Use -k/--keep otherwise.", path_obj.display())) {
        println!("Aborted");
        return Ok(())
    }

    let subscriptions =
        config::load_from_path(path, revision).context("Failed to load config files")?;

    if subscriptions.is_empty() {
        bail!("Could not find any subscriptions");
    }

    for subscription in subscriptions.iter() {
        if !check_query_size(subscription.query()).with_context(|| {
            format!(
                "Failed to parse query of subscription '{}' ({})",
                subscription.name(),
                subscription.uuid()
            )
        })? {
            println!("Aborted");
            return Ok(());
        }
    }
    // Build a set of subscriptions uuids
    let mut uuids = HashSet::new();

    // Insert or update subscriptions
    for subscription in subscriptions.iter() {
        println!("+ Load subscription {}", subscription.name());
        db.store_subscription(subscription)
            .await
            .context("Failed to store subscription in db")?;
        uuids.insert(subscription.uuid());
    }

    if !keep {
        // Remove other subscriptions
        let all_subscriptions = db.get_subscriptions().await?;
        for subscription in all_subscriptions.iter() {
            if !uuids.contains(subscription.uuid()) {
                println!("+ Remove subscription {}", subscription.name());
                db.delete_subscription(&subscription.uuid_string()).await?;
            }
        }
    }

    Ok(())
}

async fn skell(_db: &Db, matches: &ArgMatches) -> Result<()> {
    let path = matches
        .get_one::<String>("path")
        .ok_or_else(|| anyhow!("Missing argument path"))?;

    let uuid = Uuid::new_v4();
    let name: String = match matches.get_one::<String>("name") {
        Some(name) => name.clone(),
        None => format!("subscription-{}", uuid),
    };
    let now = chrono::Local::now();

    let content = if *matches
        .get_one::<bool>("minimal")
        .expect("defaulted by clap")
    {
        get_minimal_skell_content(uuid, &name, now)
    } else {
        get_full_skell_content(uuid, &name, now)
    };

    if path.as_str() == "-" {
        println!("{}", content);
    } else {
        let mut output = File::create(path)?;
        output.write_all(content.as_bytes())?;
    }

    Ok(())
}

/***
 * Helpers
***/

async fn find_subscription(db: &Db, matches: &ArgMatches) -> Result<SubscriptionData> {
    let identifier = matches
        .get_one::<String>("subscription")
        .ok_or_else(|| anyhow!("Missing argument subscription"))?;
    utils::find_subscription(db, identifier)
        .await
        .with_context(|| format!("Failed to find subscription with identifier {}", identifier))?
        .ok_or_else(|| {
            anyhow!(
                "Subscription \"{}\" could not be found in database",
                identifier
            )
        })
}

async fn find_subscriptions(db: &Db, matches: &ArgMatches) -> Result<Vec<SubscriptionData>> {
    match matches.get_many::<String>("subscriptions") {
        Some(identifiers) => {
            let mut subscriptions = Vec::new();
            for identifier in identifiers {
                subscriptions.push(utils::find_subscription(db, identifier).await?.ok_or_else(
                    || anyhow!("Failed to find subscription with identifier {}", identifier),
                )?);
            }
            Ok(subscriptions)
        }
        None => {
            if *matches.get_one::<bool>("all").expect("defaulted by clap") {
                db.get_subscriptions().await
            } else {
                bail!("No subscription given")
            }
        }
    }
}

fn check_subscriptions_ro(settings: &Settings) -> Result<()> {
    if settings.cli().read_only_subscriptions() {
        bail!("Subscriptions can only be edited using `openwec subscriptions load` because `cli.read_only_subscriptions` is set in settings.")
    }
    deprecated_cli_warn();
    Ok(())
}

fn deprecated_cli_warn() {
    warn!("Using commands to manage subscriptions and there outputs is deprecated and will be removed in future releases. Use subscription configuration files instead.")
}
