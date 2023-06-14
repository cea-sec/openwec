use std::env;

use common::{database::schema::Version, settings::DEFAULT_CONFIG_FILE};

use clap::{arg, command, value_parser, Arg, ArgAction, ArgGroup, Command};

#[tokio::main]
async fn main() {
    let mut command = command!() // requires `cargo` feature
        .name("openwec")
        .arg(
            arg!(
                -c --config <FILE> "Sets a custom config file"
            )
            .default_value(DEFAULT_CONFIG_FILE)
            .required(false)
            .global(true),
        )
        .arg(arg!(-v --verbosity ... "Sets the level of verbosity").global(true))
        .subcommand(
            Command::new("subscriptions")
                .about("deals with openwec subscriptions. Without arguments, it lists the current subscriptions.")
                .arg(arg!(-e --enabled "Only show enabled subscriptions"))
                .arg(arg!(-d --disabled "Only show disabled subscriptions"))
                .group(ArgGroup::new("subscription_list_status").args(["enabled", "disabled"]).required(false))
                .subcommand(
                    Command::new("new")
                    .about("Creates a new subscription. The newly created subscription will have to be enabled afterward.")
                    .arg(arg!(<name> "Name of the subscription"))
                    .arg(arg!(<query> "File containing the query (XML format)"))
                    .arg(
                        arg!(-u --uri <URI> "URI linked to this subscription. \
                        The subscription will only be presented to hosts using this URI to retrieve their subscriptions. \
                        Don't set this flag to present the subscription regardless of the URI (default). \
                        Example: /my/custom/uri.")
                    )
                    .arg(
                        arg!(--"heartbeat-interval" <HEARTBEAT> "Heartbeat interval")
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"connection-retry-count" <CONNECTION_RETRY_COUNT> "Connection retry count")
                        .value_parser(value_parser!(u16))
                    )
                    .arg(
                        arg!(--"connection-retry-interval" <CONNECTION_RETRY_INTERVAL> "Connection retry interval")
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"max-time" <MAX_TIME> "Max time") // TODO: improve help
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"max-envelope-size" <MAX_ENVELOPE_SIZE> "Max envelope size") // TODO: improve help
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"read-existing-events" "Subscription retrieves already existing events in addition to new ones")
                    )
                    .arg(
                        arg!(--"content-format" <CONTENT_FORMAT> "If set to Raw, retrieve only the \
                        EventData part of events. If set to RenderedText, retrieve the \
                        RenderingInfo part as well. RenderingInfo increases the size of events \
                        but can help with analysis.")
                        .value_parser(["Raw", "RenderedText"])
                        .default_value("Raw")
                    )
                    .arg(
                        arg!(--"ignore-channel-error" <BOOL> "Configure clients to ignore filtering errors or not. Defaults to true").value_parser(value_parser!(bool)).default_value("true")
                    )
                )
                .subcommand(
                    Command::new("edit")
                    .about("Edit an existing subscription")
                    .arg(arg!(<subscription> "Name or UUID of the subscription"))
                    .subcommand(
                        Command::new("outputs")
                        .about("Manage the outputs of a subscription")
                        .subcommand(
                            Command::new("add")
                            .about("Add a new output for this subscription")
                            .arg(arg!(-f --format <FORMAT> "Output format").value_parser(["json", "raw"]).required(true))
                            .subcommand(
                                Command::new("tcp")
                                .about("TCP output")
                                .arg(arg!(<addr> "Remote IP address"))
                                .arg(arg!(<port> "TCP port").value_parser(value_parser!(u16)))
                            )
                            .subcommand(
                                Command::new("kafka")
                                .about("Kafka output")
                                .arg(arg!(<topic> "Kafka topic"))
                                .arg(
                                    Arg::new("options")
                                    .short('o')
                                    .long("option")
                                    .num_args(2)
                                    .value_names(["KEY", "VALUE"])
                                    .help("Kafka configuration (bootstrap.servers for example)")
                                    .action(clap::ArgAction::Append))
                            )
                            .subcommand(
                                Command::new("files")
                                .about("Configures a File output. Path template is <base>/<ip>/<princ>/[<node_name>/]<filename>, where <ip> is the string representation of the IP addr of the machine and <princ> its Kerberos principal. You may split the IP Address to make a hierarchical tree structure. <node_name> is optional, and refers to the eponym server configuration.")
                                .arg(arg!(<base> "Base path"))
                                .arg(
                                    arg!(--"split-on-addr-index" <INDEX> "If specified, splits the IP address on the n-th segment. For example, with an IPv4 addr a.b.c.d, using --split-on-addr-index 1 will result in <ip> being \"a/a.b/a.b.c/a.b.c.d\"")
                                    .value_parser(value_parser!(u8))
                                )
                                .arg(
                                    arg!(--"append-node-name" "Append the configured node name at the end of the generated path (parent dir of <filename>)")
                                )
                                .arg(arg!(--filename <FILENAME> "Name of the file where logs will be written.").default_value("messages"))
                            )
                        )
                        .subcommand(
                            Command::new("delete")
                            .about("Deletes an output of this subscription")
                            .arg(arg!(-y --yes "Do not prompt for confirmation"))
                            .arg(arg!(<index> "Index of the output to delete").value_parser(value_parser!(usize)))
                        )
                        .subcommand(
                            Command::new("enable")
                            .about("Enables an output of this subscription")
                            .arg(arg!(<index> "Index of the output to enable").value_parser(value_parser!(usize)))
                        )
                        .subcommand(
                            Command::new("disable")
                            .about("Disables an output of this subscription")
                            .arg(arg!(-y --yes "Do not prompt for confirmation"))
                            .arg(arg!(<index> "Index of the output to disable").value_parser(value_parser!(usize)))
                        )
                    )
                    .arg(arg!(-q --query <QUERY> "File containing the query (XML format)"))
                    .arg(arg!(-r --rename <NAME> "Rename the subscription"))
                    .arg(
                        arg!(-u --uri [URI] "URI linked to this subscription. \
                        The subscription will only be presented to hosts using this URI to retrieve their subscriptions. \
                        Set this flag without value to present the subscription regardless of the URI (default). \
                        Example: /my/custom/uri.")
                    )
                    .arg(
                        arg!(--"heartbeat-interval" <HEARTBEAT> "Heartbeat interval")
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"connection-retry-count" <CONNECTION_RETRY_COUNT> "Connection retry count")
                        .value_parser(value_parser!(u16))
                    )
                    .arg(
                        arg!(--"connection-retry-interval" <CONNECTION_RETRY_INTERVAL> "Connection retry interval")
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"max-time" <MAX_TIME> "Max time") // TODO: improve help
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"max-envelope-size" <MAX_ENVELOPE_SIZE> "Max envelope size") // TODO: improve help
                        .value_parser(value_parser!(u32))
                    )
                    .arg(
                        arg!(--"enable" "Enable the subscription")
                    )
                    .arg(
                        arg!(--"disable" "Disable the subscription")
                    )
                    .group(ArgGroup::new("subscription_status").args(["enable", "disable"]).required(false))
                    .arg(
                        arg!(--"content-format" <CONTENT_FORMAT> "If set to Raw, retrieve only the \
                        EventData part of events. If set to RenderedText, retrieve the \
                        RenderingInfo part as well. RenderingInfo increases the size of events \
                        but can help with analysis.")
                        .value_parser(["Raw", "RenderedText"])
                    )
                    .arg(
                        arg!(--"ignore-channel-error" <BOOL> "Configure clients to ignore filtering errors or not.").value_parser(value_parser!(bool))
                    )
                )
                .subcommand(
                    Command::new("show")
                    .about("Show an existing subscription")
                    .arg(arg!(<subscription> "Name or UUID of the subscription"))
                )
                .subcommand(
                    Command::new("duplicate")
                    .about("Duplicate an existing subscription. The newly created subscription will be disabled by default.")
                    .arg(arg!(<subscription> "Name or UUID of the subscription to copy"))
                    .arg(arg!(<name> "Name of the newly created subcription"))
                )
                .subcommand(
                    Command::new("export")
                    .about("Export existing subscriptions in a json file")
                    .arg(arg!(-s --subscription <SUBSCRIPTION> "Name or UUID of a subscription if you want to export only one of them"))
                )
                .subcommand(
                    Command::new("import")
                    .about("Import subscriptions from a json file")
                    .arg(arg!(
                        -f --format <FORMAT> "Format of the file. `openwec` format is generated using `openwec export`. \
                        `windows` format comes from an export of a Windows Event Collector subscription."
                    ).value_parser(["openwec", "windows"]).default_value("openwec"))
                    .arg(arg!(
                        <file> "file to import"
                    ))
                )
                .subcommand(
                    Command::new("delete")
                    .about("Delete an existing subscription")
                    .arg(arg!(-y --yes "Do not prompt for confirmation"))
                    .arg(arg!(<subscription> "Name or UUID of the subscription"))
                )
                .subcommand(
                    Command::new("machines")
                    .about("Show subscribing machines. Defaults to all machines ever seen.")
                    .arg(arg!(<subscription> "Name or UUID of the subscription"))
                    .arg(arg!(-a --active "Only show active machines"))
                    .arg(arg!(-l --alive "Only show machines that are alive but not active"))
                    .arg(arg!(-d --dead "Only show dead machines principal"))
                    .arg(
                        arg!(-i --interval <INTERVAL> "Duration after which a machine is considered alive if no events are received or dead if no heartbeats are received. \
                            Defaults to heartbeat-interval")
                            .value_parser(value_parser!(u32))
                    )
                    .group(ArgGroup::new("subscription_machines_state").args(["active", "alive", "dead"]).required(false))
                )
                .subcommand(
                    Command::new("enable")
                    .about("Enable one or more subscriptions")
                    .arg(arg!(-a --all "Enable all subscriptions"))
                    .arg(arg!(<subscriptions> ... "Name or UUID of subscriptions to enable").action(ArgAction::Append).required(false))
                )
                .subcommand(
                    Command::new("disable")
                    .about("Disable one or more subscriptions")
                    .arg(arg!(-a --all "Disable all subscriptions"))
                    .arg(arg!(<subscriptions> ... "Name or UUID of subscriptions to disable").action(ArgAction::Append).required(false))
                )
                .subcommand(
                    Command::new("reload")
                    .about("Force openwec server to reload subscriptions outputs and clients to establish a new connection.")
                    .arg(arg!(-a --all "Reload all subscriptions"))
                    .arg(arg!(<subscriptions> ... "Name or UUID of subscriptions").action(ArgAction::Append).required(false))
                )
        )
        .subcommand(
            Command::new("heartbeats")
                .about("Retrieve machine heartbeats")
                .arg(arg!(-s --subscription <SUBSCRIPTION> "Name or UUID of a subscription"))
                .arg(arg!(-m --machine<HOSTNAME> "Name of a specific machine"))
                .arg(arg!(-a --address <ADDR> "IP Address of a specific machine"))
                .group(ArgGroup::new("host")
                    .args(["machine", "address"])
                    .required(false))
                .arg(arg!(-f --format <FORMAT> "Output format").value_parser(["text", "json"]).default_value("text"))
        )
        .subcommand(
            Command::new("bookmarks")
                .about("Manipulate bookmarks")
                .subcommand(
                    Command::new("show")
                    .about("Prints bookmarks")
                    .arg(arg!(<subscription> "Name or UUID of a subscription"))
                    .arg(arg!(-m --machine <MACHINE> "Name of a specific machine"))
                )
                .subcommand(
                    Command::new("delete")
                    .about("Delete bookmarks (dangerous!)")
                    .arg(arg!(-s --subscription <SUBSCRIPTION> "Name or UUID of a subscription"))
                    .arg(arg!(-m --machine <MACHINE> "Name of a specific machine"))
                )
                .subcommand(
                    Command::new("copy")
                    .about("Copy bookmarks from a subscription to another subscription (dangerous!)")
                    .arg(arg!(-m --machine <MACHINE> "Name of a specific machine"))
                    .arg(arg!(<source> "Name or UUID of the source subscription"))
                    .arg(arg!(<destination> "Name or UUID of the destination subscription"))
                )
        )
        .subcommand(
            Command::new("stats")
                .about("Retrieve usage statistics")
                .arg(arg!(-s --subscription <SUBSCRIPTION> "Name or UUID of a subscription"))
                .arg(arg!(-f --format <FORMAT> "Output format").value_parser(["text", "json"]).default_value("text"))
                .arg(
                    arg!(-i --interval <INTERVAL> "Duration after which a machine is considered alive if no events are received or dead if no heartbeats are received. \
                        Defaults to heartbeat-interval")
                        .value_parser(value_parser!(u32))
                )
        )
        .subcommand(
            Command::new("db")
                .about("Database operations")
                .subcommand(
                    Command::new("init")
                    .about("Initialize database schema")
                )
                .subcommand(
                    Command::new("upgrade")
                    .about("Upgrade database schema")
                    .arg(
                        arg!(-t --to <VERSION> "Schema version to upgrade to. Defaults to last version.")
                        .value_parser(value_parser!(Version))
                    )
                )
                .subcommand(
                    Command::new("downgrade")
                    .about("Downgrade database schema")
                    .arg(
                        arg!(-t --to <VERSION> "Schema version to downgrade to. Defaults to second to last version.")
                        .value_parser(value_parser!(Version))
                    )
                )
        );

    let help_str = command.render_help();
    let matches = command.get_matches();

    if env::var("OPENWEC_LOG").is_err() {
        env::set_var(
            "OPENWEC_LOG",
            match matches.get_count("verbosity") {
                0 => "warn",
                1 => "info",
                2 => "debug",
                _ => "trace",
            },
        );
    }

    env_logger::Builder::from_env("OPENWEC_LOG")
        .format_module_path(false)
        .format_timestamp(None)
        .init();

    match cli::run(matches, help_str).await {
        Ok(_) => (),
        Err(err) => {
            eprintln!("An error occurred: {:?}", err);
            std::process::exit(1);
        }
    };
}
