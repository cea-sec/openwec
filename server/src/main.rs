use clap::{arg, command};
use common::settings::{Settings, DEFAULT_CONFIG_FILE};
use server::run;
use std::env;

#[tokio::main]
async fn main() {
    let matches = command!()
        .name("openwecd")
        .arg(
            arg!(-c --config <FILE> "Sets a custom config file")
                .default_value(DEFAULT_CONFIG_FILE)
                .required(false),
        )
        .arg(arg!(-v --verbosity ... "Sets the level of verbosity"))
        .get_matches();

    let config_file = matches.get_one::<String>("config");
    let settings = match Settings::new(config_file) {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("Could not load config: {}", err);
            std::process::exit(1);
        }
    };

    if env::var("OPENWEC_LOG").is_err() {
        if matches.get_count("verbosity") > 0 {
            env::set_var(
                "OPENWEC_LOG",
                match matches.get_count("verbosity") {
                    1 => "info",
                    2 => "debug",
                    _ => "trace",
                },
            );
        } else if let Some(verbosity) = settings.server().verbosity() {
            env::set_var("OPENWEC_LOG", verbosity);
        } else {
            env::set_var("OPENWEC_LOG", "warn");
        }
    }

    env_logger::Builder::from_env("OPENWEC_LOG")
        .format_module_path(false)
        .format_timestamp(None)
        .init();

    run(settings).await;
}
