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

    let verbosity = matches.get_count("verbosity");

    run(settings, verbosity).await;
}
