use std::str::FromStr;

use anyhow::{Context, Result};
use common::settings::{LoggingType, Settings};
use log::{info, warn, LevelFilter};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
        Append,
    },
    config::{Appender, Logger, Root},
    encode::pattern::PatternEncoder,
    Config, Handle,
};
use tokio::signal::unix::{signal, SignalKind};

pub static ACCESS_LOGGER: &str = "access";
pub static SERVER_LOGGER: &str = "server";

pub fn init(settings: &Settings, verbosity: u8) -> Result<()> {
    let config = create_config(settings, verbosity)?;
    let handle = log4rs::init_config(config).unwrap();

    let settings_owned = settings.clone();

    // Loggers are reloaded when a SIGHUP signal is received
    // This is required by utilities like logrotate
    tokio::spawn(async move { reload_loggers(handle, settings_owned, verbosity).await });
    Ok(())
}

fn create_appender(
    logging_type: &LoggingType,
    pattern_opt: Option<&String>,
) -> Result<Box<dyn Append>> {
    let encoder = if let Some(pattern) = pattern_opt {
        Box::new(PatternEncoder::new(pattern))
    } else {
        Box::<PatternEncoder>::default()
    };
    match logging_type {
        LoggingType::Stdout => Ok(Box::new(
            ConsoleAppender::builder()
                .encoder(encoder)
                .target(Target::Stdout)
                .build(),
        )),
        LoggingType::Stderr => Ok(Box::new(
            ConsoleAppender::builder()
                .encoder(encoder)
                .target(Target::Stderr)
                .build(),
        )),
        LoggingType::File(path) => {
            let appender = FileAppender::builder()
                .encoder(encoder)
                .append(true)
                .build(path)
                .context("Failed to create FileAppender")?;
            Ok(Box::new(appender))
        }
    }
}

fn get_level_filter(verbosity_arg_count: u8, verbosity_setting: Option<&String>) -> LevelFilter {
    if verbosity_arg_count > 0 {
        match verbosity_arg_count {
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    } else if let Some(verbosity) = verbosity_setting {
        LevelFilter::from_str(verbosity).unwrap_or_else(|err| {
            eprintln!(
                "Could not parse verbosity level \"{}\": {}. Fallback to \"warn\".",
                verbosity, err
            );
            LevelFilter::Warn
        })
    } else {
        LevelFilter::Warn
    }
}

fn create_config(settings: &Settings, verbosity_arg_count: u8) -> Result<Config> {
    let mut builder = Config::builder();

    builder = builder.appender(
        Appender::builder().build(
            SERVER_LOGGER,
            create_appender(
                &settings.logging().server_logs(),
                settings.logging().server_logs_pattern(),
            )
            .context("Could not create server logger")?,
        ),
    );

    if let Some(access_logs) = settings.logging().access_logs() {
        // Configure access logging
        // Access logs level is always "info"
        builder = builder
            .appender(
                Appender::builder().build(
                    ACCESS_LOGGER,
                    create_appender(
                        &access_logs,
                        Some(&settings.logging().access_logs_pattern()),
                    )
                    .context("Could not create access logger")?,
                ),
            )
            .logger(
                Logger::builder()
                    .appender(ACCESS_LOGGER)
                    .additive(false)
                    .build(ACCESS_LOGGER, LevelFilter::Info),
            );
    } else {
        // Deactivate access logs (levelFilter::Off)
        builder = builder.logger(
            Logger::builder()
                .appender(SERVER_LOGGER)
                .additive(false)
                .build(ACCESS_LOGGER, LevelFilter::Off),
        );
    }

    builder
        .build(
            Root::builder()
                .appender(SERVER_LOGGER)
                .build(get_level_filter(
                    verbosity_arg_count,
                    settings.logging().verbosity(),
                )),
        )
        .context("Could not build logger config")
}

async fn reload_loggers(handle: Handle, settings: Settings, verbosity_arg_count: u8) {
    let mut sighup = signal(SignalKind::hangup()).expect("Could not listen to SIGHUP");

    loop {
        sighup.recv().await;
        match create_config(&settings, verbosity_arg_count) {
            Ok(c) => handle.set_config(c),
            Err(e) => warn!("Could not reload logger: {:?}", e),
        };
        info!("Logger config reloaded");
    }
}
