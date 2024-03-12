use anyhow::{Error, Result};
use serde::Deserialize;
use std::str::FromStr;
use std::{fs::File, io::Read};

pub const DEFAULT_CONFIG_FILE: &str = "/etc/openwec.conf.toml";

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Authentication {
    Kerberos(Kerberos),
    Tls(Tls),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Database {
    SQLite(SQLite),
    Postgres(Postgres),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    server_certificate: String,
    server_private_key: String,
    ca_certificate: String,
}

impl Tls {
    pub fn server_certificate(&self) -> &str {
        self.server_certificate.as_ref()
    }

    pub fn server_private_key(&self) -> &str {
        self.server_private_key.as_ref()
    }

    pub fn ca_certificate(&self) -> &str {
        self.ca_certificate.as_ref()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Collector {
    hostname: String,
    listen_address: String,
    listen_port: Option<u16>,
    max_content_length: Option<u64>,
    authentication: Authentication,
}

impl Collector {
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn listen_address(&self) -> &str {
        &self.listen_address
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(5985)
    }

    pub fn max_content_length(&self) -> u64 {
        self.max_content_length.unwrap_or(512_000)
    }
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Kerberos {
    service_principal_name: String,
}

impl Kerberos {
    pub fn empty() -> Self {
        Kerberos {
            service_principal_name: String::new(),
        }
    }

    pub fn service_principal_name(&self) -> &str {
        &self.service_principal_name
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SQLite {
    path: String,
}

impl SQLite {
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
pub enum PostgresSslMode {
    Disable,
    #[default]
    Prefer,
    Require,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Postgres {
    host: String,
    port: u16,
    dbname: String,
    user: String,
    password: String,
    #[serde(default)]
    ssl_mode: PostgresSslMode,
    ca_file: Option<String>,
    max_chunk_size: Option<usize>,
}

impl Postgres {
    #[cfg(test)]
    pub fn new(
        host: &str,
        port: u16,
        dbname: &str,
        user: &str,
        password: &str,
        ssl_mode: PostgresSslMode,
        ca_file: Option<&String>,
        max_chunk_size: Option<usize>,
    ) -> Postgres {
        Postgres {
            host: host.to_owned(),
            port,
            dbname: dbname.to_owned(),
            user: user.to_owned(),
            password: password.to_owned(),
            ssl_mode,
            ca_file: ca_file.cloned(),
            max_chunk_size,
        }
    }

    pub fn host(&self) -> &str {
        self.host.as_ref()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn user(&self) -> &str {
        self.user.as_ref()
    }

    pub fn password(&self) -> &str {
        self.password.as_ref()
    }

    pub fn dbname(&self) -> &str {
        self.dbname.as_ref()
    }

    pub fn ssl_mode(&self) -> &PostgresSslMode {
        &self.ssl_mode
    }

    pub fn ca_file(&self) -> Option<&String> {
        self.ca_file.as_ref()
    }

    pub fn max_chunk_size(&self) -> usize {
        self.max_chunk_size.unwrap_or(500)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum LoggingType {
    Stdout,
    Stderr,
    File(String),
}

impl FromStr for LoggingType {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s_lower = s.to_lowercase();
        if s_lower == "stdout" {
            Ok(LoggingType::Stdout)
        } else if s_lower == "stderr" {
            Ok(LoggingType::Stderr)
        } else {
            Ok(LoggingType::File(s.to_owned()))
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    verbosity: Option<String>,
    access_logs: Option<String>,
    access_logs_pattern: Option<String>,
    server_logs: Option<String>,
    server_logs_pattern: Option<String>,
}

impl Logging {
    pub fn verbosity(&self) -> Option<&String> {
        self.verbosity.as_ref()
    }

    pub fn access_logs(&self) -> Option<LoggingType> {
        // Access logs defaults to None (don't log access)
        self.access_logs
            .as_ref()
            .map(|s| LoggingType::from_str(s).expect("Can not happen"))
    }

    pub fn server_logs(&self) -> LoggingType {
        match &self.server_logs {
            Some(s) => LoggingType::from_str(s).expect("Can not happen"),
            None => LoggingType::Stderr,
        }
    }

    pub fn access_logs_pattern(&self) -> String {
        match &self.access_logs_pattern {
            Some(s) => s.to_owned(),
            None => "{X(ip)}:{X(port)} - {X(principal)} [{d}] \"{X(http_uri)}\" {X(http_status)} {X(response_time)}{n}".to_owned()
        }
    }

    pub fn server_logs_pattern(&self) -> Option<&String> {
        self.server_logs_pattern.as_ref()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Server {
    db_sync_interval: Option<u64>,
    flush_heartbeats_interval: Option<u64>,
    heartbeats_queue_size: Option<u64>,
    node_name: Option<String>,
    keytab: Option<String>,
    tcp_keepalive_time: Option<u64>,
    tcp_keepalive_intvl: Option<u64>,
    tcp_keepalive_probes: Option<u32>,
}

impl Server {
    pub fn db_sync_interval(&self) -> u64 {
        self.db_sync_interval.unwrap_or(5)
    }

    pub fn flush_heartbeats_interval(&self) -> u64 {
        self.flush_heartbeats_interval.unwrap_or(5)
    }

    pub fn node_name(&self) -> Option<&String> {
        self.node_name.as_ref()
    }

    pub fn heartbeats_queue_size(&self) -> u64 {
        self.heartbeats_queue_size.unwrap_or(2048)
    }

    pub fn keytab(&self) -> Option<&String> {
        self.keytab.as_ref()
    }

    pub fn tcp_keepalive_time(&self) -> u64 {
        self.tcp_keepalive_time.unwrap_or(7200)
    }

    pub fn tcp_keepalive_intvl(&self) -> Option<u64> {
        self.tcp_keepalive_intvl
    }

    pub fn tcp_keepalive_probes(&self) -> Option<u32> {
        self.tcp_keepalive_probes
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Cli {
    // When set, subscriptions can only be written using 
    // openwec subscriptions load`, defaults to false.
    #[serde(default)]
    read_only_subscriptions: bool,
}

impl Cli {
    pub fn read_only_subscriptions(&self) -> bool {
        self.read_only_subscriptions
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    collectors: Vec<Collector>,
    database: Database,
    server: Server,
    logging: Logging,
    #[serde(default)]
    cli: Cli
}

impl std::str::FromStr for Settings {
    type Err = anyhow::Error;
    fn from_str(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(anyhow::Error::from)
    }
}

impl Settings {
    pub fn new(config_file: Option<&String>) -> Result<Self> {
        let default = DEFAULT_CONFIG_FILE.to_owned();
        let path = config_file.unwrap_or(&default);
        let mut content = String::new();
        File::open(path)?.read_to_string(&mut content)?;
        Settings::from_str(&content)
    }

    pub fn collectors(&self) -> &[Collector] {
        self.collectors.as_ref()
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    pub fn logging(&self) -> &Logging {
        &self.logging
    }

    pub fn cli(&self) -> &Cli {
        &self.cli
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_KERBEROS_SQLITE: &str = r#"
        [server]
        keytab = "wec.windomain.local.keytab"
        tcp_keepalive_time = 3600
        tcp_keepalive_intvl = 1
        tcp_keepalive_probes = 10

        [logging]
        verbosity = "debug"
        server_logs = "stdout"

        [database]
        type =  "SQLite"
        path = "/tmp/toto.sqlite"

        [[collectors]]
        hostname = "wec.windomain.local"
        listen_address = "0.0.0.0"
        listen_port = 5986
        max_content_length = 1000

        [collectors.authentication]
        type = "Kerberos"
        service_principal_name = "http/wec.windomain.local@WINDOMAIN.LOCAL"
    "#;

    #[test]
    fn test_settings_kerberos_sqlite() {
        let s = Settings::from_str(CONFIG_KERBEROS_SQLITE).unwrap();
        assert_eq!(s.collectors().len(), 1);
        let collector = &s.collectors()[0];
        assert_eq!(collector.hostname(), "wec.windomain.local");
        assert_eq!(collector.listen_address(), "0.0.0.0");
        assert_eq!(collector.listen_port(), 5986);
        assert_eq!(collector.max_content_length(), 1000);

        let kerberos = match collector.authentication() {
            Authentication::Kerberos(kerb) => kerb,
            _ => panic!("Wrong authentication type"),
        };
        assert_eq!(s.server().keytab().unwrap(), "wec.windomain.local.keytab");
        assert_eq!(
            kerberos.service_principal_name(),
            "http/wec.windomain.local@WINDOMAIN.LOCAL"
        );

        let sqlite = match s.database() {
            Database::SQLite(sqlite) => sqlite,
            _ => panic!("Wrong database type"),
        };

        assert_eq!(sqlite.path(), "/tmp/toto.sqlite");

        assert_eq!(s.logging().verbosity().unwrap(), "debug");
        assert!(s.logging().access_logs().is_none());
        assert_eq!(s.logging().server_logs(), LoggingType::Stdout);
        assert_eq!(s.server().tcp_keepalive_time(), 3600);
        assert_eq!(s.server().tcp_keepalive_intvl().unwrap(), 1);
        assert_eq!(s.server().tcp_keepalive_probes().unwrap(), 10);
    }

    const CONFIG_TLS_POSTGRES: &str = r#"
        [server]

        [logging]
        access_logs = "/tmp/toto"
        server_logs_pattern = "toto"
        access_logs_pattern = "tutu"

        [database]
        type =  "Postgres"
        host = "localhost"
        port = 26257
        dbname = "test"
        user = "root"
        password = ""

        [[collectors]]
        hostname = "wec.windomain.local"
        listen_address = "0.0.0.0"

        [collectors.authentication]
        type = "Tls"
        server_certificate = "/etc/server_certificate.pem"
        server_private_key = "/etc/server_private_key.pem"
        ca_certificate = "/etc/ca_certificate.pem"
    "#;

    #[test]
    fn test_settings_tls_postgres() {
        let s = Settings::from_str(CONFIG_TLS_POSTGRES).unwrap();
        assert_eq!(s.collectors().len(), 1);
        let collector = &s.collectors()[0];
        assert_eq!(collector.hostname(), "wec.windomain.local");
        assert_eq!(collector.listen_address(), "0.0.0.0");
        // Checks default values
        assert_eq!(collector.listen_port(), 5985);
        assert_eq!(collector.max_content_length(), 512_000);

        let tls = match collector.authentication() {
            Authentication::Tls(tls) => tls,
            _ => panic!("Wrong authentication type"),
        };
        assert_eq!(tls.server_certificate(), "/etc/server_certificate.pem");
        assert_eq!(tls.server_private_key(), "/etc/server_private_key.pem");
        assert_eq!(tls.ca_certificate(), "/etc/ca_certificate.pem");

        let postgres = match s.database() {
            Database::Postgres(postgres) => postgres,
            _ => panic!("Wrong database type"),
        };

        assert_eq!(postgres.host(), "localhost");
        assert_eq!(postgres.port(), 26257);
        assert_eq!(postgres.dbname(), "test");
        assert_eq!(postgres.user(), "root");
        assert_eq!(postgres.password(), "");

        assert!(s.logging().verbosity().is_none());
        assert_eq!(
            s.logging().access_logs(),
            Some(LoggingType::File("/tmp/toto".to_string()))
        );
        assert_eq!(s.logging().server_logs(), LoggingType::Stderr,);
        assert_eq!(s.logging().server_logs_pattern().unwrap(), "toto");
        assert_eq!(s.logging().access_logs_pattern(), "tutu");
        assert_eq!(s.server().tcp_keepalive_time(), 7200);
        assert!(s.server().tcp_keepalive_intvl().is_none());
        assert!(s.server().tcp_keepalive_probes().is_none());
        assert_eq!(s.cli().read_only_subscriptions(), false);
    }

    const CONFIG_TLS_POSTGRES_WITH_CLI: &str = r#"
        [server]

        [logging]
        access_logs = "/tmp/toto"
        server_logs_pattern = "toto"
        access_logs_pattern = "tutu"

        [database]
        type =  "Postgres"
        host = "localhost"
        port = 26257
        dbname = "test"
        user = "root"
        password = ""

        [[collectors]]
        hostname = "wec.windomain.local"
        listen_address = "0.0.0.0"

        [collectors.authentication]
        type = "Tls"
        server_certificate = "/etc/server_certificate.pem"
        server_private_key = "/etc/server_private_key.pem"
        ca_certificate = "/etc/ca_certificate.pem"

        [cli]
        read_only_subscriptions = true
    "#;

    #[test]
    fn test_settings_tls_postgres_with_cli() {
        let s = Settings::from_str(CONFIG_TLS_POSTGRES_WITH_CLI).unwrap();
        assert_eq!(s.cli().read_only_subscriptions(), true);
    }
}
