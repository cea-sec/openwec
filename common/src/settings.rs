use anyhow::Result;
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
pub struct Kerberos {
    service_principal_name: String,
    keytab: String,
}

impl Kerberos {
    pub fn service_principal_name(&self) -> &str {
        &self.service_principal_name
    }

    pub fn keytab(&self) -> &str {
        &self.keytab
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SQLite {
    path: String,
}

impl SQLite {
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum PostgresSslMode {
    Disable,
    Prefer,
    Require,
}

impl Default for PostgresSslMode {
    fn default() -> Self {
        PostgresSslMode::Prefer
    }
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
pub struct Server {
    verbosity: Option<String>,
    db_sync_interval: Option<u64>,
    flush_heartbeats_interval: Option<u64>,
    heartbeats_queue_size: Option<u64>,
    node_name: Option<String>,
}

impl Server {
    pub fn verbosity(&self) -> Option<&String> {
        self.verbosity.as_ref()
    }

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
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    collectors: Vec<Collector>,
    database: Database,
    server: Server,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_KERBEROS_SQLITE: &str = r#"
        [server]
        verbosity = "debug"

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
        keytab = "wec.windomain.local.keytab"
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
        assert_eq!(kerberos.keytab(), "wec.windomain.local.keytab");
        assert_eq!(
            kerberos.service_principal_name(),
            "http/wec.windomain.local@WINDOMAIN.LOCAL"
        );

        let sqlite = match s.database() {
            Database::SQLite(sqlite) => sqlite,
            _ => panic!("Wrong database type"),
        };

        assert_eq!(sqlite.path(), "/tmp/toto.sqlite");
        assert_eq!(s.server().verbosity().unwrap(), "debug");
    }

    const CONFIG_TLS_POSTGRES: &str = r#"
        [server]

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
        assert!(s.server().verbosity().is_none());
    }
}
