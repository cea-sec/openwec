# Database

OpenWEC subscriptions and their metadata are stored in an external database. To be more precise, data stored in the database are:
* subscriptions (parameters and outputs)
* bookmarks
* heartbeats

OpenWEC server uses the database heavily:
- a bookmark is stored at each events batch received from each client.
- a bookmark is retrieved each time a client enumerates subscriptions.
- heartbeats are stored in batch at a fixed interval (see OpenWEC configuration).

The most precious information stored in the database is undoutbly bookmarks. A *bookmark* represents a pointer to a location in the stream of events, for each client and each subscription. If you lose them, you will probably lose event logs. Therefore, you should definitely backup regularly the database.

The size of the database is proportionnal to the number of clients and subscriptions, but should be relatively small compared to the size of collected events.

OpenWEC database schema must be initialized manually on installation using `openwec db init`.

OpenWEC database schema may be updated from one version to another. This is handled by a migration system. If you run an OpenWEC binary with an outdated database schema version, it will fail and tell you to run `openwec db upgrade`. This command will apply the required migrations to upgrade your database schema.

## Available commands

### `openwec db init`

This command initializes the database schema. On SQL based database backends, it creates tables and indexes.

### `openwec db upgrade`

This command upgrades the current database schema by applying required migrations. Database schema upgrades can update schema but also stored data. **Before applying a migration, you should always check its related release note** (if not its code).

### `openwec db downgrade`

This command downgrades the current database schema by inversing previously applied migrations. This may be usefull "one day" if an OpenWEC version that came with a database migration has critical bugs and a rollback is required, so better safe than sorry.

## Available database backends

### SQLite (on disk)

SQLite is simple and yet powerful. It is great for testing and simple environments. However, redundancy and load balancing is not possible using SQLite.

#### Configuration sample

```toml
[database]
# [Required]
# Database type: SQLite | Postgres
type = "SQLite"

# SQLite DB path
# The SQLite DB will be created and initialized if not already existing
path = "/var/db/openwec/openwec.sqlite"
```

### PostgreSQL

For redundancy and/or scaling, you probably want to setup multiple OpenWEC nodes in different availability zones. To do that, you must use an external database storage backend such as PostgreSQL. Note that OpenWEC's PostgreSQL client is optimized to be used with [CockroachDB](https://github.com/cockroachdb/cockroach).

#### Configuration sample

```toml
[database]
# [Required]
# Database type: SQLite | Postgres
type = "Postgres"

## Postgres configuration

# [Required]
# Postgres database Hostname
host = "localhost"

# [Required]
# Postgres database port
port = 5432 

# [Required]
# Postgres database name. It must already exist and user <postgres.user> should
# have all permissions on it.
dbname = "openwec"

# [Required]
# Postgres database user. It must already exist and have all permissions
# on <postgres.dbname>.
user = "openwec"

# [Required]
# Postgres database user password
password = ""

# [Optional]
# Postgres SSL mode. Possibles values are:
# - Disable: Do not use TLS
# - Prefer: Attempt to connect with TLS but allow sessions without
# - Require: Require the use of TLS
# ssl_mode = "Prefer"

# [Optional]
# Custom SSL CA certificate file
# When ssl_mode is Prefer or Require, you may want to use a specific CA
# certificate file instead of the ones trusted by your system (default).
# ca_file = unset

# [Optional]
# Max chunk size
# When performing bulk insert queries, this is the maximum number of
# entries that will be inserted in one query.
# max_chunk_size = 500
```

## How to add a new database backend ?

TODO
