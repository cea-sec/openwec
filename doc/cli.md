# Command Line Interface

OpenWEC is composed of two binaries:
- `openwecd`: OpenWEC server
- `openwec`: OpenWEC CLI

The CLI enables the user to manage its OpenWEC installation which means:
- modifying subscriptions
- getting statistics
- getting informations about machines activity
- doing database schema migrations
- ...

OpenWEC works by storing a lot of information, notably its subscriptions, in an external [database](database.md). `openwec` CLI only interacts with this database, and **does not communicate directly with openwecd server**.

This conception choice enables a multi-node OpenWEC cluster to be administrated from only one of its nodes. Information retrieved using the `openwec` CLI and changes made using the CLI apply to the entire cluster at once.
