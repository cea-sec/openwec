use std::sync::Arc;

use crate::database::sqlite::SQLiteDatabase;

use self::{
    _001_create_subscriptions_table::CreateSubscriptionsTable,
    _002_create_bookmarks_table::CreateBookmarksTable,
    _003_create_heartbeats_table::CreateHeartbeatsTable,
    _004_add_last_event_seen_field_in_heartbeats_table::AddLastEventSeenFieldInHeartbeatsTable,
    _005_add_uri_field_in_subscriptions_table::AddUriFieldInSubscriptionsTable,
    _006_add_content_format_field_in_subscriptions_table::AddContentFormatFieldInSubscriptionsTable,
};

mod _001_create_subscriptions_table;
mod _002_create_bookmarks_table;
mod _003_create_heartbeats_table;
mod _004_add_last_event_seen_field_in_heartbeats_table;
mod _005_add_uri_field_in_subscriptions_table;
mod _006_add_content_format_field_in_subscriptions_table;

pub fn register_migrations(sqlite_db: &mut SQLiteDatabase) {
    sqlite_db.register_migration(Arc::new(CreateSubscriptionsTable));
    sqlite_db.register_migration(Arc::new(CreateBookmarksTable));
    sqlite_db.register_migration(Arc::new(CreateHeartbeatsTable));
    sqlite_db.register_migration(Arc::new(AddLastEventSeenFieldInHeartbeatsTable));
    sqlite_db.register_migration(Arc::new(AddUriFieldInSubscriptionsTable));
    sqlite_db.register_migration(Arc::new(AddContentFormatFieldInSubscriptionsTable));
}
