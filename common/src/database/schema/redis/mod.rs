use std::sync::Arc;

use crate::database::redis::RedisDatabase;

use self::{
    _001_create_subscriptions_table::CreateSubscriptionsTable,
    _002_create_bookmarks_table::CreateBookmarksTable,
    _003_create_heartbeats_table::CreateHeartbeatsTable,
    _004_add_last_event_seen_field_in_heartbeats_table::AddLastEventSeenFieldInHeartbeatsTable,
    _005_add_uri_field_in_subscriptions_table::AddUriFieldInSubscriptionsTable,
    _006_add_content_format_field_in_subscriptions_table::AddContentFormatFieldInSubscriptionsTable,
    _007_add_ignore_channel_error_field_in_subscriptions_table::AddIgnoreChannelErrorFieldInSubscriptionsTable,
    _008_add_princs_filter_fields_in_subscriptions_table::AddPrincsFilterFieldsInSubscriptionsTable,
    _009_alter_outputs_format::AlterOutputsFormat,
    _010_add_revision_field_in_subscriptions_table::AddRevisionFieldInSubscriptionsTable,
    _011_add_locale_fields_in_subscriptions_table::AddLocaleFieldsInSubscriptionsTable,
    _012_alter_outputs_files_config::AlterOutputsFilesConfig,
    _013_add_max_elements_field_in_subscriptions_table::AddMaxElementsFieldInSubscriptionsTable,
};

mod _001_create_subscriptions_table;
mod _002_create_bookmarks_table;
mod _003_create_heartbeats_table;
mod _004_add_last_event_seen_field_in_heartbeats_table;
mod _005_add_uri_field_in_subscriptions_table;
mod _006_add_content_format_field_in_subscriptions_table;
mod _007_add_ignore_channel_error_field_in_subscriptions_table;
mod _008_add_princs_filter_fields_in_subscriptions_table;
mod _009_alter_outputs_format;
mod _010_add_revision_field_in_subscriptions_table;
mod _011_add_locale_fields_in_subscriptions_table;
mod _012_alter_outputs_files_config;
mod _013_add_max_elements_field_in_subscriptions_table;

pub fn register_migrations(redis_db: &mut RedisDatabase) {
    redis_db.register_migration(Arc::new(CreateSubscriptionsTable));
    redis_db.register_migration(Arc::new(CreateBookmarksTable));
    redis_db.register_migration(Arc::new(CreateHeartbeatsTable));
    redis_db.register_migration(Arc::new(AddLastEventSeenFieldInHeartbeatsTable));
    redis_db.register_migration(Arc::new(AddUriFieldInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AddContentFormatFieldInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AddIgnoreChannelErrorFieldInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AddPrincsFilterFieldsInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AlterOutputsFormat));
    redis_db.register_migration(Arc::new(AddRevisionFieldInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AddLocaleFieldsInSubscriptionsTable));
    redis_db.register_migration(Arc::new(AlterOutputsFilesConfig));
    redis_db.register_migration(Arc::new(AddMaxElementsFieldInSubscriptionsTable));
}
