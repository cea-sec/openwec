use std::sync::Arc;

use crate::database::postgres::PostgresDatabase;

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
    _014_alter_client_filter_in_subscriptions::AlterClientFilterInSubscriptionsTable,
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
mod _014_alter_client_filter_in_subscriptions;

pub fn register_migrations(postgres_db: &mut PostgresDatabase) {
    postgres_db.register_migration(Arc::new(CreateSubscriptionsTable));
    postgres_db.register_migration(Arc::new(CreateBookmarksTable));
    postgres_db.register_migration(Arc::new(CreateHeartbeatsTable));
    postgres_db.register_migration(Arc::new(AddLastEventSeenFieldInHeartbeatsTable));
    postgres_db.register_migration(Arc::new(AddUriFieldInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AddContentFormatFieldInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AddIgnoreChannelErrorFieldInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AddPrincsFilterFieldsInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AlterOutputsFormat));
    postgres_db.register_migration(Arc::new(AddRevisionFieldInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AddLocaleFieldsInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AlterOutputsFilesConfig));
    postgres_db.register_migration(Arc::new(AddMaxElementsFieldInSubscriptionsTable));
    postgres_db.register_migration(Arc::new(AlterClientFilterInSubscriptionsTable));
}
