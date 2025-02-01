use crate::database::redis::RedisDatabase;

pub mod v1;

pub fn register_migrations(_redis_db: &mut RedisDatabase) {
    // for future changes
}
