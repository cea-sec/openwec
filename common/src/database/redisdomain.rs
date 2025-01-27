use deadpool_redis::redis::{self, ToRedisArgs};
use strum::{Display, EnumString};

#[derive(Debug, Eq, Hash, PartialEq, EnumString, Display)]
pub enum RedisDomain {
    Users,
    Subscription,
    Machine,
    Heartbeat,
    BookMark,
    Ip,
    FirstSeen,
    LastSeen,
    LastEventSeen,
    #[strum(serialize = "*")]
    Any,
}

impl ToRedisArgs for RedisDomain {
    fn write_redis_args<W: ?Sized + redis::RedisWrite>(&self, out: &mut W) {
        out.write_arg(self.as_str().as_bytes());
    }
}

impl RedisDomain {
    pub fn as_str(&self) -> &str {
        match self {
            RedisDomain::Users => "users",
            RedisDomain::Subscription => "subscription",
            RedisDomain::Machine => "machine",
            RedisDomain::Heartbeat => "heartbeat",
            RedisDomain::BookMark => "bookmark",
            RedisDomain::Ip => "ip",
            RedisDomain::FirstSeen => "first_seen",
            RedisDomain::LastSeen => "last_seen",
            RedisDomain::LastEventSeen => "last_event_seen",
            RedisDomain::Any => "*",
        }
    }
}
