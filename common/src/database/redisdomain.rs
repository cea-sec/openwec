use deadpool_redis::redis::{self, ToRedisArgs};
use std::fmt;

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum RedisDomain {
    Users,
    Subscription,
    Machine,
    Heartbeat,
    BookMark,
    Ip,
    FistSeen,
    LastSeen,
    LastEventSeen,
    Any,
}

impl fmt::Display for RedisDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
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
            RedisDomain::FistSeen => "first_seen",
            RedisDomain::LastSeen => "last_seen",
            RedisDomain::LastEventSeen => "last_event_seen",
            RedisDomain::Any => "*",
        }
    }
}
