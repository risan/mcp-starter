//! Building blocks for a single-owner MCP server.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use jiff::Timestamp;

pub mod config;
pub mod http;
pub mod oauth;
pub mod server;
pub mod store;
mod sys;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod tools;
pub mod work;

/// What a service tells the blocks about itself. Everything service-specific the blocks need
/// is here, next to the service's section type.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    /// The command name, as the operator types it (used in hints and messages).
    pub command: &'static str,
    /// The name shown to people, such as on the consent page.
    pub display_name: &'static str,
    /// The prefix of every environment variable, including the trailing underscore.
    pub env_prefix: &'static str,
    /// The listen address when `<prefix>LISTEN` is not set.
    pub default_listen: &'static str,
    /// The data directory when `<prefix>DATA_DIR` is not set.
    pub default_data_dir: &'static str,
    /// The IANA time zone when `<prefix>TZ` is not set.
    pub default_tz: &'static str,
    /// The OAuth scope the service grants and advertises.
    pub scope: &'static str,
    /// The bytes served at `/favicon.ico`.
    pub favicon: &'static [u8],
}

/// A source of the current time, replaceable in tests.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The wall clock.
pub fn system_clock() -> Clock {
    Arc::new(Timestamp::now)
}
