//! Building blocks for a single-owner MCP server: an OAuth 2.1 authorization server, a JSON
//! state file with a cross-process lock, an HTTP server with strict deadlines, the CLI
//! commands every such server needs and the helpers that run MCP tools as detached work.
//!
//! This is not a framework. A service keeps its own `main`, command dispatch, tool handler
//! and upstream client, and gives the blocks three things: a [`ServiceInfo`], its own
//! [`store::Section`] type and a factory for its tool handler. A complete service is in
//! `examples/minimal`; `cargo test` compiles and runs it.
//!
//! ```ignore
//! pub static SERVICE: ServiceInfo = ServiceInfo { /* command, prefix, defaults, scope */ };
//!
//! #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
//! pub struct MyState { /* the service's part of state.json */ }
//!
//! impl Section for MyState {
//!     const KEY: &'static str = "my_service";
//! }
//!
//! fn main() {
//!     runtime::run_main(|args, io, getenv| my_service::run(args, io, getenv))
//! }
//!
//! // in `serve`:
//! let serving = cli::Serving::start(&SERVICE, config, store, None).await?;
//! serving.run(&mut io, MyTools::factory(app)).await
//! ```
//!
//! | Module | What it holds |
//! |---|---|
//! | [`config`] | the environment settings under the service's prefix |
//! | [`store`] | the state file, [`store::Section`], the lease |
//! | [`oauth`] | the authorization server and the owner-password commands' core |
//! | [`server`] | the router, bearer check, body caps and the connection driver |
//! | [`work`] | detached, tracked work and the connection slot |
//! | [`http`] | the upstream client builder and bounded reads |
//! | [`tools`] | tool-call helpers for an rmcp handler |
//! | [`cli`] | the shared commands and the `serve` runner |
//! | [`runtime`] | the current-thread runtime and exit sequence |
//! | `test_support` | rigs and helpers for tests (feature `test-support`) |

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use jiff::Timestamp;

pub mod cli;
pub mod config;
pub mod http;
pub mod oauth;
pub mod runtime;
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
    /// The HTML page served at `/`; empty leaves `/` a 404. claude.ai takes a connector's icon
    /// from Google's favicon index, which only knows a host that has a page to crawl, so a page
    /// that links the favicon is what gets the service its own icon there.
    pub home_page: &'static str,
}

/// A source of the current time, replaceable in tests.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The wall clock.
pub fn system_clock() -> Clock {
    Arc::new(Timestamp::now)
}
