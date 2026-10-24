#![allow(dead_code)]

use std::time::Duration;

use mcp_starter::server::ServerOptions;
use mcp_starter::store::StoreOptions;
use mcp_starter::test_support::oauth_flow::OAuthRig;
use mcp_starter::test_support::server_rig::{RigSetup, ServerRig};
use std::sync::Arc;

#[path = "../../examples/minimal/service.rs"]
pub mod example;

pub use example::{ExampleState, SERVICE as INFO};

pub type TestState = ExampleState;

pub async fn rig() -> OAuthRig<ExampleState> {
    OAuthRig::start(&INFO).await
}

pub async fn rig_with(options: StoreOptions) -> OAuthRig<ExampleState> {
    OAuthRig::start_with(&INFO, options).await
}

/// How a test server is set up: the tool deadline plus the rig's own settings.
pub struct Setup {
    pub tool_deadline: Duration,
    pub server: ServerOptions,
    pub store: StoreOptions,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            tool_deadline: Duration::from_secs(10),
            server: ServerOptions::default(),
            store: StoreOptions::default(),
        }
    }
}

pub async fn start() -> ServerRig<ExampleState> {
    start_with(Setup::default()).await
}

pub async fn start_with(setup: Setup) -> ServerRig<ExampleState> {
    let tool_deadline = setup.tool_deadline;
    let rig_setup = RigSetup {
        server: setup.server,
        store: setup.store,
        ..RigSetup::default()
    };

    ServerRig::start(
        &INFO,
        rig_setup,
        |_| {},
        move |context| {
            example::ExampleTools::factory(Arc::new(example::App {
                store: context.store.clone(),
                config: context.config.clone(),
                work: context.work.clone(),
                now: context.clock.clone(),
                tool_deadline,
            }))
        },
    )
    .await
}
