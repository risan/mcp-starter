#![allow(dead_code)]

use mcp_starter::ServiceInfo;
use mcp_starter::store::{Section, StoreOptions};
use mcp_starter::test_support::oauth_flow::OAuthRig;
use serde::{Deserialize, Serialize};

pub static INFO: ServiceInfo = ServiceInfo {
    command: "example-mcp",
    display_name: "Example",
    env_prefix: "EXAMPLE_MCP_",
    default_listen: "127.0.0.1:8090",
    default_data_dir: "/var/lib/example-mcp",
    default_tz: "Asia/Jakarta",
    scope: "example",
    favicon: &[],
};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestState {
    pub rev: i64,
}

impl Section for TestState {
    const KEY: &'static str = "test";
}

pub async fn rig() -> OAuthRig<TestState> {
    OAuthRig::start(&INFO).await
}

pub async fn rig_with(options: StoreOptions) -> OAuthRig<TestState> {
    OAuthRig::start_with(&INFO, options).await
}
