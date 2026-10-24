//! The example service's tools over the MCP endpoint alone (no bearer, no OAuth).

mod support;

use std::sync::Arc;
use std::time::Duration;

use mcp_starter::config::Config;
use mcp_starter::store::{Store, StoreOptions};
use mcp_starter::test_support::jsonrpc::McpClient;
use mcp_starter::test_support::{TestClock, serve_mcp};
use mcp_starter::work::Work;
use serde_json::json;
use support::example::{App, ExampleState, ExampleTools};
use tokio_util::task::TaskTracker;

struct Env {
    client: McpClient,
    store: Store<ExampleState>,
    dir: tempfile::TempDir,
}

async fn start() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), StoreOptions::default()).unwrap();
    // 2026-10-23T18:30Z is already the 24th in Asia/Jakarta.
    let clock = TestClock::new("2026-10-23T18:30:00Z");
    let app = Arc::new(App {
        store: store.clone(),
        config: Config::load(&support::INFO, &|_| String::new(), false).unwrap(),
        work: Work::new(TaskTracker::new()),
        now: clock.as_clock(),
        tool_deadline: Duration::from_secs(5),
    });
    let client = serve_mcp(ExampleTools::factory(app)).await;

    Env { client, store, dir }
}

#[tokio::test]
async fn invalid_params_become_tool_errors() {
    let env = start().await;

    let result = env
        .client
        .call("example_wait", json!({"milliseconds": "x"}))
        .await;

    assert!(result.is_error);
    assert!(
        result.text.contains("invalid type") || result.text.contains("deserializ"),
        "{}",
        result.text
    );

    let missing = env.client.call("example_echo", json!({})).await;

    assert!(missing.is_error);
    assert!(missing.text.contains("text"), "{}", missing.text);
}

#[tokio::test]
async fn echo_returns_text_and_date() {
    let env = start().await;

    let today = env.client.call("example_echo", json!({"text": "hi"})).await;

    assert!(!today.is_error, "{}", today.text);
    assert_eq!(
        today.structured,
        json!({"text": "hi", "date": "2026-10-24"})
    );
    assert!(
        today.text.contains("\"date\":\"2026-10-24\""),
        "{}",
        today.text
    );

    let dated = env
        .client
        .call("example_echo", json!({"text": "hi", "date": "2026-01-05"}))
        .await;

    assert_eq!(dated.structured["date"], "2026-01-05");

    let bad = env
        .client
        .call("example_echo", json!({"text": "hi", "date": "2026-02-30"}))
        .await;

    assert!(bad.is_error);
    assert!(bad.text.contains("use YYYY-MM-DD"), "{}", bad.text);
}

#[tokio::test]
async fn wait_rejects_more_than_the_maximum() {
    let env = start().await;

    let result = env
        .client
        .call("example_wait", json!({"milliseconds": 30001}))
        .await;

    assert!(result.is_error);
    assert!(
        result.text.contains("between 0 and 30000"),
        "{}",
        result.text
    );
}

#[tokio::test]
async fn count_persists() {
    let env = start().await;

    let first = env.client.call("example_count", json!({})).await;
    let second = env.client.call("example_count", json!({})).await;

    assert_eq!(first.structured["count"], 1);
    assert_eq!(second.structured["count"], 2);

    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.store.path()).unwrap()).unwrap();

    assert_eq!(saved["example"], json!({"count": 2}));
    assert!(saved["owner"].is_object());
    drop(env.dir);
}
