//! K2: a state file written by mfp-mcp-rs (main @ 3a064fc) loads and saves back through
//! mcp-starter unchanged, with `MfpSection` standing in for mfp's own section type.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use mcp_starter::store::{Change, Section, Store, StoreOptions, TokenKind};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Copied field by field, with its serde attributes, from mfp-mcp-rs `src/store.rs`.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct MfpSection {
    #[serde(default)]
    session_rev: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    cookies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    account_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_expires_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_keep_alive_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "is_false")]
    session_invalid: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_expires_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    user_id: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Section for MfpSection {
    const KEY: &'static str = "mfp";
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn open_with_fixture(name: &str) -> (tempfile::TempDir, Store<MfpSection>) {
    let dir = tempfile::tempdir().unwrap();

    fs::copy(fixture(name), dir.path().join("state.json")).unwrap();

    let store = Store::open(dir.path(), StoreOptions::default()).unwrap();

    (dir, store)
}

fn resave<F>(store: &Store<MfpSection>, change: F)
where
    F: FnOnce(&mut mcp_starter::store::State<MfpSection>) + Send + 'static,
{
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            store
                .update(|state| {
                    change(state);

                    Change::Write(())
                })
                .await
                .unwrap();
        });
}

/// Go writes timestamps in whatever offset the host used and trims trailing zeros the same
/// way jiff does, but instants are what matter, so timestamp strings are normalized.
fn normalize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, normalize(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(normalize).collect()),
        Value::String(text) => match text.parse::<Timestamp>() {
            Ok(instant) if text.contains('T') && text.len() > 18 => {
                Value::String(instant.to_string())
            }
            _ => Value::String(text),
        },
        other => other,
    }
}

fn saved_json(name: &str) -> (Value, Value) {
    let (_dir, store) = open_with_fixture(name);
    let original: Value = serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();

    resave(&store, |_| {});

    let saved: Value = serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();

    (normalize(original), normalize(saved))
}

#[test]
fn mfp_rs_files_round_trip_byte_for_byte() {
    for name in [
        "mfp-rs-state-full.json",
        "mfp-rs-state-sparse.json",
        "mfp-rs-state-extras.json",
    ] {
        let (_dir, store) = open_with_fixture(name);

        resave(&store, |_| {});

        assert_eq!(
            fs::read(store.path()).unwrap(),
            fs::read(fixture(name)).unwrap(),
            "{name} changed on save"
        );
    }
}

#[test]
fn mfp_rs_full_fields_read() {
    let (_dir, store) = open_with_fixture("mfp-rs-state-full.json");
    let state = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(store.read(|state| state.clone()))
        .unwrap();

    assert_eq!(state.section.session_rev, 7);
    assert_eq!(state.section.cookies.len(), 2);
    assert!(state.section.session_invalid);
    assert_eq!(state.section.account_name, "Fixture Owner");
    assert_eq!(state.section.token, "fixture-mfp-bearer-token");
    assert_eq!(state.section.user_id, "fixture-user-1");
    assert!(state.owner.password_hash.starts_with("$2a$12$"));

    let client = &state.clients["client-full"];

    assert_eq!(client.client_name, "Fixture Claude");
    assert_eq!(
        client.redirect_uris,
        ["https://claude.ai/api/mcp/auth_callback"]
    );
    assert!(client.last_used_at.is_some());
    assert_eq!(state.tokens.len(), 3);

    let rotated = state
        .tokens
        .values()
        .filter(|token| token.kind == TokenKind::Refresh && token.rotated)
        .count();

    assert_eq!(rotated, 1);
    assert!(state.tokens.values().all(|token| token.scope == "mfp"));
}

#[test]
fn loads_and_saves_go_state_full() {
    let (original, saved) = saved_json("go-state-full.json");

    assert_eq!(saved, original);
    assert_eq!(saved["mfp"]["session_invalid"], true);
    assert_eq!(saved["mfp"]["cookies"].as_object().unwrap().len(), 2);
}

#[test]
fn loads_and_saves_go_state_sparse() {
    let (original, saved) = saved_json("go-state-sparse.json");

    assert_eq!(saved, original);

    let mfp = saved["mfp"].as_object().unwrap();

    assert_eq!(mfp.len(), 1, "only session_rev is written: {mfp:?}");
    assert!(
        saved["clients"]["client-sparse"]
            .get("last_used_at")
            .is_none()
    );
    assert!(saved["owner"].as_object().unwrap().is_empty());

    for token in saved["tokens"].as_object().unwrap().values() {
        assert!(token.get("rotated").is_none());
        assert!(token.get("scope").is_none());
    }
}

#[test]
fn unknown_extras_survive_a_save() {
    let (_dir, store) = open_with_fixture("mfp-rs-state-extras.json");

    resave(&store, |state| state.section.session_rev += 1);

    let saved: Value = serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();

    assert_eq!(saved["mfp"]["added_later"], "x");
    assert_eq!(saved["added_top"]["a"], 1);
    assert_eq!(saved["owner"]["x"], 1);
    assert_eq!(saved["mfp"]["session_rev"], 3);
}
