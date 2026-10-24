//! The example service's commands driven in-process, including `serve` running next to them.

mod support;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mcp_starter::cli::{self, Getenv, Io, Outcome};
use mcp_starter::store::{Change, Client, State, Store, StoreOptions, Token, TokenKind};
use mcp_starter::test_support::jsonrpc::McpClient;
use mcp_starter::test_support::{Capture, store_bearer, wait_until};
use serde_json::json;
use support::example::{self, ExampleState};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

struct Cli {
    dir: TempDir,
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Serving {
    address: String,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Outcome>,
}

impl Cli {
    fn new() -> Cli {
        mcp_starter::http::install_crypto_provider();

        Cli {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn getenv(&self, public_url: bool) -> Getenv {
        let data_dir = self.data_dir().display().to_string();

        Arc::new(move |key| match key {
            "EXAMPLE_MCP_DATA_DIR" => data_dir.clone(),
            "EXAMPLE_MCP_PUBLIC_URL" if public_url => "https://mcp.example.com".to_string(),
            "EXAMPLE_MCP_LISTEN" => "127.0.0.1:0".to_string(),
            _ => String::new(),
        })
    }

    async fn run(&self, stdin: &str, args: &[&str]) -> Run {
        self.run_with(stdin, args, self.getenv(true)).await
    }

    async fn run_with(&self, stdin: &str, args: &[&str], getenv: Getenv) -> Run {
        let (stdout, stderr) = (Capture::default(), Capture::default());
        let io = Io {
            stdin: Box::new(Cursor::new(stdin.as_bytes().to_vec())),
            stdin_is_tty: false,
            stdout: Box::new(stdout.clone()),
            stderr: Box::new(stderr.clone()),
        };
        let args = args.iter().map(|arg| arg.to_string()).collect();
        let outcome = example::run(args, io, getenv, None).await;

        Run {
            code: outcome.code,
            stdout: stdout.text(),
            stderr: stderr.text(),
        }
    }

    fn store(&self) -> Store<ExampleState> {
        Store::open(&self.data_dir(), StoreOptions::default()).unwrap()
    }

    async fn state(&self) -> State<ExampleState> {
        self.store().read(|state| state.clone()).await.unwrap()
    }

    async fn start_serve(&self) -> Serving {
        let stderr = Capture::default();
        let io = Io {
            stdin: Box::new(Cursor::new(Vec::new())),
            stdin_is_tty: false,
            stdout: Box::new(Capture::default()),
            stderr: Box::new(stderr.clone()),
        };
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(example::run(
            vec!["serve".to_string()],
            io,
            self.getenv(true),
            Some(shutdown.clone()),
        ));

        wait_until(Duration::from_secs(10), "serve to listen", || {
            stderr.text().contains("listening on")
        })
        .await;

        let text = stderr.text();
        let address = text
            .split("listening on ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap()
            .to_string();

        Serving {
            address,
            shutdown,
            task,
        }
    }
}

impl Serving {
    async fn stop(self) -> Outcome {
        self.shutdown.cancel();

        self.task.await.unwrap()
    }
}

fn client(id: &str) -> Client {
    Client {
        client_id: id.to_string(),
        client_name: String::new(),
        redirect_uris: Vec::new(),
        registered_at: "2026-10-24T00:00:00Z".parse().unwrap(),
        last_used_at: None,
        extra: Default::default(),
    }
}

fn token(kind: TokenKind, expires_at: &str, rotated: bool) -> Token {
    Token {
        kind,
        client_id: String::new(),
        family: String::new(),
        scope: String::new(),
        resource: String::new(),
        expires_at: expires_at.parse().unwrap(),
        rotated,
        extra: Default::default(),
    }
}

#[tokio::test]
async fn set_password_rules() {
    let cli = Cli::new();

    cli.store()
        .update(|state| {
            state.tokens.insert(
                "h".to_string(),
                token(TokenKind::Access, "2099-01-01T00:00:00Z", false),
            );

            Change::Write(())
        })
        .await
        .unwrap();

    let short = cli.run("short\nshort\n", &["set-password"]).await;

    assert!(
        short.code != 0 && short.stderr.contains("12"),
        "{}",
        short.stderr
    );

    let mismatch = cli
        .run(
            "a long enough password\nanother long enough one\n",
            &["set-password"],
        )
        .await;

    assert!(
        mismatch.code != 0 && mismatch.stderr.contains("match"),
        "{}",
        mismatch.stderr
    );

    let state = cli.state().await;

    assert!(
        state.owner.password_hash.is_empty() && state.tokens.len() == 1,
        "a rejected password changes nothing"
    );

    let run = cli
        .run(
            "a long enough password\na long enough password\n",
            &["set-password"],
        )
        .await;
    let state = cli.state().await;

    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(bcrypt::verify("a long enough password", &state.owner.password_hash).unwrap());
    assert!(state.tokens.is_empty(), "tokens revoked");
    assert!(!(run.stdout + &run.stderr).contains("a long enough password"));
}

#[tokio::test]
async fn status_no_secrets() {
    let cli = Cli::new();

    assert_eq!(
        cli.run(
            "a long enough password\na long enough password\n",
            &["set-password"]
        )
        .await
        .code,
        0
    );

    let password_hash = cli.state().await.owner.password_hash;

    cli.store()
        .update(|state| {
            state
                .clients
                .insert("client-1".to_string(), client("client-1"));

            for (name, kind, expires_at, rotated) in [
                (
                    "RAW-LOOKING-HASH-1",
                    TokenKind::Access,
                    "2099-01-01T00:00:00Z",
                    false,
                ),
                (
                    "RAW-LOOKING-HASH-2",
                    TokenKind::Refresh,
                    "2099-01-01T00:00:00Z",
                    false,
                ),
                (
                    "RAW-LOOKING-HASH-3",
                    TokenKind::Refresh,
                    "2099-01-01T00:00:00Z",
                    true,
                ),
                (
                    "RAW-LOOKING-HASH-4",
                    TokenKind::Access,
                    "2020-01-01T00:00:00Z",
                    false,
                ),
            ] {
                state
                    .tokens
                    .insert(name.to_string(), token(kind, expires_at, rotated));
            }

            Change::Write(())
        })
        .await
        .unwrap();

    let run = cli.run("", &["status"]).await;

    assert_eq!(run.code, 0, "{}", run.stderr);

    for secret in [
        &password_hash,
        "a long enough password",
        "RAW-LOOKING-HASH",
        "client-1",
    ] {
        assert!(!run.stdout.contains(secret), "status leaks {secret:?}");
    }

    for wanted in [
        "Count: 0",
        "Owner password set: yes",
        "OAuth clients: 1",
        "Live OAuth tokens: 2",
    ] {
        assert!(
            run.stdout.contains(wanted),
            "status lacks {wanted:?}:\n{}",
            run.stdout
        );
    }
}

#[tokio::test]
async fn status_lines_are_generic() {
    let now = "2026-10-24T09:00:00Z".parse().unwrap();
    let mut state = State::<ExampleState>::default();

    assert_eq!(
        cli::oauth_status(&state, now),
        "Owner password set: no\nOAuth clients: 0\nLive OAuth tokens: 0\n"
    );

    state.owner.password_hash = "hash".to_string();
    state.clients.insert("c".to_string(), client("c"));
    state.tokens.insert(
        "live".to_string(),
        token(TokenKind::Access, "2026-10-24T10:00:00Z", false),
    );
    state.tokens.insert(
        "expired".to_string(),
        token(TokenKind::Access, "2026-10-24T08:00:00Z", false),
    );
    state.tokens.insert(
        "rotated".to_string(),
        token(TokenKind::Refresh, "2026-10-24T10:00:00Z", true),
    );

    assert_eq!(
        cli::oauth_status(&state, now),
        "Owner password set: yes\nOAuth clients: 1\nLive OAuth tokens: 1\n"
    );
}

#[tokio::test]
async fn status_fresh_install() {
    let cli = Cli::new();

    let run = cli.run("", &["status"]).await;

    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("Owner password set: no") && run.stdout.contains("Count: 0"),
        "{}",
        run.stdout
    );
}

#[tokio::test]
async fn revoke_tokens() {
    let cli = Cli::new();

    store_bearer(&cli.store(), "some-token").await;
    cli.store()
        .update(|state| {
            state.owner.password_hash = "keep-me".to_string();
            state.clients.insert("c".to_string(), client("c"));

            Change::Write(())
        })
        .await
        .unwrap();

    assert_eq!(cli.run("", &["revoke-tokens"]).await.code, 0);

    let state = cli.state().await;

    assert!(state.tokens.is_empty() && state.clients.is_empty());
    assert_eq!(state.owner.password_hash, "keep-me");
}

#[tokio::test]
async fn unknown_command_and_help() {
    let cli = Cli::new();

    let unknown = cli.run("", &["frobnicate"]).await;

    assert!(
        unknown.code == 2 && unknown.stderr.contains("usage"),
        "{}",
        unknown.stderr
    );

    let help = cli.run("", &["help"]).await;

    assert_eq!(help.code, 0);

    for command in ["serve", "set-password", "status", "revoke-tokens"] {
        assert!(help.stdout.contains(command), "{}", help.stdout);
    }
}

#[tokio::test]
async fn serve_refuses_corrupt_state() {
    let cli = Cli::new();
    std::fs::create_dir_all(cli.data_dir()).unwrap();
    let path = cli.data_dir().join("state.json");
    std::fs::write(&path, b"{broken").unwrap();

    let run = cli.run("", &["serve"]).await;

    assert!(
        run.code != 0 && run.stderr.contains(&path.display().to_string()),
        "{}",
        run.stderr
    );
}

#[tokio::test]
async fn serve_requires_public_url() {
    let cli = Cli::new();

    let run = cli.run_with("", &["serve"], cli.getenv(false)).await;

    assert!(
        run.code != 0 && run.stderr.contains("EXAMPLE_MCP_PUBLIC_URL"),
        "{}",
        run.stderr
    );
}

#[tokio::test]
async fn serve_refuses_second_instance() {
    let cli = Cli::new();
    let first = cli.start_serve().await;

    let second = cli.run("", &["serve"]).await;

    assert_ne!(second.code, 0);
    assert!(
        second
            .stderr
            .contains("another example-mcp process is using this data dir"),
        "{}",
        second.stderr
    );

    drop(first.stop().await);

    let third = cli.start_serve().await;

    drop(third.stop().await);
}

#[tokio::test]
async fn revoke_tokens_while_serving() {
    let cli = Cli::new();
    let serving = cli.start_serve().await;

    store_bearer(&cli.store(), "bearer-token-for-test").await;

    let mcp = McpClient::new(&format!("http://{}/mcp", serving.address))
        .with_bearer("bearer-token-for-test");
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    assert_eq!(
        mcp.request(&list).send().await.unwrap().status(),
        200,
        "before the revoke"
    );

    assert_eq!(cli.run("", &["revoke-tokens"]).await.code, 0);
    assert_eq!(
        mcp.request(&list).send().await.unwrap().status(),
        401,
        "after the revoke"
    );

    // a server-side write must not bring the revoked token back
    let http = reqwest::Client::new();
    let register = http
        .post(format!("http://{}/register", serving.address))
        .header("content-type", "application/json")
        .body(r#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(register.status(), 201);
    assert_eq!(
        mcp.request(&list).send().await.unwrap().status(),
        401,
        "a revoked token stays revoked"
    );

    drop(serving.stop().await);
}

#[tokio::test]
async fn serve_runs_tools_end_to_end() {
    let cli = Cli::new();
    let serving = cli.start_serve().await;

    store_bearer(&cli.store(), "bearer-token-for-test").await;

    let mcp = McpClient::new(&format!("http://{}/mcp", serving.address))
        .with_bearer("bearer-token-for-test");

    mcp.initialize().await;

    let result = mcp.call("example_count", json!({})).await;

    assert!(!result.is_error, "{}", result.text);
    assert_eq!(result.structured["count"], 1);
    assert_eq!(cli.state().await.section.count, 1);

    drop(serving.stop().await);
}
