//! The HTTP wiring over real sockets: bearer checks, body caps, connection deadlines and the
//! shutdown sequence, with the example service's tools behind the server.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mcp_starter::server::{ServerOptions, buffer_body, serve};
use mcp_starter::store::{Hooks, StoreOptions};
use mcp_starter::test_support::jsonrpc::McpClient;
use mcp_starter::test_support::oauth_flow::{
    CLAUDE_CALLBACK, OWNER_PASSWORD, VERIFIER, authorize_params, set_param,
};
use mcp_starter::test_support::{raw_http, wait_until};
use mcp_starter::work::Work;
use serde_json::{Value, json};
use support::Setup;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
const RESOURCE_METADATA: &str =
    r#"resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource""#;

fn scaled(server: ServerOptions) -> Setup {
    Setup {
        server,
        ..Setup::default()
    }
}

fn fast_server() -> ServerOptions {
    ServerOptions {
        max_connections: 64,
        header_read_timeout: Duration::from_millis(300),
        read_deadline: Duration::from_millis(600),
        write_deadline: Duration::from_millis(900),
    }
}

fn stalling_store() -> (StoreOptions, Arc<AtomicBool>) {
    let stalled = Arc::new(AtomicBool::new(false));
    let flag = stalled.clone();
    let hooks = Hooks {
        sync_file: Arc::new(move |file| {
            while flag.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }

            file.sync_all()
        }),
        ..Hooks::default()
    };

    (
        StoreOptions {
            hooks,
            ..StoreOptions::default()
        },
        stalled,
    )
}

struct LiftOnDrop(Arc<AtomicBool>);

impl Drop for LiftOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

async fn read_until_closed(stream: &mut TcpStream, limit: Duration) -> Option<Vec<u8>> {
    let mut data = Vec::new();

    match timeout(limit, stream.read_to_end(&mut data)).await {
        Ok(_) => Some(data),
        Err(_) => None,
    }
}

async fn fire_and_forget(address: &str, path: &str, content_type: &str, body: &str) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: x\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );

    let _ = stream.write_all(request.as_bytes()).await;
}

#[tokio::test]
async fn unauthenticated_mcp_401() {
    let rig = support::start().await;
    let client = McpClient::new(&rig.url("/mcp"));

    let response = client
        .request(&serde_json::from_str(TOOLS_LIST).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["www-authenticate"],
        format!("Bearer {RESOURCE_METADATA}").as_str()
    );
}

#[tokio::test]
async fn invalid_token_has_error_param() {
    let rig = support::start().await;
    let client = McpClient::new(&rig.url("/mcp")).with_bearer("not-a-token");

    let response = client
        .request(&serde_json::from_str(TOOLS_LIST).unwrap())
        .send()
        .await
        .unwrap();
    let challenge = response.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();

    assert_eq!(response.status(), 401);
    assert_eq!(
        challenge,
        format!(r#"Bearer error="invalid_token", {RESOURCE_METADATA}"#)
    );
}

#[tokio::test]
async fn token_for_another_resource_401() {
    let rig = support::start().await;
    let client = rig.mcp().await;
    let body: Value = serde_json::from_str(TOOLS_LIST).unwrap();

    rig.store
        .update(|state| {
            for token in state.tokens.values_mut() {
                token.resource = "https://old.example.com/mcp".to_string();
            }

            mcp_starter::store::Change::Write(())
        })
        .await
        .unwrap();
    let response = client.request(&body).send().await.unwrap();

    assert_eq!(response.status(), 401);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains(r#"error="invalid_token""#)
    );
}

#[tokio::test]
async fn rig_with_its_own_public_url_runs_the_oauth_flow() {
    let rig = support::start_with(Setup {
        public_url: "https://garmin.example.org".to_string(),
        ..Setup::default()
    })
    .await;

    let client = rig.mcp().await;

    assert!(!client.list_tools().await.is_empty());

    let resources: Vec<String> = rig
        .store
        .read(|state| {
            state
                .tokens
                .values()
                .map(|token| token.resource.clone())
                .collect()
        })
        .await
        .unwrap();

    assert!(!resources.is_empty());
    assert!(
        resources
            .iter()
            .all(|resource| resource == "https://garmin.example.org/mcp"),
        "{resources:?}"
    );
}

#[tokio::test]
async fn expired_token_has_error_param() {
    let rig = support::start().await;
    let client = rig.mcp().await;
    let body: Value = serde_json::from_str(TOOLS_LIST).unwrap();

    assert_eq!(
        client.request(&body).send().await.unwrap().status(),
        200,
        "a fresh token"
    );

    rig.clock.advance(jiff::SignedDuration::from_hours(25));
    let response = client.request(&body).send().await.unwrap();

    assert_eq!(response.status(), 401);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains(r#"error="invalid_token""#)
    );
}

#[tokio::test]
async fn protected_resource_metadata() {
    let rig = support::start().await;

    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let reply = rig.oauth_client.get(path).await;
        let meta = reply.json();

        assert_eq!(reply.status, 200, "{path}");
        assert_eq!(meta["resource"], "https://mcp.example.com/mcp");
        assert_eq!(
            meta["authorization_servers"],
            json!(["https://mcp.example.com"])
        );
        assert_eq!(meta["scopes_supported"], json!(["example"]));
        assert_eq!(meta["bearer_methods_supported"], json!(["header"]));
    }
}

#[tokio::test]
async fn public_host_on_loopback_listener_allowed() {
    let rig = support::start().await;
    let client = rig.mcp().await;

    for (host, allowed) in [("mcp.example.com", true), ("evil.example", false)] {
        let response = client
            .request(&serde_json::from_str(TOOLS_LIST).unwrap())
            .header("host", host)
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.status() != 403,
            allowed,
            "Host {host}: {}",
            response.status()
        );

        if allowed {
            assert_eq!(response.status(), 200);
        }
    }
}

#[tokio::test]
async fn mcp_body_limit_413() {
    let rig = support::start().await;
    let client = rig.mcp().await;
    let big = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"pad":"{}"}}}}"#,
        "a".repeat(1 << 20)
    );
    let response = client
        .request(&Value::Null)
        .body(big.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413, "declared length");

    let mcp_token = {
        let client_id = rig.oauth_client.register(&[CLAUDE_CALLBACK]).await;
        let code = rig.oauth_client.grant(&client_id, CLAUDE_CALLBACK).await;
        let (_, tokens) = rig
            .oauth_client
            .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
            .await;

        tokens.unwrap().access_token
    };
    let authorization = format!("Bearer {mcp_token}");
    let headers = [
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
    ];
    let (status, _) = raw_http(&rig.address, "POST", "/mcp", &headers, &big, true).await;

    assert_eq!(status, 413, "chunked");
}

#[tokio::test]
async fn unauthenticated_mcp_answered_before_body_is_read() {
    let rig = support::start().await;

    for authorization in [None, Some("Bearer not-a-token")] {
        let mut stream = TcpStream::connect(&rig.address).await.unwrap();
        let mut head = format!(
            "POST /mcp HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
            rig.address,
            512 * 1024
        );

        if let Some(value) = authorization {
            head.push_str(&format!("authorization: {value}\r\n"));
        }

        // The declared body never arrives: a server that buffered before checking the bearer
        // would sit on the read until its deadline.
        stream
            .write_all(format!("{head}\r\n").as_bytes())
            .await
            .unwrap();

        let mut buffer = vec![0u8; 1024];
        let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("the 401 must not wait for the body")
            .unwrap();
        let reply = String::from_utf8_lossy(&buffer[..read]);

        assert!(
            reply.starts_with("HTTP/1.1 401"),
            "{authorization:?}: {reply}"
        );
    }
}

fn with_routes(routes: Router) -> Setup {
    Setup {
        routes,
        ..Setup::default()
    }
}

#[tokio::test]
async fn extra_route_served_next_to_the_built_in_ones() {
    let routes = Router::new().route("/extra", get(|| async { "extra\n" }));
    let rig = support::start_with(with_routes(routes)).await;

    let (status, reply) = raw_http(&rig.address, "GET", "/extra", &[], "", false).await;

    assert_eq!(status, 200);
    assert!(reply.ends_with("extra\n"), "{reply}");

    let (status, reply) = raw_http(&rig.address, "GET", "/healthz", &[], "", false).await;

    assert_eq!(status, 200);
    assert!(reply.ends_with("ok\n"), "{reply}");
}

#[tokio::test]
async fn extra_route_with_buffer_body_answers_413_before_its_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let routes = Router::new().route(
        "/upload",
        post(move || {
            let counter = counter.clone();

            async move {
                counter.fetch_add(1, Ordering::SeqCst);

                "stored"
            }
        })
        .route_layer(middleware::from_fn_with_state(1024usize, buffer_body)),
    );
    let rig = support::start_with(with_routes(routes)).await;
    let (status, _) = raw_http(
        &rig.address,
        "POST",
        "/upload",
        &[],
        &"a".repeat(2048),
        false,
    )
    .await;

    assert_eq!(status, 413);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (status, _) = raw_http(
        &rig.address,
        "POST",
        "/upload",
        &[],
        &"a".repeat(512),
        false,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oauth_body_cap_does_not_apply_to_extra_routes() {
    let routes = Router::new().route(
        "/upload",
        post(|body: String| async move { body.len().to_string() })
            .route_layer(middleware::from_fn_with_state(1usize << 20, buffer_body)),
    );
    let rig = support::start_with(with_routes(routes)).await;
    let body = "a".repeat(100 * 1024);
    let (status, reply) = raw_http(&rig.address, "POST", "/upload", &[], &body, false).await;

    assert_eq!(status, 200);
    assert!(reply.ends_with(&(100 * 1024).to_string()), "{reply}");
}

#[tokio::test]
async fn access_check_added_after_buffer_body_answers_before_the_body_is_read() {
    async fn refuse(_request: Request, _next: Next) -> Response {
        StatusCode::NOT_FOUND.into_response()
    }

    let routes = Router::new().route(
        "/upload",
        post(|| async { "stored" })
            .route_layer(middleware::from_fn_with_state(1usize << 20, buffer_body))
            .route_layer(middleware::from_fn(refuse)),
    );
    let rig = support::start_with(with_routes(routes)).await;
    let mut stream = TcpStream::connect(&rig.address).await.unwrap();
    let head = format!(
        "POST /upload HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\n\r\n",
        rig.address,
        1024 * 1024
    );

    // The declared body never arrives: a route that buffered before its check would sit on
    // the read until the connection's deadline.
    stream.write_all(head.as_bytes()).await.unwrap();

    let mut buffer = vec![0u8; 1024];
    let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .expect("the 404 must not wait for the body")
        .unwrap();
    let reply = String::from_utf8_lossy(&buffer[..read]);

    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
}

#[tokio::test]
async fn oauth_body_limit_413_through_router() {
    let rig = support::start().await;
    let before = std::fs::read(rig.store.path()).unwrap();
    let oversize = "a".repeat(64 * 1024 + 1);
    let form = [("content-type", "application/x-www-form-urlencoded")];

    for chunked in [false, true] {
        let (status, _) = raw_http(
            &rig.address,
            "POST",
            "/token",
            &form,
            &format!("grant_type=x&junk={oversize}"),
            chunked,
        )
        .await;
        assert_eq!(status, 413, "token chunked={chunked}");

        let (status, _) = raw_http(
            &rig.address,
            "POST",
            "/authorize",
            &form,
            &format!("password={oversize}"),
            chunked,
        )
        .await;
        assert_eq!(status, 413, "authorize chunked={chunked}");

        let json = [("content-type", "application/json")];
        let (status, _) = raw_http(
            &rig.address,
            "POST",
            "/register",
            &json,
            &format!(r#"{{"x":"{oversize}"}}"#),
            chunked,
        )
        .await;
        assert_eq!(status, 413, "register chunked={chunked}");
    }

    assert_eq!(
        std::fs::read(rig.store.path()).unwrap(),
        before,
        "state.json changed"
    );
    assert_eq!(rig.probe.started(), 0);
    assert_eq!(rig.work.peak_tasks(), 0, "no handler ran");
}

#[tokio::test]
async fn slow_header_closed() {
    let rig = support::start_with(scaled(fast_server())).await;
    let mut stream = TcpStream::connect(&rig.address).await.unwrap();
    let started = Instant::now();

    stream
        .write_all(b"POST /register HTTP/1.1\r\nhost: x\r\ncontent-le")
        .await
        .unwrap();

    let reply = read_until_closed(&mut stream, Duration::from_secs(3)).await;

    assert!(reply.is_some(), "the connection must be closed");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "{:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(rig.work.peak_tasks(), 0, "the handler never runs");
}

#[tokio::test]
async fn slow_body_closed() {
    let rig = support::start_with(scaled(fast_server())).await;
    let mut stream = TcpStream::connect(&rig.address).await.unwrap();
    let started = Instant::now();

    stream
        .write_all(b"POST /register HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"redirect")
        .await
        .unwrap();

    let mut closed_at = None;

    for _ in 0..30 {
        sleep(Duration::from_millis(100)).await;

        if stream.write_all(b"_").await.is_err() {
            closed_at = Some(started.elapsed());

            break;
        }
    }

    let reply = read_until_closed(&mut stream, Duration::from_secs(2)).await;

    assert!(reply.is_some());
    assert!(closed_at.is_some() || started.elapsed() < Duration::from_secs(3));
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(rig.work.peak_tasks(), 0, "the handler never runs");
}

#[tokio::test]
async fn response_closes_connection() {
    let rig = support::start().await;
    let (status, text) = raw_http(&rig.address, "GET", "/healthz", &[], "", false).await;

    assert_eq!(status, 200);
    assert!(
        text.to_ascii_lowercase().contains("connection: close"),
        "{text}"
    );

    let mut stream = TcpStream::connect(&rig.address).await.unwrap();

    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();

    assert!(
        read_until_closed(&mut stream, Duration::from_secs(2))
            .await
            .is_some(),
        "EOF after one response"
    );
}

#[tokio::test]
async fn healthz_responsive_during_password_check() {
    let rig = support::start().await;
    let client_id = rig.oauth_client.register(&[CLAUDE_CALLBACK]).await;
    let (form, _) = rig
        .oauth_client
        .consent(&authorize_params(
            &support::INFO,
            &client_id,
            CLAUDE_CALLBACK,
        ))
        .await;
    let form = form.unwrap();

    rig.probe.hold();
    let client = rig.oauth_client.clone();
    let attempt = tokio::spawn(async move { client.approve(&form, OWNER_PASSWORD).await });
    wait_until(Duration::from_secs(5), "the slow check to start", || {
        rig.probe.started() == 1
    })
    .await;

    let reply = timeout(Duration::from_millis(500), rig.oauth_client.get("/healthz")).await;

    assert_eq!(reply.expect("healthz must answer at once").status, 200);

    rig.probe.release();
    assert_eq!(attempt.await.unwrap().status, 303);
}

#[tokio::test]
async fn healthz_responsive_during_store_lock_wait() {
    let setup = Setup {
        store: StoreOptions {
            lock_wait: Duration::from_millis(700),
            hooks: Hooks::default(),
        },
        ..Setup::default()
    };
    let rig = support::start_with(setup).await;
    let holder = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(rig.dir.path().join("state.lock"))
        .unwrap();

    holder.lock().unwrap();

    let client = rig.oauth_client.clone();
    let started = Instant::now();
    let token_request =
        tokio::spawn(async move { client.refresh("some-client", "some-token").await.0 });
    sleep(Duration::from_millis(150)).await;

    let reply = timeout(Duration::from_millis(500), rig.oauth_client.get("/healthz")).await;

    assert_eq!(
        reply.expect("healthz answers while the store waits").status,
        200
    );

    let token_reply = token_request.await.unwrap();

    assert_eq!(token_reply.status, 500, "an error after the bounded wait");
    assert!(
        started.elapsed() >= Duration::from_millis(650),
        "{:?}",
        started.elapsed()
    );
    drop(holder);
}

#[tokio::test]
async fn healthz_responsive_during_stalled_fsync() {
    let (store, stalled) = stalling_store();
    let _lift = LiftOnDrop(stalled.clone());
    let rig = support::start_with(Setup {
        store,
        server: fast_server(),
        ..Setup::default()
    })
    .await;

    stalled.store(true, Ordering::SeqCst);

    let client = rig.oauth_client.clone();
    let register = tokio::spawn(async move {
        client
            .post_json("/register", &json!({"redirect_uris": [CLAUDE_CALLBACK]}))
            .await
            .status
    });
    sleep(Duration::from_millis(100)).await;

    let reply = timeout(Duration::from_millis(500), rig.oauth_client.get("/healthz")).await;

    assert_eq!(
        reply
            .expect("healthz answers while fsync is stalled")
            .status,
        200
    );

    let mut slow = TcpStream::connect(&rig.address).await.unwrap();
    let started = Instant::now();

    slow.write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\n")
        .await
        .unwrap();

    assert!(
        read_until_closed(&mut slow, Duration::from_secs(3))
            .await
            .is_some()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "closed on time: {:?}",
        started.elapsed()
    );

    stalled.store(false, Ordering::SeqCst);
    assert_eq!(register.await.unwrap(), 201);
}

#[tokio::test]
async fn connection_cap_backpressure() {
    let rig = support::start_with(scaled(ServerOptions {
        max_connections: 2,
        header_read_timeout: Duration::from_secs(10),
        read_deadline: Duration::from_secs(10),
        write_deadline: Duration::from_secs(10),
    }))
    .await;
    let first = TcpStream::connect(&rig.address).await.unwrap();
    let _second = TcpStream::connect(&rig.address).await.unwrap();

    sleep(Duration::from_millis(100)).await;

    let address = rig.address.clone();
    let third = tokio::spawn(async move {
        raw_http(&address, "GET", "/healthz", &[], "", false)
            .await
            .0
    });

    sleep(Duration::from_millis(300)).await;
    assert!(
        !third.is_finished(),
        "a third connection waits while two are open"
    );

    drop(first);

    assert_eq!(
        timeout(Duration::from_secs(3), third)
            .await
            .expect("served once a slot frees")
            .unwrap(),
        200
    );
}

#[tokio::test]
async fn dropped_request_flood_stays_bounded() {
    let real_euid = Hooks::default().euid;
    let hooks = Hooks {
        euid: Arc::new(move || {
            std::thread::sleep(Duration::from_millis(8));

            real_euid()
        }),
        ..Hooks::default()
    };
    let rig = support::start_with(Setup {
        store: StoreOptions {
            hooks,
            ..StoreOptions::default()
        },
        server: ServerOptions {
            max_connections: 4,
            ..ServerOptions::default()
        },
        ..Setup::default()
    })
    .await;
    let form = "application/x-www-form-urlencoded";

    for index in 0..100 {
        let body = format!(
            "grant_type=authorization_code&code=unknown-{index}&client_id=c&redirect_uri=x&code_verifier={}",
            "v".repeat(43)
        );

        fire_and_forget(&rig.address, "/token", form, &body).await;
    }

    let client_id = rig.oauth_client.register(&[CLAUDE_CALLBACK]).await;
    let mut forms = Vec::new();

    for _ in 0..100 {
        let (page, _) = rig
            .oauth_client
            .consent(&authorize_params(
                &support::INFO,
                &client_id,
                CLAUDE_CALLBACK,
            ))
            .await;
        forms.push(page.unwrap());
    }

    for page in &forms {
        let mut page = page.clone();
        set_param(&mut page, "password", "wrong");
        let body = serde_urlencoded::to_string(&page).unwrap();

        fire_and_forget(&rig.address, "/authorize", form, &body).await;
    }

    wait_until(Duration::from_secs(60), "everything to drain", || {
        rig.work.live_tasks() == 0
    })
    .await;
    // the last health check queues behind everything that was sent before it
    assert_eq!(rig.oauth_client.get("/healthz").await.status, 200);
    wait_until(Duration::from_secs(60), "the backlog to drain", || {
        rig.work.live_tasks() == 0
    })
    .await;

    assert!(
        rig.work.peak_tasks() <= 4,
        "detached tasks peaked at {}",
        rig.work.peak_tasks()
    );
    assert!(
        rig.store.peak_jobs() <= 4,
        "store jobs peaked at {}",
        rig.store.peak_jobs()
    );
}

async fn count(
    rig: &mcp_starter::test_support::server_rig::ServerRig<support::ExampleState>,
) -> u64 {
    rig.store.read(|state| state.section.count).await.unwrap()
}

async fn bearer(
    rig: &mcp_starter::test_support::server_rig::ServerRig<support::ExampleState>,
) -> String {
    let client_id = rig.oauth_client.register(&[CLAUDE_CALLBACK]).await;
    let code = rig.oauth_client.grant(&client_id, CLAUDE_CALLBACK).await;
    let (_, tokens) = rig
        .oauth_client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    tokens.unwrap().access_token
}

#[tokio::test]
async fn healthz() {
    let rig = support::start().await;

    let reply = rig.oauth_client.get("/healthz").await;

    assert_eq!(reply.status, 200);
    assert_eq!(reply.body.trim(), "ok");
    assert_eq!(rig.work.peak_tasks(), 0, "healthz starts no work");
}

#[tokio::test]
async fn favicon_served_without_a_token() {
    let rig = support::start().await;

    let (status, reply) = raw_http(&rig.address, "GET", "/favicon.ico", &[], "", false).await;

    assert_eq!(status, 200);
    assert!(reply.contains("content-type: image/x-icon"), "{reply}");
    assert!(
        reply.contains(&format!("content-length: {}", support::INFO.favicon.len())),
        "{reply}"
    );
    assert_eq!(rig.work.peak_tasks(), 0, "the icon starts no work");
}

#[tokio::test]
async fn home_page_served_without_a_token() {
    let rig = support::start().await;

    let (status, reply) = raw_http(&rig.address, "GET", "/", &[], "", false).await;

    assert_eq!(status, 200);
    assert!(
        reply.contains("content-type: text/html; charset=utf-8"),
        "{reply}"
    );
    assert!(
        reply.contains("<link rel=\"icon\" href=\"/favicon.ico\">"),
        "{reply}"
    );
    assert_eq!(rig.work.peak_tasks(), 0, "the home page starts no work");
}

#[tokio::test]
async fn end_to_end_tools_list() {
    let rig = support::start().await;
    let client = rig.mcp().await;

    assert_eq!(client.list_tools().await.len(), 3);
}

#[tokio::test]
async fn tools_list_marks_read_only() {
    let rig = support::start().await;
    let client = rig.mcp().await;
    let tools = client.list_tools().await;
    let hint = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))["annotations"]["readOnlyHint"]
            .clone()
    };

    assert_eq!(hint("example_echo"), true);
    assert_eq!(hint("example_wait"), true);
    assert_eq!(hint("example_count"), false);
}

#[tokio::test]
async fn write_window_counts_from_body_end() {
    let setup = Setup {
        tool_deadline: Duration::from_millis(400),
        server: ServerOptions {
            max_connections: 64,
            header_read_timeout: Duration::from_secs(5),
            read_deadline: Duration::from_millis(500),
            write_deadline: Duration::from_millis(900),
        },
        ..Setup::default()
    };
    let rig = support::start_with(setup).await;
    let token = bearer(&rig).await;
    let call = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "example_wait", "arguments": {"milliseconds": 1500}},
    })
    .to_string();
    let head = format!(
        "POST /mcp HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        rig.address,
        call.len()
    );
    let mut stream = TcpStream::connect(&rig.address).await.unwrap();

    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&call.as_bytes()[..40]).await.unwrap();
    sleep(Duration::from_millis(250)).await;
    stream.write_all(&call.as_bytes()[40..]).await.unwrap();

    let started = Instant::now();
    let reply = read_until_closed(&mut stream, Duration::from_secs(5))
        .await
        .expect("a reply");
    let text = String::from_utf8_lossy(&reply).into_owned();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    let rpc: Value =
        serde_json::from_str(body.trim()).unwrap_or_else(|error| panic!("{error}: {text}"));

    assert_eq!(rpc["result"]["isError"], true, "{text}");
    assert!(
        rpc["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("did not finish within 400ms"),
        "{text}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );

    wait_until(Duration::from_secs(5), "the wait to end", || {
        rig.work.live_tasks() == 0
    })
    .await;
}

#[tokio::test]
async fn spawn_work_refused_after_shutdown() {
    let rig = support::start().await;
    let mcp = rig.mcp().await;

    rig.work.begin_shutdown();

    assert!(
        rig.work.spawn(async {}).is_err(),
        "nothing spawns after the flag"
    );

    let result = mcp.call("example_count", json!({})).await;

    assert!(result.is_error);
    assert!(
        result
            .text
            .contains("server is shutting down, try again in a minute"),
        "{}",
        result.text
    );
    assert_eq!(count(&rig).await, 0, "no work after the flag");
}

#[tokio::test]
async fn shutdown_stops_accepting() {
    let mut rig = support::start().await;
    let mcp = rig.mcp().await;
    let call = tokio::spawn(async move {
        mcp.call("example_wait", json!({"milliseconds": 1000}))
            .await
    });

    wait_until(Duration::from_secs(5), "the tool task", || {
        rig.work.live_tasks() == 1
    })
    .await;

    rig.shutdown.cancel();
    sleep(Duration::from_millis(100)).await;

    let refused = TcpStream::connect(&rig.address).await;

    assert!(
        refused.is_err(),
        "a new connection must be refused once shutdown began"
    );

    rig.stopped.take().unwrap().await.unwrap();
    let _ = call.await;
}

#[tokio::test]
async fn shutdown_waits_for_tool_work() {
    let mut rig = support::start().await;
    let mcp = rig.mcp().await;
    let started = Instant::now();
    let call = tokio::spawn(async move {
        mcp.call("example_wait", json!({"milliseconds": 1000}))
            .await
    });

    wait_until(Duration::from_secs(5), "the tool task", || {
        rig.work.live_tasks() == 1
    })
    .await;
    // The bearer check is detached work too; once it has ended, the one live task is the tool.
    sleep(Duration::from_millis(200)).await;

    assert_eq!(rig.work.live_tasks(), 1, "the wait is running");

    rig.stop().await;

    assert!(
        started.elapsed() >= Duration::from_millis(950),
        "serve returned before the wait ended: {:?}",
        started.elapsed()
    );
    assert_eq!(rig.work.live_tasks(), 0);

    let result = call.await.unwrap();

    assert!(!result.is_error, "{}", result.text);
}

#[tokio::test]
async fn upload_unfinished_at_shutdown_closed() {
    let mut rig = support::start_with(Setup {
        server: ServerOptions {
            max_connections: 64,
            header_read_timeout: Duration::from_secs(5),
            read_deadline: Duration::from_secs(10),
            write_deadline: Duration::from_secs(10),
        },
        ..Setup::default()
    })
    .await;
    let token = bearer(&rig).await;
    let call = json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "example_count", "arguments": {}},
    })
    .to_string();
    let head = format!(
        "POST /mcp HTTP/1.1\r\nhost: {}\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {}\r\n\r\n",
        rig.address,
        call.len()
    );
    let mut stream = TcpStream::connect(&rig.address).await.unwrap();

    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&call.as_bytes()[..30]).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let started = Instant::now();

    rig.stop().await;

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "serve waited for the unfinished upload: {:?}",
        started.elapsed()
    );

    let reply = read_until_closed(&mut stream, Duration::from_secs(2))
        .await
        .expect("the connection is closed");

    assert!(
        reply.is_empty(),
        "no reply: {}",
        String::from_utf8_lossy(&reply)
    );
    assert_eq!(count(&rig).await, 0, "the tool never ran");
}

#[tokio::test]
async fn tool_task_keeps_the_connection_slot_after_the_client_leaves() {
    let rig = support::start_with(Setup {
        server: ServerOptions {
            max_connections: 1,
            ..ServerOptions::default()
        },
        ..Setup::default()
    })
    .await;
    let mcp = rig.mcp().await;
    let call = tokio::spawn(async move {
        mcp.call("example_wait", json!({"milliseconds": 1500}))
            .await
    });

    wait_until(Duration::from_secs(5), "the tool task", || {
        rig.work.live_tasks() == 1
    })
    .await;
    // The bearer check is detached work too; once it has ended, the one live task is the tool.
    sleep(Duration::from_millis(150)).await;

    assert_eq!(rig.work.live_tasks(), 1, "the wait is running");

    call.abort();

    let started = Instant::now();

    assert_eq!(rig.oauth_client.get("/healthz").await.status, 200);
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "the only slot was free while the tool still ran: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn custom_router_with_the_body_layer_answers_in_flight_requests_at_shutdown() {
    let work = Work::new(TaskTracker::new());
    let handler_started = Arc::new(AtomicBool::new(false));
    let started = handler_started.clone();
    let router = Router::new()
        .route(
            "/slow",
            post(move || {
                let started = started.clone();

                async move {
                    started.store(true, Ordering::SeqCst);
                    sleep(Duration::from_millis(800)).await;

                    "finished"
                }
            }),
        )
        .layer(middleware::from_fn_with_state(1 << 10, buffer_body));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let shutdown = CancellationToken::new();
    let serving = tokio::spawn(serve(
        work,
        listener,
        router,
        ServerOptions::default(),
        shutdown.clone(),
    ));
    let call =
        tokio::spawn(async move { raw_http(&address, "POST", "/slow", &[], "{}", false).await });

    wait_until(Duration::from_secs(5), "the handler to start", || {
        handler_started.load(Ordering::SeqCst)
    })
    .await;
    shutdown.cancel();

    let (status, reply) = call.await.unwrap();

    assert_eq!(status, 200, "{reply}");
    assert!(reply.ends_with("finished"), "{reply}");

    serving.await.unwrap();
}
