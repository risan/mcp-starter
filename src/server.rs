//! HTTP wiring: the router with its bearer middleware and body layer, and the connection
//! driver with its deadlines.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::ServiceInfo;
use crate::oauth::{OAuth, VerifyError};
use crate::store::Section;
use crate::work::{ConnPermit, Work};

const MCP_BODY_LIMIT: usize = 1 << 20;
const OAUTH_BODY_LIMIT: usize = 64 << 10;
const MAX_HEADER_BYTES: usize = 32 << 10;

/// The hosts a request may name: the public URL's host (and `host:port` when it has a port)
/// plus the loopback names cloudflared and local callers use.
pub fn allowed_hosts(public_url: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let authority = public_url.strip_prefix("https://").unwrap_or(public_url);

    if !authority.is_empty() {
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host);

        hosts.push(host.to_string());

        if host != authority {
            hosts.push(authority.to_string());
        }
    }

    hosts.extend(["localhost", "127.0.0.1", "::1"].map(String::from));

    hosts
}

/// The stateless MCP endpoint with JSON responses. One service is built once; `tools` hands
/// each request a handler holding the shared state.
pub fn mcp_service<H, F>(
    public_url: &str,
    tools: F,
) -> StreamableHttpService<H, NeverSessionManager>
where
    H: ServerHandler + Send + 'static,
    F: Fn() -> H + Send + Sync + 'static,
{
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts(public_url))
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_max_request_body_bytes(MCP_BODY_LIMIT);

    StreamableHttpService::new(
        move || Ok(tools()),
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

/// Every route behind its body layer: `/healthz`, the favicon, the home page (when set), the OAuth
/// routes, the protected-resource metadata and `/mcp`. `/mcp` checks the bearer first, so an
/// anonymous caller never makes the server buffer a body.
pub fn build_router<S, H>(
    info: &'static ServiceInfo,
    oauth: OAuth<S>,
    work: Arc<Work>,
    mcp: StreamableHttpService<H, NeverSessionManager>,
) -> Router
where
    S: Section,
    H: ServerHandler + Send + 'static,
{
    build_router_with(info, oauth, work, mcp, Router::new())
}

/// [`build_router`] plus the service's own `routes`. They are logged like every other route
/// and sit outside the 64 KiB OAuth body layer, so they get no body cap unless they add
/// [`buffer_body`] themselves. A path the built-in routes already use makes axum panic when
/// the router is built.
pub fn build_router_with<S, H>(
    info: &'static ServiceInfo,
    oauth: OAuth<S>,
    work: Arc<Work>,
    mcp: StreamableHttpService<H, NeverSessionManager>,
    routes: Router,
) -> Router
where
    S: Section,
    H: ServerHandler + Send + 'static,
{
    let public_url = oauth.issuer().to_string();
    let metadata_url = format!("{public_url}/.well-known/oauth-protected-resource");
    let resource_metadata = json!({
        "resource": format!("{public_url}/mcp"),
        "authorization_servers": [public_url],
        "scopes_supported": [info.scope],
        "bearer_methods_supported": ["header"],
    })
    .to_string();
    let metadata = move || {
        let body = resource_metadata.clone();

        async move { ([(header::CONTENT_TYPE, "application/json")], body) }
    };
    let favicon = move || async move {
        (
            [
                (header::CONTENT_TYPE, "image/x-icon"),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            info.favicon,
        )
    };
    let home_page = move || async move {
        (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            info.home_page,
        )
    };

    let oauth_routes = oauth.routes();
    let mcp = Router::new()
        .route_service("/mcp", mcp)
        .route_layer(middleware::from_fn_with_state(MCP_BODY_LIMIT, buffer_body))
        .route_layer(middleware::from_fn_with_state(
            BearerState {
                oauth,
                work,
                metadata_url,
            },
            require_bearer,
        ));

    let mut router = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/favicon.ico", get(favicon));

    if !info.home_page.is_empty() {
        router = router.route("/", get(home_page));
    }

    router
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata.clone()),
        )
        .route("/.well-known/oauth-protected-resource/mcp", get(metadata))
        .merge(oauth_routes)
        .layer(middleware::from_fn_with_state(
            OAUTH_BODY_LIMIT,
            buffer_body,
        ))
        .merge(mcp)
        .merge(routes)
        .layer(middleware::from_fn(log_request))
}

/// One line per request: method, path (never the query) and status.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;

    eprintln!("{method} {path} {}", response.status().as_u16());

    response
}

struct BearerState<S> {
    oauth: OAuth<S>,
    work: Arc<Work>,
    metadata_url: String,
}

impl<S> Clone for BearerState<S> {
    fn clone(&self) -> BearerState<S> {
        BearerState {
            oauth: self.oauth.clone(),
            work: self.work.clone(),
            metadata_url: self.metadata_url.clone(),
        }
    }
}

/// Our own middleware because it must emit `error="invalid_token"` when a token was sent
/// and check expiry against the injectable clock.
async fn require_bearer<S: Section>(
    State(state): State<BearerState<S>>,
    permit: ConnPermit,
    request: Request,
    next: Next,
) -> Response {
    let challenge = |with_error: bool| {
        let error = if with_error {
            r#"error="invalid_token", "#
        } else {
            ""
        };

        format!(
            r#"Bearer {error}resource_metadata="{}""#,
            state.metadata_url
        )
    };
    let unauthorized = |with_error: bool, message: &'static str| {
        let mut response = (StatusCode::UNAUTHORIZED, message).into_response();

        if let Ok(value) = HeaderValue::from_str(&challenge(with_error)) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }

        response
    };

    let Some(token) = bearer_token(&request) else {
        return unauthorized(false, "authentication required");
    };
    let oauth = state.oauth.clone();
    let check = {
        let (oauth, token) = (oauth.clone(), token.clone());

        async move { oauth.verify(&token).await }
    };
    // A request accepted before shutdown still gets its answer, so a refused spawn falls
    // back to checking inline; the tool then reports that the server is shutting down.
    let verified = match state.work.run_detached(permit, check).await {
        Ok(verified) => verified,
        Err(_) => oauth.verify(&token).await,
    };

    match verified {
        Ok(_) => next.run(request).await,
        Err(VerifyError::Invalid) => unauthorized(true, "invalid or expired token"),
        Err(VerifyError::Store(error)) => {
            eprintln!("bearer check: {error}");

            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

fn bearer_token(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();

    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_string())
}

/// Durations and limits of the connection driver; tests scale them down.
#[derive(Clone)]
pub struct ServerOptions {
    /// Connections served at once; more wait in the kernel backlog.
    pub max_connections: usize,
    /// The time the request line and headers have to arrive in.
    pub header_read_timeout: Duration,
    /// The time a request has to arrive in full, counted from the accept.
    pub read_deadline: Duration,
    /// The time the reply has to be delivered, counted from the end of the request read.
    pub write_deadline: Duration,
}

impl Default for ServerOptions {
    fn default() -> ServerOptions {
        ServerOptions {
            max_connections: 64,
            header_read_timeout: Duration::from_secs(10),
            read_deadline: Duration::from_secs(30),
            write_deadline: Duration::from_secs(60),
        }
    }
}

/// What a request's layers need from its connection: the deadline to move, and a mark that
/// the request has been read in full.
struct ConnControl {
    deadline: watch::Sender<Instant>,
    request_read: AtomicBool,
    write_deadline: Duration,
}

/// Reads the whole body first, with the route's cap, and then gives the reply its write
/// window, so a slow upload cannot eat into it. Over the cap answers 413 before any
/// handler, state change or password check runs.
///
/// [`build_router`] applies it on every route. A service that builds its own router must apply
/// it too, on every route that reads a body: [`serve`] closes a connection at shutdown unless
/// this layer has marked its request as read, so without it every request in flight is cut off.
/// Put it inside any layer that rejects a caller (`middleware::from_fn_with_state(limit,
/// buffer_body)`), so an anonymous request never makes the server buffer a body.
pub async fn buffer_body(State(limit): State<usize>, request: Request, next: Next) -> Response {
    let control = request.extensions().get::<Arc<ConnControl>>().cloned();
    let (parts, body) = request.into_parts();

    let bytes = match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let too_large = error
                .into_inner()
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some();

            return if too_large {
                (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response()
            } else {
                (StatusCode::BAD_REQUEST, "could not read the request body").into_response()
            };
        }
    };

    if let Some(control) = control {
        control.request_read.store(true, Ordering::SeqCst);
        control
            .deadline
            .send_replace(Instant::now() + control.write_deadline);
    }

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Accepts connections until `shutdown`, then drains: the listener closes, new work is
/// refused, connections still reading their request are closed, and the call returns once
/// every tracked task has ended: the connections, the detached work and any background loop
/// the service started on the same tracker.
pub async fn serve(
    work: Arc<Work>,
    listener: TcpListener,
    router: Router,
    options: ServerOptions,
    shutdown: CancellationToken,
) {
    let slots = Arc::new(Semaphore::new(options.max_connections));

    loop {
        let permit = tokio::select! {
            permit = slots.clone().acquire_owned() => permit.expect("the semaphore is never closed"),
            _ = shutdown.cancelled() => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.cancelled() => break,
        };
        let stream = match accepted {
            Ok((stream, _peer)) => stream,
            Err(error) => {
                eprintln!("accept: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;

                continue;
            }
        };
        let connection = drive_connection(
            stream,
            router.clone(),
            options.clone(),
            Arc::new(permit),
            shutdown.clone(),
        );

        work.tracker().spawn(connection);
    }

    drop(listener);
    work.begin_shutdown();
    work.tracker().close();
    work.tracker().wait().await;
}

/// Serves one connection with one request (keep-alive is off, so no connection sits idle and
/// no idle timer or buffer outlives a request). The deadline starts at accept + the read
/// deadline and moves when the request has been read; when it passes, the connection is
/// dropped whether the handler is still running or a stalled reader has the reply stuck.
async fn drive_connection(
    stream: tokio::net::TcpStream,
    router: Router,
    options: ServerOptions,
    slot: Arc<tokio::sync::OwnedSemaphorePermit>,
    shutdown: CancellationToken,
) {
    let (deadline, mut deadline_changes) = watch::channel(Instant::now() + options.read_deadline);
    let control = Arc::new(ConnControl {
        deadline,
        request_read: AtomicBool::new(false),
        write_deadline: options.write_deadline,
    });
    let router = router
        .layer(Extension(ConnPermit(Some(slot))))
        .layer(Extension(control.clone()));
    let mut builder = http1::Builder::new();

    builder
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout)
        .max_buf_size(MAX_HEADER_BYTES)
        .keep_alive(false);

    let connection =
        builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
    tokio::pin!(connection);

    let mut shutdown_seen = false;

    loop {
        let deadline = *deadline_changes.borrow_and_update();

        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    eprintln!("connection: {error}");
                }

                return;
            }
            _ = tokio::time::sleep_until(deadline) => return,
            _ = deadline_changes.changed() => {}
            _ = shutdown.cancelled(), if !shutdown_seen => {
                shutdown_seen = true;

                if !control.request_read.load(Ordering::SeqCst) {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use axum::body::Bytes;
    use http_body::{Body as HttpBody, Frame};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpSocket;

    use super::*;

    /// A body far larger than loopback socket buffers hold; it records when it is dropped.
    struct BigBody {
        remaining_chunks: usize,
        dropped_at: Arc<Mutex<Option<std::time::Instant>>>,
    }

    impl HttpBody for BigBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if self.remaining_chunks == 0 {
                return Poll::Ready(None);
            }

            self.remaining_chunks -= 1;

            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![7u8; 64 * 1024])))))
        }
    }

    impl Drop for BigBody {
        fn drop(&mut self) {
            *self.dropped_at.lock().unwrap() = Some(std::time::Instant::now());
        }
    }

    #[tokio::test]
    async fn stalled_reader_closed_after_write_deadline() {
        let dropped_at = Arc::new(Mutex::new(None));
        let body_clock = dropped_at.clone();
        let router = Router::new()
            .route(
                "/big",
                get(move || {
                    let dropped_at = body_clock.clone();

                    async move {
                        // 64 MiB in 64 KiB chunks
                        Response::new(Body::new(BigBody {
                            remaining_chunks: 1024,
                            dropped_at,
                        }))
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(64 << 10, buffer_body));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let options = ServerOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_secs(5),
            read_deadline: Duration::from_secs(5),
            write_deadline: Duration::from_millis(300),
        };
        let slot = Arc::new(Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();

            drive_connection(stream, router, options, slot, CancellationToken::new()).await;
        });

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut client = socket.connect(address).await.unwrap();
        let sent_at = std::time::Instant::now();

        client
            .write_all(b"GET /big HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        // the client never reads
        timeout_for(server).await;

        let dropped = dropped_at
            .lock()
            .unwrap()
            .expect("the body must have been dropped");
        let waited = dropped.duration_since(sent_at);

        assert!(
            waited >= Duration::from_millis(280),
            "closed before the write deadline: {waited:?}"
        );
        assert!(
            waited < Duration::from_millis(1500),
            "not closed at the write deadline: {waited:?}"
        );
    }

    async fn timeout_for(server: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the connection must end at the write deadline")
            .unwrap();
    }

    #[test]
    fn allowed_hosts_include_public_host_and_loopback() {
        assert_eq!(
            allowed_hosts("https://mcp.example.com"),
            ["mcp.example.com", "localhost", "127.0.0.1", "::1"]
        );
        assert_eq!(
            allowed_hosts("https://mcp.example.com:8443"),
            [
                "mcp.example.com",
                "mcp.example.com:8443",
                "localhost",
                "127.0.0.1",
                "::1"
            ]
        );
        assert_eq!(allowed_hosts(""), ["localhost", "127.0.0.1", "::1"]);
    }
}
