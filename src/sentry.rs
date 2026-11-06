//! Reports error lines to Sentry, so a team's alert rules can notify people. It speaks Sentry's
//! envelope endpoint directly: the `sentry` crate would bring a second HTTP and TLS stack.
//!
//! ```ignore
//! let reporter = match config.sentry_dsn {
//!     Some(dsn) => Reporter::sentry(client, dsn, "my-service"),
//!     None => Reporter::default(),
//! };
//!
//! reporter.report("upstream-unavailable", "my-service: upstream timed out");
//! ```

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, Url};
use serde_json::json;
use tokio::sync::Semaphore;

/// The longest a report may take. It runs beside the reply, never in front of it.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// How many reports may be on the wire at once. A burst of errors beyond that is dropped from
/// Sentry (stderr still gets every line), so a stalled Sentry costs a few connections, not one
/// per error.
const CONCURRENT_SENDS: usize = 4;

/// How long reports stop after a 429 that says nothing usable about it.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// The longest a 429 can silence reports, so a wild `Retry-After` cannot switch them off.
const MAX_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// A Sentry DSN, `https://PUBLIC_KEY@HOST/PROJECT_ID`, split into what a report needs.
#[derive(Clone, PartialEq, Eq)]
pub struct SentryDsn {
    /// The DSN's public key, sent in the `X-Sentry-Auth` header.
    pub public_key: String,
    /// Where the envelope is posted: `<scheme>://HOST[/PREFIX]/api/PROJECT_ID/envelope/`.
    pub envelope_url: String,
}

impl SentryDsn {
    /// Parses a DSN; `None` when it is not one. Plain `http` is accepted for tests and
    /// self-hosted Sentry.
    pub fn parse(text: &str) -> Option<SentryDsn> {
        let mut url = Url::parse(text).ok()?;
        // The project id is the last path segment; what comes before it is a prefix the Sentry
        // server is mounted under. Sentry's project ids are u64; anything else would build an
        // ingest URL that never works.
        let (prefix, project_id) = url.path().rsplit_once('/')?;
        let project_id = project_id.parse::<u64>().ok()?;
        let prefix = prefix.to_string();
        let is_dsn = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && !url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none();

        if !is_dsn {
            return None;
        }

        let public_key = url.username().to_string();

        url.set_username("").ok()?;
        url.set_path(&format!("{prefix}/api/{project_id}/envelope/"));

        Some(SentryDsn {
            public_key,
            envelope_url: url.to_string(),
        })
    }
}

// Not derived, so a `{:?}` of anything that holds a DSN never prints its key.
impl fmt::Debug for SentryDsn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SentryDsn").finish_non_exhaustive()
    }
}

/// Where a service's error lines go: stderr, and also Sentry when it was built with a DSN. A
/// clone is cheap and shares the client.
#[derive(Clone, Default)]
pub struct Reporter {
    sentry: Option<Arc<Target>>,
}

struct Target {
    client: Client,
    dsn: SentryDsn,
    logger: &'static str,
    sends: Arc<Semaphore>,
    /// Until when Sentry asked to be left alone.
    quiet_until: Mutex<Option<Instant>>,
}

impl Target {
    fn is_quiet(&self) -> bool {
        let quiet_until = self.quiet_until.lock().unwrap();

        quiet_until.is_some_and(|until| Instant::now() < until)
    }

    fn stay_quiet_for(&self, wait: Duration) {
        *self.quiet_until.lock().unwrap() = Some(Instant::now() + wait);
    }
}

impl Reporter {
    /// A reporter that also sends each line to Sentry. `logger` names the service on the event.
    pub fn sentry(client: Client, dsn: SentryDsn, logger: &'static str) -> Reporter {
        Reporter {
            sentry: Some(Arc::new(Target {
                client,
                dsn,
                logger,
                sends: Arc::new(Semaphore::new(CONCURRENT_SENDS)),
                quiet_until: Mutex::new(None),
            })),
        }
    }

    /// Writes `line` to stderr and, when this reporter has a DSN, reports it to Sentry as one
    /// error event. Lines with the same `fingerprint` are one Sentry issue, whatever their
    /// details.
    ///
    /// The report is sent on the current tokio runtime in a task of its own, so the caller never
    /// waits for it; with no runtime (the caller is sync) nothing is sent. Only a few reports
    /// are on the wire at once, and none while Sentry has asked for quiet (a 429): the others
    /// are dropped, with their line still on stderr.
    pub fn report(&self, fingerprint: &'static str, line: &str) {
        eprintln!("{line}");

        let Some(target) = self.sentry.clone() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };

        if target.is_quiet() {
            return;
        }

        let Ok(permit) = target.sends.clone().try_acquire_owned() else {
            return;
        };
        let line = line.to_string();

        runtime.spawn(async move {
            let sent = post(
                &target.client,
                &target.dsn,
                target.logger,
                fingerprint,
                &line,
            )
            .await;

            drop(permit);

            match sent {
                Ok(()) => {}
                Err(Failure::RateLimited(wait)) => {
                    target.stay_quiet_for(wait);
                    eprintln!("sentry: report failed: {}", Failure::RateLimited(wait));
                }
                Err(failure) => eprintln!("sentry: report failed: {failure}"),
            }
        });
    }
}

// Not derived, so a `{:?}` of anything that holds a reporter never prints the DSN's key.
impl fmt::Debug for Reporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Reporter")
    }
}

/// Posts `line` as one error event in an envelope. Sentry groups the events with the same
/// `fingerprint` into one issue whatever the details. The error names the cause by kind and
/// never carries the URL.
pub async fn send(
    client: &Client,
    dsn: &SentryDsn,
    logger: &str,
    fingerprint: &str,
    line: &str,
) -> Result<(), String> {
    post(client, dsn, logger, fingerprint, line)
        .await
        .map_err(|failure| failure.to_string())
}

/// Why a report did not get through.
enum Failure {
    /// Sentry answered 429 and asked for this long a pause.
    RateLimited(Duration),
    Other(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::RateLimited(_) => formatter.write_str("HTTP 429"),
            Failure::Other(cause) => formatter.write_str(cause),
        }
    }
}

async fn post(
    client: &Client,
    dsn: &SentryDsn,
    logger: &str,
    fingerprint: &str,
    line: &str,
) -> Result<(), Failure> {
    let event_id = new_event_id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let event = json!({
        "event_id": event_id,
        "timestamp": timestamp,
        "level": "error",
        "platform": "other",
        "logger": logger,
        "message": {"formatted": line},
        "fingerprint": [fingerprint],
    });
    let envelope = format!(
        "{}\n{}\n{event}\n",
        json!({"event_id": event_id}),
        json!({"type": "event"})
    );
    let auth = format!(
        "Sentry sentry_version=7, sentry_key={}, sentry_client=mcp-starter/{}",
        dsn.public_key,
        env!("CARGO_PKG_VERSION")
    );
    let response = client
        .post(&dsn.envelope_url)
        .header("X-Sentry-Auth", auth)
        .body(envelope)
        .timeout(SEND_TIMEOUT)
        .send()
        .await
        .map_err(|error| Failure::Other(transport_cause(error)))?;
    let status = response.status();

    if status.as_u16() == 429 {
        return Err(Failure::RateLimited(cooldown(response.headers())));
    }

    if !status.is_success() {
        return Err(Failure::Other(format!("HTTP {}", status.as_u16())));
    }

    Ok(())
}

/// The pause a 429 asks for in `Retry-After` seconds; a default when it is absent or not
/// seconds, and never more than [`MAX_COOLDOWN`].
fn cooldown(headers: &HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_COOLDOWN, Duration::from_secs)
        .min(MAX_COOLDOWN)
}

/// Sentry wants 32 lowercase hex characters.
fn new_event_id() -> String {
    let mut bytes = [0u8; 16];

    getrandom::fill(&mut bytes).expect("the operating system has no randomness");

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// reqwest's own message is only "error sending request" for every transport failure, and its
/// source chain can carry the URL, so the cause is named by kind instead.
fn transport_cause(error: reqwest::Error) -> String {
    if error.is_timeout() {
        return "timeout".to_string();
    }

    if error.is_connect() {
        return "connect failed".to_string();
    }

    error.without_url().to_string()
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::routing::post;
    use tokio::sync::mpsc;

    use crate::http::client_builder;

    use super::*;

    const KEY: &str = "secret-key";

    struct Received {
        path: String,
        auth: String,
        body: String,
    }

    #[derive(Clone)]
    struct FakeSentry {
        received: mpsc::UnboundedSender<Received>,
        status: StatusCode,
    }

    async fn record(
        State(fake): State<FakeSentry>,
        headers: HeaderMap,
        uri: Uri,
        body: String,
    ) -> StatusCode {
        let auth = headers
            .get("x-sentry-auth")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();

        fake.received
            .send(Received {
                path: uri.path().to_string(),
                auth,
                body,
            })
            .unwrap();

        fake.status
    }

    /// A fake Sentry answering `status`; returns its DSN and what it received.
    async fn fake_sentry(status: StatusCode) -> (SentryDsn, mpsc::UnboundedReceiver<Received>) {
        let (received, receiver) = mpsc::unbounded_channel();
        let router = Router::new()
            .route("/api/7/envelope/", post(record))
            .with_state(FakeSentry { received, status });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let dsn = SentryDsn::parse(&format!("http://{KEY}@{address}/7")).unwrap();

        (dsn, receiver)
    }

    /// A DSN whose port nothing listens on.
    async fn unreachable_dsn() -> SentryDsn {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        drop(listener);

        SentryDsn::parse(&format!("http://{KEY}@{address}/7")).unwrap()
    }

    fn client() -> Client {
        client_builder(None).build().unwrap()
    }

    fn body_lines(received: &Received) -> [serde_json::Value; 3] {
        let lines: Vec<serde_json::Value> = received
            .body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        lines.try_into().unwrap()
    }

    #[test]
    fn a_dsn_splits_into_its_key_and_envelope_url() {
        let dsn = SentryDsn::parse("https://abc123@o1.ingest.sentry.io/456").unwrap();

        assert_eq!(dsn.public_key, "abc123");
        assert_eq!(
            dsn.envelope_url,
            "https://o1.ingest.sentry.io/api/456/envelope/"
        );
    }

    #[test]
    fn a_plain_http_dsn_with_a_port_is_accepted() {
        let dsn = SentryDsn::parse("http://abc@127.0.0.1:9000/7").unwrap();

        assert_eq!(dsn.public_key, "abc");
        assert_eq!(dsn.envelope_url, "http://127.0.0.1:9000/api/7/envelope/");
    }

    #[test]
    fn a_dsn_with_a_path_prefix_keeps_the_prefix_before_api() {
        let dsn = SentryDsn::parse("https://abc@host.example/sentry/7").unwrap();

        assert_eq!(
            dsn.envelope_url,
            "https://host.example/sentry/api/7/envelope/"
        );

        let dsn = SentryDsn::parse("https://abc@host.example/a/b/7").unwrap();

        assert_eq!(dsn.envelope_url, "https://host.example/a/b/api/7/envelope/");
    }

    #[tokio::test]
    async fn a_prefixed_dsn_posts_under_its_prefix() {
        let (sender, mut received) = mpsc::unbounded_channel();
        let router = Router::new()
            .route(
                "/sentry/api/7/envelope/",
                post(
                    |State(fake): State<FakeSentry>, headers, uri, body| async move {
                        record(State(fake), headers, uri, body).await
                    },
                ),
            )
            .with_state(FakeSentry {
                received: sender,
                status: StatusCode::OK,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let dsn = SentryDsn::parse(&format!("http://{KEY}@{address}/sentry/7")).unwrap();

        send(&client(), &dsn, "svc", "boom", "line").await.unwrap();

        assert_eq!(
            received.recv().await.unwrap().path,
            "/sentry/api/7/envelope/"
        );
    }

    #[test]
    fn text_that_is_not_a_dsn_is_refused() {
        for text in [
            "",
            "not a dsn",
            "ftp://key@host/1",
            "https://host/1",
            "https://key@host",
            "https://key@host/",
            "https://key:password@host/1",
            "https://key@host/1?a=b",
            "https://key@host/1#fragment",
            "https://key@host/project",
            "https://key@host/%2F",
            "https://key@host/18446744073709551616",
        ] {
            assert_eq!(SentryDsn::parse(text), None, "{text}");
        }
    }

    #[test]
    fn debug_never_prints_the_key() {
        let dsn = SentryDsn::parse(&format!("https://{KEY}@host.example/1")).unwrap();
        let reporter = Reporter::sentry(client(), dsn.clone(), "svc");

        for text in [
            format!("{dsn:?}"),
            format!("{dsn:#?}"),
            format!("{reporter:?}"),
            format!("{reporter:#?}"),
            format!("{:?}", Some(&dsn)),
        ] {
            assert!(!text.contains(KEY), "{text}");
        }
    }

    #[test]
    fn event_ids_are_32_lowercase_hex_characters_and_differ() {
        let first = new_event_id();

        assert_eq!(first.len(), 32);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{first}"
        );
        assert_ne!(first, new_event_id());
    }

    #[tokio::test]
    async fn send_posts_the_envelope_to_the_projects_envelope_url() {
        let (dsn, mut received) = fake_sentry(StatusCode::OK).await;

        send(&client(), &dsn, "svc", "boom", "svc: it broke")
            .await
            .unwrap();

        let request = received.recv().await.unwrap();
        let [header, item, event] = body_lines(&request);

        assert_eq!(request.path, "/api/7/envelope/");
        assert_eq!(
            request.auth,
            format!(
                "Sentry sentry_version=7, sentry_key={KEY}, sentry_client=mcp-starter/{}",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(item["type"], "event");
        assert_eq!(header["event_id"], event["event_id"]);
        assert_eq!(event["event_id"].as_str().unwrap().len(), 32);
        assert_eq!(event["level"], "error");
        assert_eq!(event["platform"], "other");
        assert_eq!(event["logger"], "svc");
        assert_eq!(event["message"]["formatted"], "svc: it broke");
        assert_eq!(event["fingerprint"], json!(["boom"]));
        assert!(event["timestamp"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn report_sends_the_line_with_the_reporters_logger_and_the_fingerprint() {
        let (dsn, mut received) = fake_sentry(StatusCode::OK).await;
        let reporter = Reporter::sentry(client(), dsn, "svc");

        reporter.report("boom", "svc: it broke");

        let request = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("the report arrives")
            .unwrap();
        let [_, _, event] = body_lines(&request);

        assert_eq!(event["logger"], "svc");
        assert_eq!(event["message"]["formatted"], "svc: it broke");
        assert_eq!(event["fingerprint"], json!(["boom"]));
    }

    #[tokio::test]
    async fn a_refused_report_is_an_error_naming_the_status() {
        let (dsn, _received) = fake_sentry(StatusCode::INTERNAL_SERVER_ERROR).await;

        let error = send(&client(), &dsn, "svc", "boom", "line")
            .await
            .unwrap_err();

        assert_eq!(error, "HTTP 500");
    }

    #[tokio::test]
    async fn an_unreachable_sentry_is_an_error_that_does_not_name_the_url_or_key() {
        let dsn = unreachable_dsn().await;
        let error = send(&client(), &dsn, "svc", "boom", "line")
            .await
            .unwrap_err();

        assert_eq!(error, "connect failed");
    }

    #[tokio::test]
    async fn report_returns_and_does_not_panic_when_sentry_is_down() {
        let reporter = Reporter::sentry(client(), unreachable_dsn().await, "svc");

        reporter.report("boom", "svc: it broke");
        // The failed send runs in its own task; let it finish to see that it does not panic.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[test]
    fn report_outside_a_runtime_only_writes_the_line() {
        let dsn = SentryDsn::parse(&format!("http://{KEY}@127.0.0.1:1/7")).unwrap();

        Reporter::sentry(client(), dsn, "svc").report("boom", "svc: it broke");
        Reporter::default().report("boom", "svc: it broke");
    }

    #[test]
    fn a_rate_limit_pause_is_the_retry_after_seconds_with_a_default_and_a_cap() {
        let with = |value: &'static str| {
            let mut headers = HeaderMap::new();

            headers.insert(RETRY_AFTER, value.parse().unwrap());

            cooldown(&headers)
        };

        assert_eq!(with("5"), Duration::from_secs(5));
        assert_eq!(with(" 7 "), Duration::from_secs(7));
        assert_eq!(with("soon"), DEFAULT_COOLDOWN);
        assert_eq!(with("-3"), DEFAULT_COOLDOWN);
        assert_eq!(with("99999999999999999999"), DEFAULT_COOLDOWN);
        assert_eq!(with("18446744073709551615"), MAX_COOLDOWN);
        assert_eq!(cooldown(&HeaderMap::new()), DEFAULT_COOLDOWN);
    }

    #[tokio::test]
    async fn after_a_429_reports_pause_for_the_retry_after_and_then_resume() {
        let (sender, mut received) = mpsc::unbounded_channel();
        let router = Router::new()
            .route(
                "/api/7/envelope/",
                post(
                    |State(sender): State<mpsc::UnboundedSender<String>>, body: String| async move {
                        sender.send(body).unwrap();

                        (StatusCode::TOO_MANY_REQUESTS, [(RETRY_AFTER, "1")])
                    },
                ),
            )
            .with_state(sender);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let dsn = SentryDsn::parse(&format!("http://{KEY}@{address}/7")).unwrap();
        let reporter = Reporter::sentry(client(), dsn, "svc");

        reporter.report("boom", "first");
        received.recv().await.unwrap();
        // The client reads the 429 after the server has seen the request.
        tokio::time::sleep(Duration::from_millis(200)).await;
        reporter.report("boom", "during the pause");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            received.try_recv().is_err(),
            "a report went out during the pause"
        );

        tokio::time::sleep(Duration::from_millis(1000)).await;
        reporter.report("boom", "after the pause");

        let body = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("reports resume")
            .unwrap();

        assert!(body.contains("after the pause"), "{body}");
    }

    #[tokio::test]
    async fn a_burst_against_a_stalled_sentry_keeps_few_sends_in_flight_and_returns_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone, Default)]
        struct Stalled {
            now: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }

        let stalled = Stalled::default();
        let router = Router::new()
            .route(
                "/api/7/envelope/",
                post(|State(stalled): State<Stalled>| async move {
                    let now = stalled.now.fetch_add(1, Ordering::SeqCst) + 1;

                    stalled.peak.fetch_max(now, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }),
            )
            .with_state(stalled.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let dsn = SentryDsn::parse(&format!("http://{KEY}@{address}/7")).unwrap();
        let reporter = Reporter::sentry(client(), dsn, "svc");
        let started = Instant::now();

        for number in 0..100 {
            reporter.report("boom", &format!("line {number}"));
        }

        assert!(started.elapsed() < Duration::from_secs(1));

        tokio::time::sleep(Duration::from_millis(500)).await;

        assert_eq!(stalled.peak.load(Ordering::SeqCst), CONCURRENT_SENDS);
    }
}
