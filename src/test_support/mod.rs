//! Helpers for the tests of a service built on this crate: clocks, polling, raw HTTP and the
//! rigs that run the OAuth server and the whole HTTP server in the test process.
//!
//! Enabled by the `test-support` feature, which a service turns on only under
//! `[dev-dependencies]`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};

use crate::Clock;
pub use crate::http::install_crypto_provider;

pub mod oauth_flow;

/// A clock a test moves by hand.
#[derive(Clone)]
pub struct TestClock {
    now: Arc<Mutex<Timestamp>>,
}

impl TestClock {
    /// A clock showing `now`, an RFC 3339 timestamp.
    pub fn new(now: &str) -> TestClock {
        TestClock {
            now: Arc::new(Mutex::new(now.parse().unwrap())),
        }
    }

    /// The time the clock shows.
    pub fn now(&self) -> Timestamp {
        *self.now.lock().unwrap()
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: SignedDuration) {
        let mut now = self.now.lock().unwrap();
        *now += by;
    }

    /// The clock as the [`Clock`] the blocks take.
    pub fn as_clock(&self) -> Clock {
        let clone = self.clone();

        Arc::new(move || clone.now())
    }
}

/// Polls until `condition` holds, failing the test after `limit`.
pub async fn wait_until(limit: Duration, what: &str, condition: impl Fn() -> bool) {
    let started = std::time::Instant::now();

    while !condition() {
        assert!(started.elapsed() < limit, "timed out waiting for {what}");

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Sends one raw HTTP/1.1 request and returns the status code and the whole reply text. The
/// server may answer and close before the body is fully written, so write errors are ignored.
pub async fn raw_http(
    address: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
    chunked: bool,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\n");

    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }

    let payload = if chunked {
        format!(
            "{head}transfer-encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
    } else {
        format!("{head}content-length: {}\r\n\r\n{body}", body.len())
    };
    let _ = stream.write_all(payload.as_bytes()).await;
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply).await;
    let text = String::from_utf8_lossy(&reply).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    (status, text)
}
