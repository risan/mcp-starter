//! Drives the OAuth endpoints over real HTTP: register, consent, approve, exchange, refresh.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;

use axum::http::HeaderMap;
use jiff::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

use super::TestClock;
use crate::ServiceInfo;
use crate::oauth::{OAuth, PasswordChecker};
use crate::store::{Change, Section, Store, StoreOptions};
use crate::work::Work;

/// The issuer every rig uses.
pub const ISSUER: &str = "https://mcp.example.com";
/// The owner password every rig sets.
pub const OWNER_PASSWORD: &str = "correct horse battery staple";
/// The one non-loopback redirect URI a client may register.
pub const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
/// A valid PKCE verifier.
pub const VERIFIER: &str = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";

/// Form fields in order.
pub type Pairs = Vec<(String, String)>;

/// An HTTP answer, read whole.
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body as text.
    pub body: String,
}

impl Reply {
    /// A header value, empty when absent.
    pub fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// The body parsed as JSON, `null` when it is not.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// The OAuth `error` code of a JSON error body.
    pub fn error_code(&self) -> String {
        self.json()["error"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// A query parameter of the `Location` header.
    pub fn location_param(&self, name: &str) -> Option<String> {
        let location = self.header("location");
        let url = reqwest::Url::parse(&location).ok()?;

        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }
}

#[derive(Clone, Debug)]
/// A token answer.
pub struct Tokens {
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: String,
    /// The whole answer body.
    pub raw: Value,
}

/// Counts and gates the injected password checker.
#[derive(Default)]
pub struct Probe {
    started: AtomicUsize,
    completed: AtomicUsize,
    running: AtomicUsize,
    max_running: AtomicUsize,
    threads: Mutex<Vec<ThreadId>>,
    gate: Mutex<bool>,
    gate_opened: Condvar,
}

impl Probe {
    /// Makes every check wait until `release`.
    pub fn hold(&self) {
        *self.gate.lock().unwrap() = true;
    }

    /// Lets the waiting checks go.
    pub fn release(&self) {
        *self.gate.lock().unwrap() = false;
        self.gate_opened.notify_all();
    }

    /// How many checks have started.
    pub fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    /// How many checks have finished.
    pub fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    /// The most checks that ran at once.
    pub fn max_running(&self) -> usize {
        self.max_running.load(Ordering::SeqCst)
    }

    /// The thread each check ran on.
    pub fn threads(&self) -> Vec<ThreadId> {
        self.threads.lock().unwrap().clone()
    }

    /// The checker to hand to [`OAuth::new`].
    pub fn checker(self: &Arc<Probe>) -> PasswordChecker {
        let probe = self.clone();

        Arc::new(move |hash, password| {
            probe.started.fetch_add(1, Ordering::SeqCst);
            probe
                .threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());

            let running = probe.running.fetch_add(1, Ordering::SeqCst) + 1;
            probe.max_running.fetch_max(running, Ordering::SeqCst);

            let mut held = probe.gate.lock().unwrap();

            while *held {
                held = probe.gate_opened.wait(held).unwrap();
            }

            drop(held);

            let matches = bcrypt::verify(password, hash).unwrap_or(false);

            probe.running.fetch_sub(1, Ordering::SeqCst);
            probe.completed.fetch_add(1, Ordering::SeqCst);

            matches
        })
    }
}

/// The S256 challenge of a verifier.
pub fn pkce(verifier: &str) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The query of a valid authorization request.
pub fn authorize_params(info: &ServiceInfo, client_id: &str, redirect: &str) -> Pairs {
    let scope = format!("{} offline_access", info.scope);

    [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code_challenge", &pkce(VERIFIER)),
        ("code_challenge_method", "S256"),
        ("state", "st-1"),
        ("scope", &scope),
        ("resource", &format!("{ISSUER}/mcp")),
    ]
    .iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

/// Sets a field, replacing an earlier one of the same name.
pub fn set_param(pairs: &mut Pairs, name: &str, value: &str) {
    pairs.retain(|(key, _)| key != name);
    pairs.push((name.to_string(), value.to_string()));
}

/// An HTTP client for the OAuth endpoints of one service.
#[derive(Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    info: &'static ServiceInfo,
    /// The base URL the routes are served at.
    pub base: String,
}

impl OAuthClient {
    /// A client for the routes served at `base`.
    pub fn new(info: &'static ServiceInfo, base: &str) -> OAuthClient {
        super::install_crypto_provider();

        OAuthClient {
            info,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: base.to_string(),
        }
    }

    async fn reply(response: reqwest::Response) -> Reply {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();

        Reply {
            status,
            headers,
            body,
        }
    }

    /// A GET.
    pub async fn get(&self, path: &str) -> Reply {
        OAuthClient::reply(
            self.http
                .get(format!("{}{path}", self.base))
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    /// A POST with a raw body.
    pub async fn post(&self, path: &str, content_type: &str, body: String) -> Reply {
        let request = self
            .http
            .post(format!("{}{path}", self.base))
            .header("content-type", content_type)
            .body(body);

        OAuthClient::reply(request.send().await.unwrap()).await
    }

    /// A form POST.
    pub async fn post_form(&self, path: &str, pairs: &[(String, String)]) -> Reply {
        let body = serde_urlencoded::to_string(pairs).unwrap();

        self.post(path, "application/x-www-form-urlencoded", body)
            .await
    }

    /// A JSON POST.
    pub async fn post_json(&self, path: &str, body: &Value) -> Reply {
        self.post(path, "application/json", body.to_string()).await
    }

    /// Registers a client and returns its id.
    pub async fn register(&self, redirects: &[&str]) -> String {
        let body = json!({"client_name": "Claude", "redirect_uris": redirects, "token_endpoint_auth_method": "none"});
        let reply = self.post_json("/register", &body).await;

        assert_eq!(reply.status, 201, "register: {}", reply.body);

        reply.json()["client_id"].as_str().unwrap().to_string()
    }

    /// Loads the consent page and returns the form values it would post, when it has a form.
    pub async fn consent(&self, params: &Pairs) -> (Option<Pairs>, Reply) {
        let query = serde_urlencoded::to_string(params).unwrap();
        let reply = self.get(&format!("/authorize?{query}")).await;
        let marker = "name=\"csrf\" value=\"";
        let csrf = reply.body.find(marker).map(|start| {
            let rest = &reply.body[start + marker.len()..];

            rest[..rest.find('"').unwrap()].to_string()
        });
        let form = csrf.map(|csrf| {
            let mut form = params.clone();
            set_param(&mut form, "csrf", &csrf);

            form
        });

        (form, reply)
    }

    /// Posts the consent form with a password.
    pub async fn approve(&self, form: &Pairs, password: &str) -> Reply {
        let mut form = form.clone();
        set_param(&mut form, "password", password);

        self.post_form("/authorize", &form).await
    }

    /// Runs the whole consent flow and returns the authorization code.
    pub async fn grant(&self, client_id: &str, redirect: &str) -> String {
        let (form, reply) = self
            .consent(&authorize_params(self.info, client_id, redirect))
            .await;
        let form =
            form.unwrap_or_else(|| panic!("no consent page ({}): {}", reply.status, reply.body));
        let approved = self.approve(&form, OWNER_PASSWORD).await;

        assert_eq!(approved.status, 303, "approve: {}", approved.body);

        approved
            .location_param("code")
            .unwrap_or_else(|| panic!("no code in {}", approved.header("location")))
    }

    /// Exchanges an authorization code.
    pub async fn exchange(
        &self,
        client_id: &str,
        redirect: &str,
        code: &str,
        verifier: &str,
    ) -> (Reply, Option<Tokens>) {
        let reply = self
            .post_form(
                "/token",
                &pairs(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client_id),
                    ("redirect_uri", redirect),
                    ("code_verifier", verifier),
                ]),
            )
            .await;
        let tokens = tokens_of(&reply);

        (reply, tokens)
    }

    /// Exchanges a refresh token.
    pub async fn refresh(&self, client_id: &str, refresh_token: &str) -> (Reply, Option<Tokens>) {
        let reply = self
            .post_form(
                "/token",
                &pairs(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", client_id),
                ]),
            )
            .await;
        let tokens = tokens_of(&reply);

        (reply, tokens)
    }

    /// A registered client with a fresh token pair, and the code that produced it.
    pub async fn full_flow(&self) -> (String, Tokens, String) {
        self.full_flow_with_password(OWNER_PASSWORD).await
    }

    /// [`OAuthClient::full_flow`] with a chosen owner password.
    pub async fn full_flow_with_password(&self, password: &str) -> (String, Tokens, String) {
        let client_id = self.register(&[CLAUDE_CALLBACK]).await;
        let (form, reply) = self
            .consent(&authorize_params(self.info, &client_id, CLAUDE_CALLBACK))
            .await;
        let form =
            form.unwrap_or_else(|| panic!("no consent page ({}): {}", reply.status, reply.body));
        let approved = self.approve(&form, password).await;

        assert_eq!(approved.status, 303, "approve: {}", approved.body);

        let code = approved
            .location_param("code")
            .expect("a code in the redirect");
        let (reply, tokens) = self
            .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
            .await;

        assert_eq!(reply.status, 200, "exchange: {}", reply.body);

        (client_id, tokens.unwrap(), code)
    }
}

/// Form fields from string pairs.
pub fn pairs(items: &[(&str, &str)]) -> Pairs {
    items
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn tokens_of(reply: &Reply) -> Option<Tokens> {
    let raw = reply.json();

    Some(Tokens {
        access_token: raw["access_token"].as_str()?.to_string(),
        refresh_token: raw["refresh_token"].as_str()?.to_string(),
        raw,
    })
}

/// The OAuth routes alone on a bare test router, over a fresh data dir with the owner
/// password set.
pub struct OAuthRig<S> {
    /// The data dir.
    pub dir: TempDir,
    /// The state file.
    pub store: Store<S>,
    /// The clock the server reads.
    pub clock: TestClock,
    /// The server under test.
    pub oauth: OAuth<S>,
    /// A client for the server's routes.
    pub client: OAuthClient,
    /// Counts and gates password checks.
    pub probe: Arc<Probe>,
    /// The detached work the server starts.
    pub work: Arc<Work>,
    info: &'static ServiceInfo,
    server: JoinHandle<()>,
}

impl<S: Section> OAuthRig<S> {
    /// A rig with default store options.
    pub async fn start(info: &'static ServiceInfo) -> OAuthRig<S> {
        OAuthRig::start_with(info, StoreOptions::default()).await
    }

    /// A rig with the given store options.
    pub async fn start_with(info: &'static ServiceInfo, options: StoreOptions) -> OAuthRig<S> {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), options).unwrap();
        let hash = bcrypt::hash(OWNER_PASSWORD, 4).unwrap();

        store
            .update(move |state| {
                state.owner.password_hash = hash;

                Change::Write(())
            })
            .await
            .unwrap();

        let clock = TestClock::new("2026-10-24T09:00:00Z");
        let probe = Arc::new(Probe::default());
        let work = Work::new(TaskTracker::new());
        let (oauth, client, server) = OAuthRig::serve(info, &store, &clock, &probe, &work).await;

        OAuthRig {
            dir,
            store,
            clock,
            oauth,
            client,
            probe,
            work,
            info,
            server,
        }
    }

    async fn serve(
        info: &'static ServiceInfo,
        store: &Store<S>,
        clock: &TestClock,
        probe: &Arc<Probe>,
        work: &Arc<Work>,
    ) -> (OAuth<S>, OAuthClient, JoinHandle<()>) {
        let oauth = OAuth::new(
            info,
            store.clone(),
            ISSUER,
            clock.as_clock(),
            probe.checker(),
            work.clone(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = oauth.routes();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (
            oauth.clone(),
            OAuthClient::new(info, &format!("http://{address}")),
            server,
        )
    }

    /// A fresh `OAuth` on the same store, like a restart.
    pub async fn restart(&mut self) {
        self.server.abort();

        let (oauth, client, server) =
            OAuthRig::serve(self.info, &self.store, &self.clock, &self.probe, &self.work).await;

        self.oauth = oauth;
        self.client = client;
        self.server = server;
    }

    /// The `host:port` the routes are served at.
    pub fn address(&self) -> String {
        self.client.base.trim_start_matches("http://").to_string()
    }

    /// Whether the server accepts the access token.
    pub async fn valid(&self, access_token: &str) -> bool {
        self.oauth.verify(access_token).await.is_ok()
    }

    /// A copy of the state file.
    pub async fn state(&self) -> crate::store::State<S> {
        self.store.read(|state| state.clone()).await.unwrap()
    }

    /// The time the clock shows.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

impl<S> Drop for OAuthRig<S> {
    fn drop(&mut self) {
        self.server.abort();
    }
}
