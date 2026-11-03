//! Drives the OAuth endpoints over real HTTP: register, consent, approve, exchange, refresh.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use jiff::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

use super::TestClock;
use crate::ServiceInfo;
use crate::oauth::{GrantStore, OAuth, PasswordChecker, SignIn, Subject, Upstream};
use crate::store::{Change, Section, Store, StoreOptions};
use crate::work::Work;

/// The issuer every rig uses.
pub const ISSUER: &str = "https://mcp.example.com";
/// The owner password every rig sets.
pub const OWNER_PASSWORD: &str = "correct horse battery staple";
/// The one non-loopback redirect URI a client may register.
pub const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
/// The name of the cookie that binds a sign-in to the browser that started it.
pub const SIGN_IN_COOKIE: &str = "__Host-mcp-sign-in";
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

    /// The value of the browser-binding cookie the reply sets.
    pub fn sign_in_cookie(&self) -> Option<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|cookie| {
                cookie
                    .strip_prefix(&format!("{SIGN_IN_COOKIE}="))
                    .and_then(|rest| rest.split(';').next())
                    .map(str::to_string)
            })
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

/// The query of a valid authorization request to a server at [`ISSUER`]. For a server at
/// another public URL, use [`OAuthClient::authorize_params`] on a client made
/// [`OAuthClient::with_issuer`].
pub fn authorize_params(info: &ServiceInfo, client_id: &str, redirect: &str) -> Pairs {
    params_for_resource(info, &resource_of(ISSUER), client_id, redirect)
}

fn resource_of(issuer: &str) -> String {
    format!("{issuer}/mcp")
}

fn params_for_resource(
    info: &ServiceInfo,
    resource: &str,
    client_id: &str,
    redirect: &str,
) -> Pairs {
    let scope = format!("{} offline_access", info.scope);

    [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code_challenge", &pkce(VERIFIER)),
        ("code_challenge_method", "S256"),
        ("state", "st-1"),
        ("scope", &scope),
        ("resource", resource),
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
    resource: String,
    /// The base URL the routes are served at.
    pub base: String,
}

impl OAuthClient {
    /// A client for the routes served at `base` by a server whose public URL is [`ISSUER`].
    pub fn new(info: &'static ServiceInfo, base: &str) -> OAuthClient {
        super::install_crypto_provider();

        OAuthClient {
            info,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            resource: resource_of(ISSUER),
            base: base.to_string(),
        }
    }

    /// The same client for a server whose public URL is `issuer`: its authorization
    /// requests name `issuer/mcp` as the resource.
    pub fn with_issuer(mut self, issuer: &str) -> OAuthClient {
        self.resource = resource_of(issuer);

        self
    }

    /// The query of a valid authorization request to this client's server.
    pub fn authorize_params(&self, client_id: &str, redirect: &str) -> Pairs {
        params_for_resource(self.info, &self.resource, client_id, redirect)
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
            .consent(&self.authorize_params(client_id, redirect))
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

    /// A GET as the browser that holds `cookie`.
    pub async fn get_as(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut request = self.http.get(format!("{}{path}", self.base));

        if let Some(cookie) = cookie {
            request = request.header("cookie", format!("{SIGN_IN_COOKIE}={cookie}"));
        }

        OAuthClient::reply(request.send().await.unwrap()).await
    }

    /// A form POST as the browser that holds `cookie`.
    pub async fn post_form_as(
        &self,
        path: &str,
        pairs: &[(String, String)],
        cookie: Option<&str>,
    ) -> Reply {
        let mut request = self
            .http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(pairs).unwrap());

        if let Some(cookie) = cookie {
            request = request.header("cookie", format!("{SIGN_IN_COOKIE}={cookie}"));
        }

        OAuthClient::reply(request.send().await.unwrap()).await
    }

    /// `GET /authorize` on an upstream server as the browser that holds `cookie` (a new
    /// browser when `None`). Returns the reply.
    pub async fn authorize_as(&self, params: &Pairs, cookie: Option<&str>) -> Reply {
        let query = serde_urlencoded::to_string(params).unwrap();

        self.get_as(&format!("/authorize?{query}"), cookie).await
    }

    /// Starts a sign-in and returns the pending id and the browser's cookie.
    pub async fn start_sign_in(
        &self,
        client_id: &str,
        redirect: &str,
        cookie: Option<&str>,
    ) -> (String, String) {
        let reply = self
            .authorize_as(&self.authorize_params(client_id, redirect), cookie)
            .await;

        assert_eq!(reply.status, 302, "authorize: {}", reply.body);

        let location = reply.header("location");
        let pending = reply
            .location_param("pending")
            .unwrap_or_else(|| panic!("no pending id in {location}"));

        (pending, reply.sign_in_cookie().expect("a sign-in cookie"))
    }

    /// The service's callback: `subject` called `name` finished signing in.
    pub async fn finish_sign_in(
        &self,
        pending: &str,
        cookie: Option<&str>,
        subject: &str,
        name: &str,
    ) -> Reply {
        let query = serde_urlencoded::to_string([
            ("pending", pending),
            ("subject", subject),
            ("name", name),
        ])
        .unwrap();

        self.get_as(&format!("/upstream/callback?{query}"), cookie)
            .await
    }

    /// The service's callback: the upstream refused the sign-in.
    pub async fn deny_sign_in(&self, pending: &str, cookie: Option<&str>) -> Reply {
        let query = serde_urlencoded::to_string([("pending", pending), ("deny", "1")]).unwrap();

        self.get_as(&format!("/upstream/callback?{query}"), cookie)
            .await
    }

    /// Starts a sign-in and finishes it as `subject`. Returns the browser's cookie and the
    /// reply of the callback: the consent page or the redirect with a code.
    pub async fn sign_in(
        &self,
        client_id: &str,
        redirect: &str,
        subject: &str,
        name: &str,
    ) -> (String, Reply) {
        let (pending, cookie) = self.start_sign_in(client_id, redirect, None).await;
        let reply = self
            .finish_sign_in(&pending, Some(&cookie), subject, name)
            .await;

        (cookie, reply)
    }

    /// The consent ticket in a consent page.
    pub fn consent_ticket(reply: &Reply) -> Option<String> {
        let marker = "name=\"ticket\" value=\"";
        let start = reply.body.find(marker)? + marker.len();
        let rest = &reply.body[start..];

        Some(rest[..rest.find('"')?].to_string())
    }

    /// Posts the consent page's `decision` (`allow` or `cancel`) for `ticket`.
    pub async fn decide(&self, ticket: &str, decision: &str, cookie: Option<&str>) -> Reply {
        self.post_form_as(
            "/authorize",
            &pairs(&[("ticket", ticket), ("decision", decision)]),
            cookie,
        )
        .await
    }

    /// Signs in as `subject`, clicks Allow when the consent page shows, and returns the
    /// browser's cookie and the code.
    pub async fn upstream_grant(
        &self,
        client_id: &str,
        redirect: &str,
        subject: &str,
        name: &str,
    ) -> (String, String) {
        let (cookie, mut reply) = self.sign_in(client_id, redirect, subject, name).await;

        if let Some(ticket) = OAuthClient::consent_ticket(&reply) {
            reply = self.decide(&ticket, "allow", Some(&cookie)).await;
        }

        let code = reply
            .location_param("code")
            .unwrap_or_else(|| panic!("no code ({}): {}", reply.status, reply.body));

        (cookie, code)
    }

    /// A registered client with a fresh token pair, and the code that produced it.
    pub async fn full_flow(&self) -> (String, Tokens, String) {
        self.full_flow_with_password(OWNER_PASSWORD).await
    }

    /// [`OAuthClient::full_flow`] with a chosen owner password.
    pub async fn full_flow_with_password(&self, password: &str) -> (String, Tokens, String) {
        let client_id = self.register(&[CLAUDE_CALLBACK]).await;
        let (form, reply) = self
            .consent(&self.authorize_params(&client_id, CLAUDE_CALLBACK))
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

/// The upstream the test rigs send browsers to.
pub struct TestUpstream;

impl Upstream for TestUpstream {
    fn sign_in_url(&self, pending: &str) -> String {
        format!("https://upstream.example/sign-in?pending={pending}")
    }
}

/// The OAuth routes plus `GET /upstream/callback?pending=&subject=&name=&deny=`, which plays
/// the service's callback: it takes the pending sign-in, then denies it when `deny` is
/// present and otherwise completes it for `subject` called `name`.
pub fn upstream_routes<St: GrantStore>(oauth: OAuth<St>) -> Router {
    let callback = Router::new()
        .route("/upstream/callback", get(upstream_callback::<St>))
        .with_state(oauth.clone());

    oauth.routes().merge(callback)
}

async fn upstream_callback<St: GrantStore>(
    State(oauth): State<OAuth<St>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let field = |name: &str| query.get(name).cloned().unwrap_or_default();
    let pending = match oauth.take_pending(&headers, &field("pending")) {
        Ok(pending) => pending,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };

    if query.contains_key("deny") {
        return oauth.deny(pending);
    }

    let subject = Subject {
        id: field("subject"),
        name: field("name"),
    };

    oauth.complete(pending, subject).await
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
    pub oauth: OAuth<Store<S>>,
    /// A client for the server's routes.
    pub client: OAuthClient,
    /// Counts and gates password checks.
    pub probe: Arc<Probe>,
    /// The detached work the server starts.
    pub work: Arc<Work>,
    info: &'static ServiceInfo,
    upstream: bool,
    server: JoinHandle<()>,
}

impl<S: Section> OAuthRig<S> {
    /// A rig with default store options.
    pub async fn start(info: &'static ServiceInfo) -> OAuthRig<S> {
        OAuthRig::start_with(info, StoreOptions::default()).await
    }

    /// A rig whose sign-in goes to [`TestUpstream`]: the routes are [`upstream_routes`].
    pub async fn start_upstream(info: &'static ServiceInfo) -> OAuthRig<S> {
        OAuthRig::start_in(info, StoreOptions::default(), true).await
    }

    /// A rig with the given store options.
    pub async fn start_with(info: &'static ServiceInfo, options: StoreOptions) -> OAuthRig<S> {
        OAuthRig::start_in(info, options, false).await
    }

    async fn start_in(
        info: &'static ServiceInfo,
        options: StoreOptions,
        upstream: bool,
    ) -> OAuthRig<S> {
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
        let (oauth, client, server) =
            OAuthRig::serve(info, &store, &clock, &probe, &work, upstream).await;

        OAuthRig {
            dir,
            store,
            clock,
            oauth,
            client,
            probe,
            work,
            info,
            upstream,
            server,
        }
    }

    async fn serve(
        info: &'static ServiceInfo,
        store: &Store<S>,
        clock: &TestClock,
        probe: &Arc<Probe>,
        work: &Arc<Work>,
        upstream: bool,
    ) -> (OAuth<Store<S>>, OAuthClient, JoinHandle<()>) {
        let sign_in = if upstream {
            SignIn::Upstream(Arc::new(TestUpstream))
        } else {
            SignIn::Password(probe.checker())
        };
        let oauth = OAuth::new(
            info,
            store.clone(),
            ISSUER,
            clock.as_clock(),
            sign_in,
            work.clone(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = if upstream {
            upstream_routes(oauth.clone())
        } else {
            oauth.routes()
        };
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

        let (oauth, client, server) = OAuthRig::serve(
            self.info,
            &self.store,
            &self.clock,
            &self.probe,
            &self.work,
            self.upstream,
        )
        .await;

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
