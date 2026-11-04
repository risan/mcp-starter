//! A minimal OAuth 2.1 authorization server: dynamic client registration, PKCE S256, rotating
//! refresh tokens and a sign-in that is either the owner's password on a consent page or an
//! upstream service of the caller's ([`SignIn`]). Clients and grants live in a [`GrantStore`]:
//! the state file for one owner, Postgres (feature `postgres`) for many people. Tokens and codes
//! are opaque; only their SHA-256 is stored.

mod authorize;
#[cfg(feature = "postgres")]
pub mod postgres;
mod register;
mod state_file;
mod token;
mod upstream;

pub use upstream::{Pending, PendingError, SignIn, Upstream};

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::store::{Change, Client, Section, Store, StoreError};
use crate::work::{ShuttingDown, Work};
use crate::{Clock, ServiceInfo};
use authorize::AuthRequest;

const ACCESS_TTL: SignedDuration = SignedDuration::from_hours(24);
const REFRESH_TTL: SignedDuration = SignedDuration::from_hours(60 * 24);
const CODE_TTL: SignedDuration = SignedDuration::from_mins(5);
const CSRF_TTL: SignedDuration = SignedDuration::from_mins(10);
const MAX_PENDING: usize = 100;
/// How long a flow that began before a revocation can still produce a code: a consent page and
/// then the code.
const REVOCATION_MEMORY: SignedDuration = SignedDuration::from_mins(15);
const BODY_LIMIT: usize = 64 << 10;
const LOCKOUT_FAILS: usize = 5;
const LOCKOUT_WINDOW: SignedDuration = SignedDuration::from_mins(15);
const PASSWORD_COST: u32 = 12;
const OFFLINE_ACCESS: &str = "offline_access";

/// Compares the owner's stored hash with a password. Tests inject a counter or a gate.
pub type PasswordChecker = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// The production checker: bcrypt.
pub fn bcrypt_checker() -> PasswordChecker {
    Arc::new(|hash, password| bcrypt::verify(password, hash).unwrap_or(false))
}

/// The person a grant belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// An opaque id, stable for the person.
    pub id: String,
    /// The name to show people.
    pub name: String,
}

impl Subject {
    /// The owner of a single-owner server, who signs in with the password.
    pub fn owner() -> Subject {
        Subject {
            id: "owner".to_string(),
            name: "Owner".to_string(),
        }
    }
}

/// What a valid access token grants.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// The scope the token was issued with.
    pub scope: String,
    /// The person the token was issued to.
    pub subject: Subject,
    /// When the token stops working.
    pub expires_at: Timestamp,
}

/// Why a bearer token was not accepted.
#[derive(Debug)]
pub enum VerifyError {
    /// Unknown, expired, rotated or not an access token.
    Invalid,
    /// The state file could not be read.
    Store(StoreError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Invalid => f.write_str("unknown or expired access token"),
            VerifyError::Store(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for VerifyError {}

/// The hashes and expiry times of a new access and refresh token. The store never sees the
/// raw tokens.
#[derive(Debug, Clone)]
pub struct NewTokens {
    /// Lowercase hex SHA-256 of the access token.
    pub access_hash: String,
    /// Lowercase hex SHA-256 of the refresh token.
    pub refresh_hash: String,
    /// When the access token stops working.
    pub access_expires_at: Timestamp,
    /// When the refresh token stops working.
    pub refresh_expires_at: Timestamp,
}

/// An authorization code that is about to become a grant: a family and its first token pair.
#[derive(Debug, Clone)]
pub struct NewGrant {
    /// Lowercase hex SHA-256 of the code; the id of the family the grant starts.
    pub family: String,
    /// The client the code was issued to.
    pub client_id: String,
    /// The granted scope.
    pub scope: String,
    /// The MCP resource URL the tokens are bound to.
    pub resource: String,
    /// The person the code was approved for.
    pub subject: Subject,
    /// The owner password hash the approval was checked against; the grant is refused when
    /// the owner password has changed since. `None` for a person who signed in upstream.
    pub owner_hash: Option<String>,
    /// The first token pair.
    pub tokens: NewTokens,
}

/// A refresh token that is about to be exchanged for a new pair.
#[derive(Debug, Clone)]
pub struct Rotation {
    /// Lowercase hex SHA-256 of the refresh token the client presented.
    pub presented_hash: String,
    /// The client that presented it.
    pub client_id: String,
    /// The resource of this server; a token issued for another one is refused.
    pub resource: String,
    /// The new token pair.
    pub tokens: NewTokens,
}

/// What a store decided about a code exchange or a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Granted<T> {
    /// The new tokens were stored.
    Issued(T),
    /// The grant is invalid, expired or already used. Whatever the attempt revoked is revoked.
    Refused,
}

/// What a store decided about a new client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// The client was stored.
    Accepted,
    /// The store holds as many clients as it allows and could not make room.
    Full,
}

/// Where the authorization server keeps its clients and grants. The state file implements
/// it for a single owner; every method is one atomic decision, so a store can sit on a
/// database as well as on a file.
///
/// Implementors write `async fn`; the declarations spell out the `Send` bound a router needs.
pub trait GrantStore: Send + Sync + 'static {
    /// The registered client with this id.
    fn find_client(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send;

    /// Stores a new client, making room first when the store is full.
    fn register_client(
        &self,
        client: Client,
        now: Timestamp,
    ) -> impl Future<Output = Result<Registered, StoreError>> + Send;

    /// Turns an approved code into a grant. Refused when the client is gone.
    fn exchange_code(
        &self,
        grant: NewGrant,
        now: Timestamp,
    ) -> impl Future<Output = Result<Granted<()>, StoreError>> + Send;

    /// Exchanges a refresh token for a new pair. Presenting a rotated token revokes its
    /// family and still answers [`Granted::Refused`]. On success it returns the scope.
    fn rotate_refresh(
        &self,
        rotation: Rotation,
        now: Timestamp,
    ) -> impl Future<Output = Result<Granted<String>, StoreError>> + Send;

    /// Deletes every token of a family.
    fn revoke_family(
        &self,
        family: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Revokes by token: a refresh token takes its family, an access token only itself.
    fn revoke_token(
        &self,
        token_hash: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// What a live access token for `resource` grants; `None` for anything else.
    fn verify(
        &self,
        token_hash: &str,
        resource: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<Option<TokenInfo>, StoreError>> + Send;

    /// The bcrypt hash of the owner password; empty when none is set.
    fn owner_password_hash(&self) -> impl Future<Output = Result<String, StoreError>> + Send;

    /// Whether this person approved this client on the consent page before.
    fn has_consent(
        &self,
        subject: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Remembers that this person approved this client. A client that is gone is ignored: its
    /// codes cannot be exchanged anyway.
    fn save_consent(
        &self,
        subject: &str,
        client_id: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes every token of this person. Remembered consents stay: a consent is trust in a
    /// client, not a grant.
    fn revoke_subject(
        &self,
        subject: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// A pending CSRF token, authorization code, sign-in or consent ticket, held in memory only.
trait Expiring {
    fn expires(&self) -> Timestamp;
    fn seq(&self) -> u64;
}

struct CsrfRecord {
    expires: Timestamp,
    params_hash: String,
    seq: u64,
}

impl Expiring for CsrfRecord {
    fn expires(&self) -> Timestamp {
        self.expires
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

struct CodeRecord {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    scope: String,
    resource: String,
    subject: Subject,
    /// The owner password hash the approval was checked against. A password change makes
    /// the code worthless, including one approved by an attempt that was already queued.
    /// `None` when the person signed in upstream.
    owner_hash: Option<String>,
    /// The revocation stamp the sign-in saw. The exchange refuses the code when its subject was
    /// revoked after that.
    stamp: u64,
    expires: Timestamp,
    seq: u64,
}

impl Expiring for CodeRecord {
    fn expires(&self) -> Timestamp {
        self.expires
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Adds a record, first dropping expired ones and then the oldest until there is room, so
/// the map never exceeds `MAX_PENDING`.
fn insert_bounded<R: Expiring>(
    records: &mut HashMap<String, R>,
    key: String,
    record: R,
    now: Timestamp,
) {
    records.retain(|_, existing| now < existing.expires());

    while records.len() >= MAX_PENDING {
        let Some(oldest) = records
            .iter()
            .min_by_key(|(_, existing)| existing.seq())
            .map(|(key, _)| key.clone())
        else {
            break;
        };

        records.remove(&oldest);
    }

    records.insert(key, record);
}

/// An upstream sign-in that has begun and not come back, bound to the browser that began it.
struct SignInRecord {
    request: AuthRequest,
    browser: String,
    started_at: Timestamp,
    expires: Timestamp,
    seq: u64,
}

impl Expiring for SignInRecord {
    fn expires(&self) -> Timestamp {
        self.expires
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// A consent page that was shown and not answered yet.
struct ConsentRecord {
    request: AuthRequest,
    subject: Subject,
    browser: String,
    stamp: u64,
    expires: Timestamp,
    seq: u64,
}

impl Expiring for ConsentRecord {
    fn expires(&self) -> Timestamp {
        self.expires
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// When a subject was last revoked: the `seq` the revocation took, and the time.
struct Revocation {
    seq: u64,
    at: Timestamp,
}

#[derive(Default)]
struct PendingState {
    seq: u64,
    /// Dropped by the next revocation once older than `REVOCATION_MEMORY`.
    revocations: HashMap<String, Revocation>,
    csrf: HashMap<String, CsrfRecord>,
    codes: HashMap<String, CodeRecord>,
    sign_ins: HashMap<String, SignInRecord>,
    consents: HashMap<String, ConsentRecord>,
    failures: Vec<Timestamp>,
    locked_until: Option<Timestamp>,
}

struct Inner<St> {
    store: St,
    info: &'static ServiceInfo,
    issuer: String,
    resource: String,
    clock: Clock,
    sign_in: SignIn,
    work: Arc<Work>,
    pending: Mutex<PendingState>,
    /// Held across the lockout check, the password check and its bookkeeping.
    password_lock: tokio::sync::Mutex<()>,
    /// Held from the code lookup through the store commit that issues the tokens, and by
    /// `revoke_subject`, so the two never interleave.
    grant_lock: tokio::sync::Mutex<()>,
}

/// The authorization server for one service, over a [`GrantStore`]. For the state file,
/// `OAuth<Store<S>>`.
pub struct OAuth<St> {
    inner: Arc<Inner<St>>,
}

impl<St> Clone for OAuth<St> {
    fn clone(&self) -> OAuth<St> {
        OAuth {
            inner: self.inner.clone(),
        }
    }
}

impl<St: GrantStore> OAuth<St> {
    /// `issuer` is the public https origin; the protected resource is `issuer/mcp`. The
    /// service's scope, display name and command come from `info`.
    pub fn new(
        info: &'static ServiceInfo,
        store: St,
        issuer: &str,
        clock: Clock,
        sign_in: SignIn,
        work: Arc<Work>,
    ) -> OAuth<St> {
        OAuth {
            inner: Arc::new(Inner {
                store,
                info,
                issuer: issuer.to_string(),
                resource: format!("{issuer}/mcp"),
                clock,
                sign_in,
                work,
                pending: Mutex::new(PendingState::default()),
                password_lock: tokio::sync::Mutex::new(()),
                grant_lock: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// The OAuth routes. They carry their own 64 KiB body cap, so they are safe on their
    /// own, not only behind the server's body layer.
    pub fn routes(&self) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(metadata::<St>),
            )
            .route("/register", post(register::register::<St>))
            .route(
                "/authorize",
                get(authorize::authorize_get::<St>).post(authorize::authorize_post::<St>),
            )
            .route("/token", post(token::token::<St>))
            .route("/revoke", post(token::revoke::<St>))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .with_state(self.clone())
    }

    fn now(&self) -> Timestamp {
        (self.inner.clock)()
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, PendingState> {
        self.inner.pending.lock().unwrap()
    }

    /// The public https origin the server answers for.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// How many CSRF tokens and authorization codes are waiting in memory.
    pub fn pending_counts(&self) -> (usize, usize) {
        let pending = self.pending();

        (pending.csrf.len(), pending.codes.len())
    }

    /// How many upstream sign-ins and consent tickets are waiting in memory.
    pub fn pending_sign_in_counts(&self) -> (usize, usize) {
        let pending = self.pending();

        (pending.sign_ins.len(), pending.consents.len())
    }

    /// Drops what is waiting in memory for this person: authorization codes that were issued
    /// and consent tickets that were shown. For a service that deletes the person's grants
    /// itself, such as through a foreign key in its own transaction.
    pub fn forget_subject(&self, id: &str) {
        let mut pending = self.pending();

        pending.codes.retain(|_, record| record.subject.id != id);
        pending.consents.retain(|_, record| record.subject.id != id);
    }

    /// Ends this person's grants: [`OAuth::forget_subject`], then every token in the store.
    /// Their remembered consents stay.
    ///
    /// It waits for a code exchange that is under way: an exchange has taken its code before it
    /// writes its tokens, so without the wait it could write them after the delete.
    ///
    /// A sign-in that was already past the upstream when this ran may still issue a code, from
    /// a consent write or lookup that was under way. The exchange refuses that code.
    pub async fn revoke_subject(&self, id: &str) -> Result<(), StoreError> {
        let _exchanges = self.inner.grant_lock.lock().await;
        let now = self.now();

        {
            let mut pending = self.pending();

            pending.seq += 1;

            let revocation = Revocation {
                seq: pending.seq,
                at: now,
            };

            pending
                .revocations
                .retain(|_, existing| now < existing.at + REVOCATION_MEMORY);
            pending.revocations.insert(id.to_string(), revocation);
        }

        self.forget_subject(id);

        self.inner.store.revoke_subject(id, now).await
    }

    /// What a sign-in remembers about revocations when it starts.
    fn revocation_stamp(&self) -> u64 {
        self.pending().seq
    }

    fn revoked_since(&self, id: &str, stamp: u64) -> bool {
        self.pending()
            .revocations
            .get(id)
            .is_some_and(|revocation| revocation.seq > stamp)
    }

    /// Checks a bearer access token against the store. A token issued for another resource
    /// (the state file of a server at another public URL) is refused.
    pub async fn verify(&self, raw_token: &str) -> Result<TokenInfo, VerifyError> {
        self.inner
            .store
            .verify(&hash_token(raw_token), &self.inner.resource, self.now())
            .await
            .map_err(VerifyError::Store)?
            .ok_or(VerifyError::Invalid)
    }
}

async fn metadata<St: GrantStore>(State(oauth): State<OAuth<St>>) -> Response {
    let issuer = &oauth.inner.issuer;

    json_response(
        StatusCode::OK,
        &json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "registration_endpoint": format!("{issuer}/register"),
            "revocation_endpoint": format!("{issuer}/revoke"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [oauth.inner.info.scope, OFFLINE_ACCESS],
            "authorization_response_iss_parameter_supported": true,
        }),
    )
}

/// Stores a bcrypt hash of the owner password and revokes every token.
pub async fn set_password<S: Section>(store: &Store<S>, password: &str) -> Result<(), String> {
    let hash = bcrypt::hash(password, PASSWORD_COST).map_err(|error| error.to_string())?;

    store
        .update(move |state| {
            state.owner.password_hash = hash;
            state.tokens.clear();

            Change::Write(())
        })
        .await
        .map_err(|error| error.to_string())
}

/// Deletes every OAuth token and registered client.
pub async fn revoke_all<S: Section>(store: &Store<S>) -> Result<(), StoreError> {
    store
        .update(|state| {
            state.tokens.clear();
            state.clients.clear();

            Change::Write(())
        })
        .await
}

/// Records written before tokens carried a resource have none; they stay valid.
fn is_for_resource(record_resource: &str, resource: &str) -> bool {
    record_resource.is_empty() || record_resource == resource
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("the operating system has no randomness");

    URL_SAFE_NO_PAD.encode(buffer)
}

fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    let mut response = (status, value.to_string()).into_response();
    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    response
}

/// An RFC 6749 error answer.
#[derive(Debug, Clone)]
struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl OAuthError {
    fn bad_request(code: &'static str, description: &str) -> OAuthError {
        OAuthError {
            status: StatusCode::BAD_REQUEST,
            code,
            description: description.to_string(),
        }
    }

    fn invalid_grant() -> OAuthError {
        OAuthError::bad_request(
            "invalid_grant",
            "the grant is invalid, expired or already used",
        )
    }

    fn internal() -> OAuthError {
        OAuthError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: "could not update the token store".to_string(),
        }
    }

    fn shutting_down() -> OAuthError {
        OAuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "temporarily_unavailable",
            description: ShuttingDown.to_string(),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        json_response(
            self.status,
            &json!({"error": self.code, "error_description": self.description}),
        )
    }
}

/// Parses `a=b&c=d` pairs; a repeated name keeps its first value, as `ParseForm` does.
fn parse_pairs(bytes: &[u8]) -> HashMap<String, String> {
    let mut fields = HashMap::new();

    for (name, value) in
        serde_urlencoded::from_bytes::<Vec<(String, String)>>(bytes).unwrap_or_default()
    {
        fields.entry(name).or_insert(value);
    }

    fields
}
