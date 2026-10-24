//! A minimal single-owner OAuth 2.1 authorization server: dynamic client registration, PKCE
//! S256, a password consent page and rotating refresh tokens. Tokens and codes are opaque;
//! only their SHA-256 is stored.

mod authorize;
mod register;
mod token;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
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

use crate::store::{Change, Section, State as StoreState, Store, StoreError, TokenKind};
use crate::work::{ShuttingDown, Work};
use crate::{Clock, ServiceInfo};

const ACCESS_TTL: SignedDuration = SignedDuration::from_hours(24);
const REFRESH_TTL: SignedDuration = SignedDuration::from_hours(60 * 24);
const CODE_TTL: SignedDuration = SignedDuration::from_mins(5);
const CSRF_TTL: SignedDuration = SignedDuration::from_mins(10);
const MAX_CLIENTS: usize = 50;
const MAX_PENDING: usize = 100;
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

/// What a valid access token grants.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// The scope the token was issued with.
    pub scope: String,
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

/// A pending CSRF token or authorization code, held in memory only.
trait Pending {
    fn expires(&self) -> Timestamp;
    fn seq(&self) -> u64;
}

struct CsrfRecord {
    expires: Timestamp,
    params_hash: String,
    seq: u64,
}

impl Pending for CsrfRecord {
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
    expires: Timestamp,
    seq: u64,
}

impl Pending for CodeRecord {
    fn expires(&self) -> Timestamp {
        self.expires
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Adds a record, first dropping expired ones and then the oldest until there is room, so
/// the map never exceeds `MAX_PENDING`.
fn insert_bounded<R: Pending>(
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

#[derive(Default)]
struct PendingState {
    seq: u64,
    csrf: HashMap<String, CsrfRecord>,
    codes: HashMap<String, CodeRecord>,
    failures: Vec<Timestamp>,
    locked_until: Option<Timestamp>,
}

struct Inner<S> {
    store: Store<S>,
    info: &'static ServiceInfo,
    issuer: String,
    resource: String,
    clock: Clock,
    checker: PasswordChecker,
    work: Arc<Work>,
    pending: Mutex<PendingState>,
    /// Held across the lockout check, the password check and its bookkeeping (D47).
    password_lock: tokio::sync::Mutex<()>,
    /// Held from the code lookup through the store commit that issues the tokens (D50).
    grant_lock: tokio::sync::Mutex<()>,
}

/// The authorization server for one service, over its state file.
pub struct OAuth<S> {
    inner: Arc<Inner<S>>,
}

impl<S> Clone for OAuth<S> {
    fn clone(&self) -> OAuth<S> {
        OAuth {
            inner: self.inner.clone(),
        }
    }
}

impl<S: Section> OAuth<S> {
    /// `issuer` is the public https origin; the protected resource is `issuer/mcp`. The
    /// service's scope, display name and command come from `info`.
    pub fn new(
        info: &'static ServiceInfo,
        store: Store<S>,
        issuer: &str,
        clock: Clock,
        checker: PasswordChecker,
        work: Arc<Work>,
    ) -> OAuth<S> {
        OAuth {
            inner: Arc::new(Inner {
                store,
                info,
                issuer: issuer.to_string(),
                resource: format!("{issuer}/mcp"),
                clock,
                checker,
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
                get(metadata::<S>),
            )
            .route("/register", post(register::register::<S>))
            .route(
                "/authorize",
                get(authorize::authorize_get::<S>).post(authorize::authorize_post::<S>),
            )
            .route("/token", post(token::token::<S>))
            .route("/revoke", post(token::revoke::<S>))
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

    /// Checks a bearer access token against `state.json`.
    pub async fn verify(&self, raw_token: &str) -> Result<TokenInfo, VerifyError> {
        let hash = hash_token(raw_token);
        let now = self.now();
        let info = self
            .inner
            .store
            .read(move |state| {
                let record = state.tokens.get(&hash)?;

                (record.kind == TokenKind::Access && !record.rotated && now < record.expires_at)
                    .then(|| TokenInfo {
                        scope: record.scope.clone(),
                        expires_at: record.expires_at,
                    })
            })
            .await
            .map_err(VerifyError::Store)?;

        info.ok_or(VerifyError::Invalid)
    }
}

async fn metadata<S: Section>(State(oauth): State<OAuth<S>>) -> Response {
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

/// Drops expired tokens. A rotated refresh record stays only while its family still has a
/// live token, so replaying it keeps revoking the descendants; a family with nothing live
/// is removed whole. Returns whether anything was removed.
fn prune_tokens<S>(state: &mut StoreState<S>, now: Timestamp) -> bool {
    let live: BTreeSet<String> = state
        .tokens
        .values()
        .filter(|token| !token.rotated && now < token.expires_at)
        .map(|token| token.family.clone())
        .collect();
    let before = state.tokens.len();

    state.tokens.retain(|_, token| {
        if token.rotated {
            live.contains(&token.family)
        } else {
            now < token.expires_at
        }
    });

    state.tokens.len() != before
}

fn delete_family<S>(state: &mut StoreState<S>, family: &str) -> bool {
    let before = state.tokens.len();

    state.tokens.retain(|_, token| token.family != family);

    state.tokens.len() != before
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
