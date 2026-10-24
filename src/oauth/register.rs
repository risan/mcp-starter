use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;

use super::{MAX_CLIENTS, OAuth, OAuthError, json_response, prune_tokens, random_token};
use crate::store::{Change, Client, Section, State as StoreState};
use crate::work::ConnPermit;

pub(super) const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

pub(super) async fn register<S: Section>(
    State(oauth): State<OAuth<S>>,
    permit: ConnPermit,
    body: Bytes,
) -> Response {
    let work = oauth.inner.work.clone();

    match work
        .run_detached(permit, register_client(oauth, body))
        .await
    {
        Ok(response) => response,
        Err(_) => OAuthError::shutting_down().into_response(),
    }
}

async fn register_client<S: Section>(oauth: OAuth<S>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Registration>(&body) else {
        return OAuthError::bad_request(
            "invalid_client_metadata",
            "the body must be a JSON object",
        )
        .into_response();
    };

    if request
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| !method.is_empty() && method != "none")
    {
        return OAuthError::bad_request(
            "invalid_client_metadata",
            "only public clients are supported (token_endpoint_auth_method none)",
        )
        .into_response();
    }

    if request.redirect_uris.is_empty() || request.redirect_uris.len() > 10 {
        return OAuthError::bad_request(
            "invalid_redirect_uri",
            "redirect_uris must list 1 to 10 URIs",
        )
        .into_response();
    }

    if let Some(redirect) = request
        .redirect_uris
        .iter()
        .find(|uri| !allowed_redirect(uri))
    {
        return OAuthError::bad_request(
            "invalid_redirect_uri",
            &format!("redirect URI not allowed: {redirect}"),
        )
        .into_response();
    }

    let now = oauth.now();
    let client = Client {
        client_id: random_token(16),
        client_name: truncate(request.client_name.as_deref().unwrap_or_default(), 100),
        redirect_uris: request.redirect_uris,
        registered_at: now,
        last_used_at: None,
        extra: Default::default(),
    };
    let stored = client.clone();
    let saved = oauth
        .inner
        .store
        .update(move |state| {
            let keep = stored.client_id.clone();

            state.clients.insert(keep.clone(), stored);

            while state.clients.len() > MAX_CLIENTS {
                if !evict_client(state, &keep) {
                    break;
                }
            }

            prune_tokens(state, now);

            Change::Write(())
        })
        .await;

    if saved.is_err() {
        return OAuthError::internal().into_response();
    }

    json_response(
        StatusCode::CREATED,
        &json!({
            "client_id": client.client_id,
            "client_id_issued_at": client.registered_at.as_second(),
            "redirect_uris": client.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": client.client_name,
        }),
    )
}

/// Removes the client unused for longest (Go D17): never-used clients first, oldest
/// registration first; otherwise the oldest grant. `keep` is spared. Returns whether a
/// client was removed.
fn evict_client<S>(state: &mut StoreState<S>, keep: &str) -> bool {
    let victim = state
        .clients
        .values()
        .filter(|client| client.client_id != keep)
        .min_by_key(|client| {
            (
                client.last_used_at.is_some(),
                client.last_used_at,
                client.registered_at,
            )
        })
        .map(|client| client.client_id.clone());

    let Some(victim) = victim else {
        return false;
    };

    state.clients.remove(&victim);
    state.tokens.retain(|_, token| token.client_id != victim);

    true
}

fn truncate(text: &str, limit: usize) -> String {
    text.trim().chars().take(limit).collect()
}

/// A loopback `http` URL on `localhost` or `127.0.0.1`, any port, with a path.
pub(super) fn parse_loopback(raw: &str) -> Option<Url> {
    let parsed = Url::parse(raw).ok()?;
    let host_is_loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1"));

    (parsed.scheme() == "http"
        && host_is_loopback
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
        && parsed.path().starts_with('/')
        && parsed.port() != Some(0))
    .then_some(parsed)
}

fn allowed_redirect(raw: &str) -> bool {
    raw == CLAUDE_CALLBACK || parse_loopback(raw).is_some()
}

/// Accepts the exact registered URI, or for loopback URIs the same host, path and query on
/// any port.
pub(super) fn redirect_matches(registered: &[String], requested: &str) -> bool {
    let requested_loopback = parse_loopback(requested);

    registered.iter().any(|candidate| {
        if candidate == requested {
            return true;
        }

        match (&requested_loopback, parse_loopback(candidate)) {
            (Some(requested), Some(candidate)) => {
                candidate.host_str() == requested.host_str()
                    && candidate.path() == requested.path()
                    && candidate.query() == requested.query()
            }
            _ => false,
        }
    })
}
