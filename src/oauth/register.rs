use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;

use super::{GrantStore, OAuth, OAuthError, Registered, json_response, random_token};
use crate::store::Client;
use crate::work::ConnPermit;

pub(super) const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_COM_CALLBACK: &str = "https://claude.com/api/mcp/auth_callback";
// ChatGPT uses the stable callback or, for an authorization server without RFC 9207 issuer
// identification, one with a per-connector id
// (https://developers.openai.com/apps-sdk/build/auth).
const CHATGPT_CALLBACK: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
const CHATGPT_CONNECTOR_CALLBACK_PREFIX: &str = "https://chatgpt.com/connector/oauth/";

#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

pub(super) async fn register<St: GrantStore>(
    State(oauth): State<OAuth<St>>,
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

async fn register_client<St: GrantStore>(oauth: OAuth<St>, body: Bytes) -> Response {
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
        consented_subjects: Vec::new(),
        extra: Default::default(),
    };
    let saved = oauth.inner.store.register_client(client.clone(), now).await;

    match saved {
        Ok(Registered::Accepted) => {}
        Ok(Registered::Full) => {
            eprintln!("register: too many registered clients");

            return OAuthError::bad_request(
                "invalid_client_metadata",
                "too many registered clients",
            )
            .into_response();
        }
        Err(_) => return OAuthError::internal().into_response(),
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
    raw == CLAUDE_CALLBACK
        || raw == CLAUDE_COM_CALLBACK
        || raw == CHATGPT_CALLBACK
        || is_chatgpt_connector_callback(raw)
        || parse_loopback(raw).is_some()
}

fn is_chatgpt_connector_callback(raw: &str) -> bool {
    let Some(callback_id) = raw.strip_prefix(CHATGPT_CONNECTOR_CALLBACK_PREFIX) else {
        return false;
    };

    (1..=128).contains(&callback_id.len())
        && callback_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
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
