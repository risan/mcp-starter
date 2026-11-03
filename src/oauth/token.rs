use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    ACCESS_TTL, CodeRecord, GrantStore, Granted, NewGrant, NewTokens, OAuth, OAuthError,
    REFRESH_TTL, Rotation, constant_time_eq, hash_token, json_response, parse_pairs, random_token,
};
use crate::work::ConnPermit;

struct TokenResponse {
    access_token: String,
    refresh_token: String,
    scope: String,
}

impl TokenResponse {
    fn into_json(self) -> serde_json::Value {
        json!({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL.as_secs(),
            "refresh_token": self.refresh_token,
            "scope": self.scope,
        })
    }
}

struct CodeGrant {
    code: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
    resource: String,
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

pub(super) async fn token<St: GrantStore>(
    State(oauth): State<OAuth<St>>,
    permit: ConnPermit,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let work = oauth.inner.work.clone();
    let is_form = is_form(&headers);

    match work.run_detached(permit, grant(oauth, is_form, body)).await {
        Ok(response) => response,
        Err(_) => OAuthError::shutting_down().into_response(),
    }
}

async fn grant<St: GrantStore>(oauth: OAuth<St>, is_form: bool, body: Bytes) -> Response {
    if !is_form {
        return OAuthError::bad_request(
            "invalid_request",
            "the token endpoint takes application/x-www-form-urlencoded",
        )
        .into_response();
    }

    let form = parse_pairs(&body);
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();

    let result = match field("grant_type").as_str() {
        "authorization_code" => {
            let grant = CodeGrant {
                code: field("code"),
                client_id: field("client_id"),
                redirect_uri: field("redirect_uri"),
                code_verifier: field("code_verifier"),
                resource: field("resource"),
            };
            oauth.clone().exchange_code(grant).await
        }
        "refresh_token" => {
            oauth
                .rotate_refresh(field("refresh_token"), field("client_id"))
                .await
        }
        _ => Err(OAuthError::bad_request(
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        )),
    };

    match result {
        Ok(response) => json_response(StatusCode::OK, &response.into_json()),
        Err(error) => error.into_response(),
    }
}

fn verifier_is_valid(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

fn pkce_matches(challenge: &str, verifier: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// A fresh token pair: the raw values for the client and the hashes for the store.
struct Minted {
    access: String,
    refresh: String,
    stored: NewTokens,
}

impl Minted {
    fn new(now: Timestamp) -> Minted {
        let (access, refresh) = (random_token(32), random_token(32));
        let stored = NewTokens {
            access_hash: hash_token(&access),
            refresh_hash: hash_token(&refresh),
            access_expires_at: now + ACCESS_TTL,
            refresh_expires_at: now + REFRESH_TTL,
        };

        Minted {
            access,
            refresh,
            stored,
        }
    }

    fn response(self, scope: String) -> TokenResponse {
        TokenResponse {
            access_token: self.access,
            refresh_token: self.refresh,
            scope,
        }
    }
}

impl<St: GrantStore> OAuth<St> {
    /// Exchanges an authorization code. It runs as detached work under one lock held from the
    /// code lookup through the store commit that issues the tokens, so a concurrent
    /// replay waits, then finds the family in `state.json` and revokes it. The commit also
    /// refuses the code when the owner password changed since it was approved.
    async fn exchange_code(self, grant: CodeGrant) -> Result<TokenResponse, OAuthError> {
        if grant.code.is_empty() || grant.client_id.is_empty() {
            return Err(OAuthError::bad_request(
                "invalid_request",
                "code and client_id are required",
            ));
        }

        let _exchange = self.inner.grant_lock.lock().await;
        let code_hash = hash_token(&grant.code);
        let now = self.now();
        let record: Option<CodeRecord> = self.pending().codes.remove(&code_hash);

        let Some(record) = record.filter(|record| now < record.expires) else {
            // A code that is gone may have been used: revoke what it produced.
            let family = code_hash;

            return match self.revoke_family(family).await {
                Ok(()) => Err(OAuthError::invalid_grant()),
                Err(_) => Err(OAuthError::internal()),
            };
        };

        if record.client_id != grant.client_id
            || record.redirect_uri != grant.redirect_uri
            || !verifier_is_valid(&grant.code_verifier)
            || !pkce_matches(&record.challenge, &grant.code_verifier)
        {
            return Err(OAuthError::invalid_grant());
        }

        if !grant.resource.is_empty() && grant.resource != record.resource {
            return Err(OAuthError::bad_request(
                "invalid_target",
                "the resource does not match the authorization",
            ));
        }

        let minted = Minted::new(now);
        let scope = record.scope.clone();
        let new_grant = NewGrant {
            family: code_hash,
            client_id: grant.client_id,
            scope: record.scope,
            resource: record.resource,
            subject: record.subject,
            owner_hash: record.owner_hash,
            tokens: minted.stored.clone(),
        };

        match self.inner.store.exchange_code(new_grant, now).await {
            Ok(Granted::Issued(())) => Ok(minted.response(scope)),
            Ok(Granted::Refused) => Err(OAuthError::invalid_grant()),
            Err(_) => Err(OAuthError::internal()),
        }
    }

    async fn revoke_family(&self, family: String) -> Result<(), crate::store::StoreError> {
        self.inner.store.revoke_family(&family, self.now()).await
    }

    /// Rotates a refresh token: one store transaction with a fresh read. Presenting an
    /// already-rotated token revokes the whole family and persists that revocation although
    /// the answer is an error. A token issued for another resource is refused; one without
    /// a resource (an older record) is accepted and its new tokens carry this server's.
    async fn rotate_refresh(
        &self,
        refresh_token: String,
        client_id: String,
    ) -> Result<TokenResponse, OAuthError> {
        if refresh_token.is_empty() || client_id.is_empty() {
            return Err(OAuthError::bad_request(
                "invalid_request",
                "refresh_token and client_id are required",
            ));
        }

        let now = self.now();
        let minted = Minted::new(now);
        let rotation = Rotation {
            presented_hash: hash_token(&refresh_token),
            client_id,
            resource: self.inner.resource.clone(),
            tokens: minted.stored.clone(),
        };

        match self.inner.store.rotate_refresh(rotation, now).await {
            Ok(Granted::Issued(scope)) => Ok(minted.response(scope)),
            Ok(Granted::Refused) => Err(OAuthError::invalid_grant()),
            Err(_) => Err(OAuthError::internal()),
        }
    }
}

pub(super) async fn revoke<St: GrantStore>(
    State(oauth): State<OAuth<St>>,
    permit: ConnPermit,
    body: Bytes,
) -> Response {
    let work = oauth.inner.work.clone();

    match work.run_detached(permit, revoke_token(oauth, body)).await {
        Ok(response) => response,
        Err(_) => OAuthError::shutting_down().into_response(),
    }
}

async fn revoke_token<St: GrantStore>(oauth: OAuth<St>, body: Bytes) -> Response {
    let form = parse_pairs(&body);
    let hash = hash_token(form.get("token").map_or("", String::as_str));
    let saved = oauth.inner.store.revoke_token(&hash, oauth.now()).await;

    if saved.is_err() {
        return OAuthError::internal().into_response();
    }

    json_response(StatusCode::OK, &json!({}))
}
