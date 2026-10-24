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
    ACCESS_TTL, CodeRecord, OAuth, OAuthError, REFRESH_TTL, delete_family, hash_token,
    is_for_resource, json_response, parse_pairs, prune_tokens, random_token,
};
use crate::store::{Change, Section, State as StoreState, Token, TokenKind};
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

pub(super) async fn token<S: Section>(
    State(oauth): State<OAuth<S>>,
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

async fn grant<S: Section>(oauth: OAuth<S>, is_form: bool, body: Bytes) -> Response {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Adds an access and a refresh token to the family and returns the raw values.
fn issue<S>(
    state: &mut StoreState<S>,
    now: Timestamp,
    client_id: &str,
    family: &str,
    scope: &str,
    resource: &str,
) -> TokenResponse {
    let (access, refresh) = (random_token(32), random_token(32));
    let record = |kind, expires_at| Token {
        kind,
        client_id: client_id.to_string(),
        family: family.to_string(),
        scope: scope.to_string(),
        resource: resource.to_string(),
        expires_at,
        rotated: false,
        extra: Default::default(),
    };

    state.tokens.insert(
        hash_token(&access),
        record(TokenKind::Access, now + ACCESS_TTL),
    );
    state.tokens.insert(
        hash_token(&refresh),
        record(TokenKind::Refresh, now + REFRESH_TTL),
    );

    TokenResponse {
        access_token: access,
        refresh_token: refresh,
        scope: scope.to_string(),
    }
}

impl<S: Section> OAuth<S> {
    /// Exchanges an authorization code. It runs as detached work under one lock held from the
    /// code lookup through the store commit that issues the tokens, so a concurrent
    /// replay waits, then finds the family in `state.json` and revokes it.
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

        let client_id = grant.client_id;
        let outcome = self
            .inner
            .store
            .update(move |state| {
                let Some(client) = state.clients.get_mut(&client_id) else {
                    return Change::Unchanged(Err(OAuthError::invalid_grant()));
                };

                client.last_used_at = Some(now);

                let response = issue(
                    state,
                    now,
                    &client_id,
                    &code_hash,
                    &record.scope,
                    &record.resource,
                );

                prune_tokens(state, now);

                Change::Write(Ok(response))
            })
            .await;

        outcome.unwrap_or_else(|_| Err(OAuthError::internal()))
    }

    async fn revoke_family(&self, family: String) -> Result<(), crate::store::StoreError> {
        let now = self.now();

        self.inner
            .store
            .update(move |state| {
                let removed = delete_family(state, &family);
                let pruned = prune_tokens(state, now);

                if removed || pruned {
                    Change::Write(())
                } else {
                    Change::Unchanged(())
                }
            })
            .await
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

        let hash = hash_token(&refresh_token);
        let now = self.now();
        let expected_resource = self.inner.resource.clone();
        let outcome = self
            .inner
            .store
            .update(move |state| {
                let (record_kind, rotated, family, record_client, expires_at, record_resource) =
                    match state.tokens.get(&hash) {
                        Some(record) => (
                            Some(record.kind),
                            record.rotated,
                            record.family.clone(),
                            record.client_id.clone(),
                            record.expires_at,
                            record.resource.clone(),
                        ),
                        None => (
                            None,
                            false,
                            String::new(),
                            String::new(),
                            now,
                            String::new(),
                        ),
                    };

                if record_kind != Some(TokenKind::Refresh) {
                    let pruned = prune_tokens(state, now);

                    return changed_if(pruned, Err(OAuthError::invalid_grant()));
                }

                if rotated {
                    delete_family(state, &family);
                    prune_tokens(state, now);

                    return Change::Write(Err(OAuthError::invalid_grant()));
                }

                if record_client != client_id
                    || !state.clients.contains_key(&client_id)
                    || now >= expires_at
                    || !is_for_resource(&record_resource, &expected_resource)
                {
                    let pruned = prune_tokens(state, now);

                    return changed_if(pruned, Err(OAuthError::invalid_grant()));
                }

                let scope = match state.tokens.get_mut(&hash) {
                    Some(record) => {
                        record.rotated = true;

                        record.scope.clone()
                    }
                    None => String::new(),
                };

                if let Some(client) = state.clients.get_mut(&client_id) {
                    client.last_used_at = Some(now);
                }

                let response = issue(state, now, &client_id, &family, &scope, &expected_resource);

                prune_tokens(state, now);

                Change::Write(Ok(response))
            })
            .await;

        outcome.unwrap_or_else(|_| Err(OAuthError::internal()))
    }
}

fn changed_if<T>(changed: bool, value: T) -> Change<T> {
    if changed {
        Change::Write(value)
    } else {
        Change::Unchanged(value)
    }
}

pub(super) async fn revoke<S: Section>(
    State(oauth): State<OAuth<S>>,
    permit: ConnPermit,
    body: Bytes,
) -> Response {
    let work = oauth.inner.work.clone();

    match work.run_detached(permit, revoke_token(oauth, body)).await {
        Ok(response) => response,
        Err(_) => OAuthError::shutting_down().into_response(),
    }
}

async fn revoke_token<S: Section>(oauth: OAuth<S>, body: Bytes) -> Response {
    let form = parse_pairs(&body);
    let hash = hash_token(form.get("token").map_or("", String::as_str));
    let now = oauth.now();
    let saved = oauth
        .inner
        .store
        .update(move |state| {
            let removed = match state
                .tokens
                .get(&hash)
                .map(|record| (record.kind, record.family.clone()))
            {
                None => false,
                Some((TokenKind::Refresh, family)) => delete_family(state, &family),
                Some((TokenKind::Access, _)) => state.tokens.remove(&hash).is_some(),
            };
            let pruned = prune_tokens(state, now);

            changed_if(removed || pruned, ())
        })
        .await;

    if saved.is_err() {
        return OAuthError::internal().into_response();
    }

    json_response(StatusCode::OK, &json!({}))
}
