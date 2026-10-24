use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use jiff::SignedDuration;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::register::{parse_loopback, redirect_matches};
use super::{
    CODE_TTL, CSRF_TTL, CodeRecord, CsrfRecord, LOCKOUT_FAILS, LOCKOUT_WINDOW, OAuth,
    OFFLINE_ACCESS, hash_token, insert_bounded, parse_pairs, random_token,
};
use crate::store::{Client, Section};
use crate::work::ConnPermit;

/// The parameters the consent page carries from `GET /authorize` to `POST /authorize`.
#[derive(Clone)]
pub(super) struct AuthRequest {
    response_type: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    code_challenge: String,
    method: String,
    state: String,
    scope: String,
    resource: String,
}

impl AuthRequest {
    fn from_fields(fields: &HashMap<String, String>) -> AuthRequest {
        let get = |name: &str| fields.get(name).cloned().unwrap_or_default();

        AuthRequest {
            response_type: get("response_type"),
            client_id: get("client_id"),
            redirect_uri: get("redirect_uri"),
            code_challenge: get("code_challenge"),
            method: get("code_challenge_method"),
            state: get("state"),
            scope: get("scope"),
            resource: get("resource"),
        }
    }

    fn fields(&self) -> [(&'static str, &str); 8] {
        [
            ("response_type", &self.response_type),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.method),
            ("state", &self.state),
            ("scope", &self.scope),
            ("resource", &self.resource),
        ]
    }

    /// The constant-size fingerprint a CSRF record keeps instead of the parameters.
    fn hash(&self) -> String {
        let encoded = serde_json::to_string(&self.fields()).unwrap_or_default();

        Sha256::digest(encoded.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

enum CsrfCheck {
    Valid,
    Expired,
    Altered,
}

/// What one serialized password attempt decided.
enum Attempt {
    Locked(SignedDuration),
    Wrong,
    Granted(String),
}

fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&#34;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }

    escaped
}

fn page_head(display_name: &str) -> String {
    let title = escape_html(&format!("Connect to {display_name}"));

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}}input,button{{font-size:1rem;padding:.6rem;width:100%;box-sizing:border-box;margin-top:.6rem}}.warn{{background:#fff3cd;padding:.6rem;border-radius:.3rem}}.err{{color:#b00020}}</style>
</head><body>
<h1>{title}</h1>
"#
    )
}

fn page(status: StatusCode, html: String, content_security_policy: &str) -> Response {
    let mut response = (status, html).into_response();
    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    if let Ok(policy) = HeaderValue::from_str(content_security_policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }

    response
}

const DEFAULT_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";

fn error_page(status: StatusCode, message: &str) -> Response {
    page(
        status,
        format!(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Cannot connect</title></head>
<body style="font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem">
<h1>Cannot connect</h1><p>{}</p></body></html>"#,
            escape_html(message)
        ),
        DEFAULT_POLICY,
    )
}

impl<S: Section> OAuth<S> {
    async fn find_client(&self, id: &str) -> Option<Client> {
        let id = id.to_string();

        self.inner
            .store
            .read(move |state| state.clients.get(&id).cloned())
            .await
            .ok()
            .flatten()
    }

    /// Checks the client and redirect URI. A failure never redirects.
    async fn validate_target(&self, request: &AuthRequest) -> Result<Client, &'static str> {
        let Some(client) = self.find_client(&request.client_id).await else {
            return Err(
                "This connection request names an unknown client. Start the connection again from Claude.",
            );
        };

        if request.redirect_uri.is_empty()
            || !redirect_matches(&client.redirect_uris, &request.redirect_uri)
        {
            return Err(
                "This connection request uses a redirect address the client did not register.",
            );
        }

        Ok(client)
    }

    fn redirect_with_error(
        &self,
        request: &AuthRequest,
        code: &str,
        description: &str,
    ) -> Response {
        let Ok(mut target) = Url::parse(&request.redirect_uri) else {
            return error_page(
                StatusCode::BAD_REQUEST,
                "The redirect address is not valid.",
            );
        };

        {
            let mut query = target.query_pairs_mut();

            query.append_pair("error", code);
            query.append_pair("error_description", description);

            if !request.state.is_empty() {
                query.append_pair("state", &request.state);
            }

            query.append_pair("iss", &self.inner.issuer);
        }

        redirect(StatusCode::FOUND, target.as_str())
    }

    fn issue_csrf(&self, request: &AuthRequest) -> String {
        let token = random_token(32);
        let now = self.now();
        let mut pending = self.pending();

        pending.seq += 1;

        let record = CsrfRecord {
            expires: now + CSRF_TTL,
            params_hash: request.hash(),
            seq: pending.seq,
        };

        insert_bounded(&mut pending.csrf, hash_token(&token), record, now);

        token
    }

    /// Consumes the token. "Expired" covers an unknown, expired or evicted token; "altered"
    /// means the parameters differ from the page that was shown.
    fn take_csrf(&self, token: &str, request: &AuthRequest) -> CsrfCheck {
        let now = self.now();
        let mut pending = self.pending();
        let record = pending.csrf.remove(&hash_token(token));

        pending.csrf.retain(|_, existing| now < existing.expires);

        match record {
            Some(record) if now < record.expires => {
                if record.params_hash == request.hash() {
                    CsrfCheck::Valid
                } else {
                    CsrfCheck::Altered
                }
            }
            _ => CsrfCheck::Expired,
        }
    }

    /// How long password attempts stay refused.
    fn locked_for(&self) -> Option<SignedDuration> {
        let now = self.now();
        let pending = self.pending();

        pending
            .locked_until
            .filter(|until| *until > now)
            .map(|until| until.duration_since(now))
    }

    fn record_failure(&self) {
        let now = self.now();
        let mut pending = self.pending();

        pending
            .failures
            .retain(|at| now.duration_since(*at) < LOCKOUT_WINDOW);
        pending.failures.push(now);

        if pending.failures.len() >= LOCKOUT_FAILS {
            pending.locked_until = Some(now + LOCKOUT_WINDOW);
            pending.failures.clear();
        }
    }

    /// One password attempt. It runs as detached work: under one lock, the lockout is
    /// checked first, then bcrypt runs on the blocking pool, then the failure is recorded or
    /// the code issued. So at most one check runs at a time, every completed wrong password
    /// counts even if its request was dropped, and parallel submissions cannot slip past
    /// the lockout.
    async fn attempt_password(
        self,
        hash: String,
        password: String,
        request: AuthRequest,
    ) -> Attempt {
        let _attempt = self.inner.password_lock.lock().await;

        if let Some(remaining) = self.locked_for() {
            return Attempt::Locked(remaining);
        }

        let checker = self.inner.checker.clone();
        let matches = tokio::task::spawn_blocking(move || checker(&hash, &password))
            .await
            .unwrap_or(false);

        if !matches {
            self.record_failure();

            return Attempt::Wrong;
        }

        let code = random_token(32);
        let now = self.now();
        let scope = granted_scope(self.inner.info.scope, &request.scope);
        let resource = if request.resource.is_empty() {
            self.inner.resource.clone()
        } else {
            request.resource.clone()
        };
        let mut pending = self.pending();

        pending.failures.clear();
        pending.seq += 1;

        let record = CodeRecord {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            challenge: request.code_challenge,
            scope,
            resource,
            expires: now + CODE_TTL,
            seq: pending.seq,
        };

        insert_bounded(&mut pending.codes, hash_token(&code), record, now);

        Attempt::Granted(code)
    }

    fn consent_page(
        &self,
        status: StatusCode,
        request: &AuthRequest,
        client: &Client,
        message: &str,
        show_form: bool,
    ) -> Response {
        let target = Url::parse(&request.redirect_uri).ok();
        let redirect_host = target
            .as_ref()
            .and_then(|url| {
                let host = url.host_str()?;

                Some(match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_string(),
                })
            })
            .unwrap_or_default();
        let name = if client.client_name.is_empty() {
            "An application"
        } else {
            &client.client_name
        };

        let mut html = page_head(self.inner.info.display_name);

        html.push_str(&format!(
            "<p><strong>{}</strong> wants access to your {} data.</p>\n<p>It will be sent back to <strong>{}</strong>.</p>\n",
            escape_html(name),
            escape_html(self.inner.info.display_name),
            escape_html(&redirect_host)
        ));

        if parse_loopback(&request.redirect_uri).is_some() {
            html.push_str("<p class=\"warn\">This is a loopback address (a program on the same machine as your browser). Continue only if you started this connection yourself.</p>\n");
        }

        if !message.is_empty() {
            html.push_str(&format!("<p class=\"err\">{}</p>\n", escape_html(message)));
        }

        if show_form {
            html.push_str("<form method=\"post\" action=\"/authorize\">\n");

            for (name, value) in request.fields() {
                html.push_str(&format!(
                    "<input type=\"hidden\" name=\"{name}\" value=\"{}\">\n",
                    escape_html(value)
                ));
            }

            html.push_str(&format!(
                "<input type=\"hidden\" name=\"csrf\" value=\"{}\">\n",
                escape_html(&self.issue_csrf(request))
            ));
            html.push_str("<label>Owner password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required></label>\n<button type=\"submit\">Approve</button>\n</form>\n");
        }

        html.push_str("</body></html>");

        let policy = match &target {
            Some(url) => format!("{DEFAULT_POLICY} {}://{redirect_host}", url.scheme()),
            None => DEFAULT_POLICY.to_string(),
        };

        page(status, html, &policy)
    }
}

fn redirect(status: StatusCode, location: &str) -> Response {
    let mut response = status.into_response();

    if let Ok(location) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, location);
    }

    response
}

/// Keeps the requested scopes this server knows, the service's own when none.
fn granted_scope(service_scope: &str, requested: &str) -> String {
    let mut granted: Vec<&str> = Vec::new();

    for scope in requested.split_whitespace() {
        if (scope == service_scope || scope == OFFLINE_ACCESS) && !granted.contains(&scope) {
            granted.push(scope);
        }
    }

    if granted.is_empty() {
        return service_scope.to_string();
    }

    granted.join(" ")
}

pub(super) async fn authorize_get<S: Section>(
    State(oauth): State<OAuth<S>>,
    permit: ConnPermit,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let work = oauth.inner.work.clone();

    match work.run_detached(permit, show_consent(oauth, query)).await {
        Ok(response) => response,
        Err(shutting_down) => {
            error_page(StatusCode::SERVICE_UNAVAILABLE, &shutting_down.to_string())
        }
    }
}

async fn show_consent<S: Section>(oauth: OAuth<S>, query: HashMap<String, String>) -> Response {
    let request = AuthRequest::from_fields(&query);
    let client = match oauth.validate_target(&request).await {
        Ok(client) => client,
        Err(problem) => return error_page(StatusCode::BAD_REQUEST, problem),
    };

    if request.response_type != "code" {
        return oauth.redirect_with_error(
            &request,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }

    if request.code_challenge.is_empty() || request.method != "S256" {
        return oauth.redirect_with_error(
            &request,
            "invalid_request",
            "code_challenge with code_challenge_method=S256 is required",
        );
    }

    if !request.resource.is_empty() && request.resource != oauth.inner.resource {
        return oauth.redirect_with_error(&request, "invalid_target", "unknown resource");
    }

    oauth.consent_page(StatusCode::OK, &request, &client, "", true)
}

pub(super) async fn authorize_post<S: Section>(
    State(oauth): State<OAuth<S>>,
    permit: ConnPermit,
    body: Bytes,
) -> Response {
    let work = oauth.inner.work.clone();

    match work.run_detached(permit, approve(oauth, body)).await {
        Ok(response) => response,
        Err(shutting_down) => {
            error_page(StatusCode::SERVICE_UNAVAILABLE, &shutting_down.to_string())
        }
    }
}

async fn approve<S: Section>(oauth: OAuth<S>, body: Bytes) -> Response {
    let fields = parse_pairs(&body);
    let request = AuthRequest::from_fields(&fields);

    match oauth.take_csrf(fields.get("csrf").map_or("", String::as_str), &request) {
        CsrfCheck::Valid => {}
        CsrfCheck::Expired => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "The consent page expired. Start the connection again from Claude.",
            );
        }
        CsrfCheck::Altered => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "The form does not match the page that was shown. Start the connection again from Claude.",
            );
        }
    }

    let client = match oauth.validate_target(&request).await {
        Ok(client) => client,
        Err(problem) => return error_page(StatusCode::BAD_REQUEST, problem),
    };
    let hash = oauth
        .inner
        .store
        .read(|state| state.owner.password_hash.clone())
        .await
        .unwrap_or_default();

    if hash.is_empty() {
        return oauth.consent_page(
            StatusCode::OK,
            &request,
            &client,
            &format!(
                "Owner password not set. Run {} set-password on the server.",
                oauth.inner.info.command
            ),
            false,
        );
    }

    let password = fields.get("password").cloned().unwrap_or_default();
    let attempt = oauth
        .clone()
        .attempt_password(hash, password, request.clone())
        .await;

    match attempt {
        Attempt::Locked(remaining) => {
            let minutes = remaining.as_secs() / 60 + 1;

            oauth.consent_page(
                StatusCode::TOO_MANY_REQUESTS,
                &request,
                &client,
                &format!("Too many wrong passwords. Try again in {minutes} minutes."),
                true,
            )
        }
        Attempt::Wrong => {
            oauth.consent_page(StatusCode::OK, &request, &client, "Wrong password", true)
        }
        Attempt::Granted(code) => grant_redirect(&oauth, &request, &code),
    }
}

fn grant_redirect<S: Section>(oauth: &OAuth<S>, request: &AuthRequest, code: &str) -> Response {
    let Ok(mut target) = Url::parse(&request.redirect_uri) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "The redirect address is not valid.",
        );
    };

    {
        let mut query = target.query_pairs_mut();

        query.append_pair("code", code);

        if !request.state.is_empty() {
            query.append_pair("state", &request.state);
        }

        query.append_pair("iss", &oauth.inner.issuer);
    }

    let mut response = redirect(StatusCode::SEE_OTHER, target.as_str());

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}
