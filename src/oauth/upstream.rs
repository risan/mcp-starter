//! Signing people in through an upstream service instead of the owner password.
//!
//! `GET /authorize` validates the request as always, keeps it in memory under a random
//! pending id, binds it to the browser with a cookie and sends the browser to the service's
//! sign-in. The service's callback hands the pending id back to [`OAuth::take_pending`], finds
//! out who the person is and ends with [`OAuth::deny`] or [`OAuth::complete`]. The consent page
//! is shown once per person and client.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jiff::Timestamp;

use super::authorize::{
    AuthRequest, error_page, escape_html, grant_redirect, page, page_head, redirect,
    redirect_target, request_warning, security_policy, technical_details,
};
use super::{
    CSRF_TTL, ConsentRecord, GrantStore, OAuth, PasswordChecker, SignInRecord, Subject,
    constant_time_eq, hash_token, insert_bounded, parse_pairs, random_token,
};
use crate::store::Client;

const COOKIE_NAME: &str = "__Host-mcp-sign-in";
const MAX_REQUEST_BYTES: usize = 4 << 10;
const MAX_SUBJECT_ID_BYTES: usize = 256;
const MAX_SUBJECT_NAME_CHARS: usize = 256;

/// Where a service sends people to sign in.
pub trait Upstream: Send + Sync {
    /// The address of the upstream's sign-in page for the pending request `pending`. The
    /// upstream must bring `pending` back to the service's callback, usually as its `state`.
    fn sign_in_url(&self, pending: &str) -> String;
}

/// How the authorization server learns who a person is.
pub enum SignIn {
    /// The owner types the password on the consent page. The server has one subject,
    /// [`Subject::owner`].
    Password(PasswordChecker),
    /// The service signs people in elsewhere and tells the server who they are, through
    /// [`OAuth::take_pending`] and [`OAuth::complete`].
    Upstream(Arc<dyn Upstream>),
}

/// A sign-in that came back from the upstream, taken by [`OAuth::take_pending`]. It is spent:
/// end it with [`OAuth::deny`] or [`OAuth::complete`].
pub struct Pending {
    request: AuthRequest,
    browser: String,
    start_seq: u64,
    started_at: Timestamp,
}

impl Pending {
    /// When the person's browser reached `GET /authorize`.
    pub fn started_at(&self) -> Timestamp {
        self.started_at
    }
}

/// Why a pending sign-in could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingError {
    /// There is no such sign-in: it never existed, expired, was evicted or was used already.
    Unknown,
    /// The browser is not the one that started the sign-in. The sign-in stays usable.
    Browser,
}

impl fmt::Display for PendingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PendingError::Unknown => f.write_str("unknown or expired sign-in"),
            PendingError::Browser => f.write_str("the sign-in was started in another browser"),
        }
    }
}

impl std::error::Error for PendingError {}

/// The browser-binding cookie of the request, when it carries a well-formed one.
fn browser_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(text) = value.to_str() else {
            continue;
        };

        for pair in text.split(';') {
            let Some((name, cookie)) = pair.trim().split_once('=') else {
                continue;
            };

            if name == COOKIE_NAME && is_cookie_value(cookie) {
                return Some(cookie.to_string());
            }
        }
    }

    None
}

fn is_cookie_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn same_browser(cookie: Option<&str>, stored_hash: &str) -> bool {
    cookie.is_some_and(|cookie| {
        constant_time_eq(hash_token(cookie).as_bytes(), stored_hash.as_bytes())
    })
}

/// A subject the server can keep: an id of 1 to 256 bytes and a name cut to 256 characters.
fn checked_subject(subject: Subject) -> Option<Subject> {
    if subject.id.is_empty() || subject.id.len() > MAX_SUBJECT_ID_BYTES {
        return None;
    }

    Some(Subject {
        id: subject.id,
        name: subject.name.chars().take(MAX_SUBJECT_NAME_CHARS).collect(),
    })
}

impl<St: GrantStore> OAuth<St> {
    fn upstream(&self) -> Option<&Arc<dyn Upstream>> {
        match &self.inner.sign_in {
            SignIn::Upstream(upstream) => Some(upstream),
            SignIn::Password(_) => None,
        }
    }

    /// Whether people sign in upstream rather than with the owner password.
    pub(super) fn is_upstream(&self) -> bool {
        self.upstream().is_some()
    }

    /// `GET /authorize` in upstream mode: validates, keeps the request and sends the browser
    /// to the upstream.
    pub(super) async fn begin_sign_in(
        &self,
        headers: &HeaderMap,
        query: &HashMap<String, String>,
    ) -> Response {
        let Some(upstream) = self.upstream() else {
            return error_page(StatusCode::BAD_REQUEST, "Sign-in is not available.");
        };
        let request = AuthRequest::from_fields(query);

        if let Err(response) = self.check_request(&request).await {
            return *response;
        }

        if request.size() > MAX_REQUEST_BYTES {
            return error_page(
                StatusCode::BAD_REQUEST,
                "This connection request is too large. Start the connection again from Claude.",
            );
        }

        let cookie = browser_cookie(headers).unwrap_or_else(|| random_token(32));
        let id = random_token(32);
        let now = self.now();

        {
            let mut pending = self.pending();

            pending.seq += 1;

            let record = SignInRecord {
                request,
                browser: hash_token(&cookie),
                start_seq: pending.seq,
                started_at: now,
                expires: now + CSRF_TTL,
                seq: pending.seq,
            };

            insert_bounded(&mut pending.sign_ins, hash_token(&id), record, now);
        }

        let mut response = redirect(StatusCode::FOUND, &upstream.sign_in_url(&id));
        let headers = response.headers_mut();

        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

        if let Ok(value) = HeaderValue::from_str(&format!(
            "{COOKIE_NAME}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax"
        )) {
            headers.insert(header::SET_COOKIE, value);
        }

        response
    }

    /// Takes the pending sign-in `id` for the service's callback, before it asks the upstream
    /// anything. The request must come from the browser that started the sign-in. A browser
    /// mismatch leaves the sign-in usable, so a stranger cannot spend it.
    pub fn take_pending(&self, headers: &HeaderMap, id: &str) -> Result<Pending, PendingError> {
        let now = self.now();
        let key = hash_token(id);
        let cookie = browser_cookie(headers);
        let mut pending = self.pending();

        pending
            .sign_ins
            .retain(|_, existing| now < existing.expires);

        match pending.sign_ins.get(&key) {
            None => return Err(PendingError::Unknown),
            Some(record) if !same_browser(cookie.as_deref(), &record.browser) => {
                return Err(PendingError::Browser);
            }
            Some(_) => {}
        }

        let record = pending.sign_ins.remove(&key).ok_or(PendingError::Unknown)?;

        Ok(Pending {
            request: record.request,
            browser: record.browser,
            start_seq: record.start_seq,
            started_at: record.started_at,
        })
    }

    /// Ends a sign-in the upstream refused: the client gets `access_denied` with its `state`.
    pub fn deny(&self, pending: Pending) -> Response {
        self.redirect_with_error(
            StatusCode::FOUND,
            &pending.request,
            "access_denied",
            "the sign-in was refused",
        )
    }

    /// Ends a sign-in the upstream accepted for `subject`. When the person approved this
    /// client before, the browser goes back to the client with a code; otherwise it gets the
    /// consent page.
    pub async fn complete(&self, pending: Pending, subject: Subject) -> Response {
        let Some(subject) = checked_subject(subject) else {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The sign-in could not be completed.",
            );
        };
        let client = match self.validate_target(&pending.request).await {
            Ok(client) => client,
            Err(problem) => return error_page(StatusCode::BAD_REQUEST, problem),
        };

        match self
            .inner
            .store
            .has_consent(&subject.id, &client.client_id)
            .await
        {
            Ok(true) => {
                let code =
                    self.issue_code(pending.request.clone(), subject, None, pending.start_seq);

                grant_redirect(self, &pending.request, &code)
            }
            Ok(false) => self.ask_consent(pending, &client, subject),
            Err(_) => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The sign-in could not be completed.",
            ),
        }
    }

    fn ask_consent(&self, pending: Pending, client: &Client, subject: Subject) -> Response {
        let ticket = random_token(32);
        let now = self.now();
        let (target, host) = redirect_target(&pending.request.redirect_uri);
        let name = if client.client_name.is_empty() {
            "An application"
        } else {
            &client.client_name
        };
        let mut html = page_head(self.inner.info.display_name);

        html.push_str(&format!(
            "<p>Allow <strong>{}</strong> ({}) to use {} as <strong>{}</strong>?</p>\n{}\n{}",
            escape_html(name),
            escape_html(&host),
            escape_html(self.inner.info.display_name),
            escape_html(&subject.name),
            request_warning(&pending.request.redirect_uri),
            technical_details(&pending.request.redirect_uri, &client.client_id),
        ));
        html.push_str(&format!(
            "<form method=\"post\" action=\"/authorize\">\n<input type=\"hidden\" name=\"ticket\" value=\"{}\">\n<button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button>\n<button type=\"submit\" name=\"decision\" value=\"cancel\">Cancel</button>\n</form>\n</body></html>",
            escape_html(&ticket)
        ));

        {
            let mut state = self.pending();

            state.seq += 1;

            let record = ConsentRecord {
                request: pending.request,
                subject,
                browser: pending.browser,
                start_seq: pending.start_seq,
                expires: now + CSRF_TTL,
                seq: state.seq,
            };

            insert_bounded(&mut state.consents, hash_token(&ticket), record, now);
        }

        page(
            StatusCode::OK,
            html,
            &security_policy(target.as_ref(), &host),
        )
    }

    /// Takes the consent ticket for the browser that holds `headers`' cookie. A ticket is used
    /// once; a browser mismatch leaves it usable.
    fn take_ticket(
        &self,
        headers: &HeaderMap,
        ticket: &str,
    ) -> Result<ConsentRecord, PendingError> {
        let now = self.now();
        let key = hash_token(ticket);
        let cookie = browser_cookie(headers);
        let mut pending = self.pending();

        pending
            .consents
            .retain(|_, existing| now < existing.expires);

        match pending.consents.get(&key) {
            None => return Err(PendingError::Unknown),
            Some(record) if !same_browser(cookie.as_deref(), &record.browser) => {
                return Err(PendingError::Browser);
            }
            Some(_) => {}
        }

        pending.consents.remove(&key).ok_or(PendingError::Unknown)
    }

    /// `POST /authorize` in upstream mode: the answer to the consent page.
    pub(super) async fn decide_consent(&self, headers: &HeaderMap, body: &Bytes) -> Response {
        let fields = parse_pairs(body);
        let decision = fields.get("decision").map_or("", String::as_str);

        if !matches!(decision, "allow" | "cancel") {
            return error_page(
                StatusCode::BAD_REQUEST,
                "The form is not complete. Start the connection again from Claude.",
            );
        }

        let record = match self
            .take_ticket(headers, fields.get("ticket").map_or("", String::as_str))
        {
            Ok(record) => record,
            Err(PendingError::Unknown) => {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "The consent page expired. Start the connection again from Claude.",
                );
            }
            Err(PendingError::Browser) => {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "This page was opened in another browser. Start the connection again from Claude.",
                );
            }
        };

        if decision == "cancel" {
            return self.redirect_with_error(
                StatusCode::SEE_OTHER,
                &record.request,
                "access_denied",
                "the person did not allow the connection",
            );
        }

        let client = match self.validate_target(&record.request).await {
            Ok(client) => client,
            Err(problem) => return error_page(StatusCode::BAD_REQUEST, problem),
        };

        if self
            .inner
            .store
            .save_consent(&record.subject.id, &client.client_id, self.now())
            .await
            .is_err()
        {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The consent could not be saved.",
            );
        }

        let code = self.issue_code(
            record.request.clone(),
            record.subject,
            None,
            record.start_seq,
        );

        grant_redirect(self, &record.request, &code)
    }
}
