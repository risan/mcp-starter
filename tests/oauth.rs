//! The OAuth authorization server alone, over real HTTP, with the
//! concurrency rules proven by gated checkers and stalled store writes.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use jiff::SignedDuration;
use mcp_starter::oauth::{revoke_all, set_password};
use mcp_starter::store::{Change, Hooks, StoreOptions};
use mcp_starter::test_support::oauth_flow::{
    CLAUDE_CALLBACK, ISSUER, OAuthRig, OWNER_PASSWORD, VERIFIER, authorize_params, pairs, pkce,
    set_param,
};
use mcp_starter::test_support::wait_until;
use serde_json::json;
use support::{INFO, TestState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

#[tokio::test]
async fn metadata() {
    let rig = support::rig().await;
    let reply = rig
        .client
        .get("/.well-known/oauth-authorization-server")
        .await;
    let meta = reply.json();

    assert_eq!(meta["issuer"], ISSUER);
    assert_eq!(
        meta["authorization_endpoint"],
        format!("{ISSUER}/authorize")
    );
    assert_eq!(meta["token_endpoint"], format!("{ISSUER}/token"));
    assert_eq!(meta["registration_endpoint"], format!("{ISSUER}/register"));
    assert_eq!(meta["revocation_endpoint"], format!("{ISSUER}/revoke"));
    assert_eq!(meta["response_types_supported"], json!(["code"]));
    assert_eq!(
        meta["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(
        meta["scopes_supported"],
        json!(["example", "offline_access"])
    );
    assert!(
        meta.get("client_id_metadata_document_supported").is_none(),
        "CIMD must not be advertised"
    );
}

#[tokio::test]
async fn register() {
    let rig = support::rig().await;

    for redirect in [
        CLAUDE_CALLBACK,
        "http://127.0.0.1:5555/callback",
        "http://localhost:6000/callback",
    ] {
        let body = json!({"client_name": "Claude Code", "redirect_uris": [redirect]});
        let reply = rig.client.post_json("/register", &body).await;
        let registered = reply.json();

        assert_eq!(reply.status, 201, "{redirect}");
        assert!(!registered["client_id"].as_str().unwrap().is_empty());
        assert!(registered["client_id_issued_at"].is_number());
        assert_eq!(registered["token_endpoint_auth_method"], "none");
        assert_eq!(registered["client_name"], "Claude Code");
        assert_eq!(registered["redirect_uris"], json!([redirect]));
        assert_eq!(
            registered["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(registered["response_types"], json!(["code"]));
        assert_eq!(reply.header("cache-control"), "no-store");
    }

    for bad in [
        "https://evil.example/cb",
        "http://claude.ai/api/mcp/auth_callback",
        "http://evil.example:5555/cb",
        "https://claude.ai/api/mcp/auth_callback/extra",
        "http://127.0.0.1.evil.example:80/cb",
        "http://localhost@evil.example/cb",
        "javascript:alert(1)",
    ] {
        let reply = rig
            .client
            .post_json("/register", &json!({"redirect_uris": [bad]}))
            .await;

        assert_eq!(reply.status, 400, "{bad}");
        assert_eq!(reply.error_code(), "invalid_redirect_uri", "{bad}");
    }

    let mixed = json!({"redirect_uris": [CLAUDE_CALLBACK, "https://evil.example/cb"]});

    assert_eq!(
        rig.client.post_json("/register", &mixed).await.status,
        400,
        "every redirect URI is checked"
    );
    assert_eq!(
        rig.client
            .post_json("/register", &json!({"redirect_uris": []}))
            .await
            .status,
        400
    );

    let confidential = json!({"redirect_uris": [CLAUDE_CALLBACK], "token_endpoint_auth_method": "client_secret_basic"});

    assert_eq!(
        rig.client
            .post_json("/register", &confidential)
            .await
            .status,
        400
    );
    assert_eq!(
        rig.client
            .post("/register", "application/json", "not json".to_string())
            .await
            .status,
        400
    );
}

#[tokio::test]
async fn register_evicts_lru() {
    let rig = support::rig().await;
    let mut ids = Vec::new();

    for _ in 0..50 {
        ids.push(rig.client.register(&[CLAUDE_CALLBACK]).await);
        rig.clock.advance(SignedDuration::from_secs(1));
    }

    rig.client.register(&[CLAUDE_CALLBACK]).await;

    let clients = rig.state().await.clients;

    assert_eq!(clients.len(), 50);
    assert!(
        !clients.contains_key(&ids[0]),
        "with 50 never-used clients the oldest registration goes"
    );

    // mark every remaining client as used, at increasing times; then the oldest grant goes
    let base = rig.now();
    let remaining: Vec<String> = ids[1..].to_vec();

    rig.store
        .update(move |state| {
            for (index, id) in remaining.iter().enumerate() {
                state.clients.get_mut(id).unwrap().last_used_at =
                    Some(base + SignedDuration::from_mins(index as i64));
            }

            for client in state.clients.values_mut() {
                if client.last_used_at.is_none() {
                    client.last_used_at = Some(base + SignedDuration::from_mins(1000));
                }
            }

            Change::Write(())
        })
        .await
        .unwrap();

    rig.client.register(&[CLAUDE_CALLBACK]).await;

    let clients = rig.state().await.clients;

    assert!(
        !clients.contains_key(&ids[1]),
        "with all 50 used, the oldest last_used_at goes"
    );
    assert_eq!(clients.len(), 50);
}

#[tokio::test]
async fn register_churn_keeps_authorized_client() {
    let rig = support::rig().await;
    let (owner_client, issued, _) = rig.client.full_flow().await;

    for _ in 0..120 {
        rig.client.register(&[CLAUDE_CALLBACK]).await;
        rig.clock.advance(SignedDuration::from_secs(1));
    }

    assert!(
        rig.state().await.clients.contains_key(&owner_client),
        "anonymous registrations evicted the authorized client"
    );
    assert!(rig.valid(&issued.access_token).await);
}

#[tokio::test]
async fn authorize_rejects_unknown_client_without_redirect() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut no_redirect = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    no_redirect.retain(|(key, _)| key != "redirect_uri");

    for (name, params) in [
        (
            "unknown client",
            authorize_params(&INFO, "nope", CLAUDE_CALLBACK),
        ),
        (
            "unregistered uri",
            authorize_params(&INFO, &client_id, "https://evil.example/cb"),
        ),
        ("missing redirect", no_redirect),
        (
            "loopback wrong host",
            authorize_params(&INFO, &client_id, "http://127.0.0.1:1234/callback"),
        ),
    ] {
        let (_, reply) = rig.client.consent(&params).await;

        assert_eq!(reply.status, 400, "{name}");
        assert_eq!(reply.header("location"), "", "{name}");
        assert!(reply.header("content-type").contains("text/html"), "{name}");
    }
}

#[tokio::test]
async fn authorize_redirects_other_errors() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;

    let mut token_type = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    set_param(&mut token_type, "response_type", "token");
    let mut no_challenge = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    no_challenge.retain(|(key, _)| key != "code_challenge");
    let mut plain = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    set_param(&mut plain, "code_challenge_method", "plain");

    for (expected, params) in [
        ("unsupported_response_type", token_type),
        ("invalid_request", no_challenge),
        ("invalid_request", plain),
    ] {
        let (_, reply) = rig.client.consent(&params).await;

        assert_eq!(reply.status, 302, "{expected}");
        assert_eq!(reply.location_param("error").as_deref(), Some(expected));
        assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
        assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
    }
}

#[tokio::test]
async fn authorize_resource_mismatch() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut params = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    set_param(&mut params, "resource", "https://other.example/mcp");

    let (_, reply) = rig.client.consent(&params).await;

    assert_eq!(
        reply.location_param("error").as_deref(),
        Some("invalid_target")
    );
}

#[tokio::test]
async fn authorize_consent_page() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;

    let (form, reply) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;

    assert!(form.is_some());
    assert_eq!(reply.status, 200);
    assert!(reply.body.contains("Claude") && reply.body.contains("claude.ai"));
    assert!(!reply.body.contains("loopback"));

    let csp = reply.header("content-security-policy");

    assert_eq!(reply.header("x-frame-options"), "DENY");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("style-src 'unsafe-inline'"), "{csp}");
    assert!(
        csp.contains("form-action 'self' https://claude.ai"),
        "{csp}"
    );

    let loopback = rig
        .client
        .register(&["http://127.0.0.1:5555/callback"])
        .await;
    let (_, reply) = rig
        .client
        .consent(&authorize_params(
            &INFO,
            &loopback,
            "http://127.0.0.1:5555/callback",
        ))
        .await;

    assert!(
        reply.body.contains("127.0.0.1") && reply.body.contains("loopback"),
        "{}",
        reply.body
    );
    assert!(
        reply
            .header("content-security-policy")
            .contains("form-action 'self' http://127.0.0.1:5555"),
        "{}",
        reply.header("content-security-policy")
    );
}

#[tokio::test]
async fn consent_page_escapes_parameters() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut params = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    set_param(&mut params, "state", "\"><script>alert(1)</script>");

    let (_, reply) = rig.client.consent(&params).await;

    assert!(!reply.body.contains("<script>"), "{}", reply.body);
}

#[tokio::test]
async fn pending_authorize_bounded() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (mut first, mut last) = (None, None);

    for index in 0..150 {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
            .await;

        if index == 0 {
            first = form.clone();
        }

        last = form;
    }

    assert!(rig.oauth.pending_counts().0 <= 100);

    let reply = rig.client.approve(&first.unwrap(), OWNER_PASSWORD).await;

    assert_eq!(
        reply.status, 400,
        "the earliest token gets the expired page"
    );
    assert!(reply.body.contains("expired"));
    assert_eq!(
        rig.client
            .approve(&last.unwrap(), OWNER_PASSWORD)
            .await
            .status,
        303
    );
}

#[tokio::test]
async fn pending_expiry_pruned() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;

    rig.clock.advance(SignedDuration::from_mins(11));
    let reply = rig.client.approve(&form.unwrap(), OWNER_PASSWORD).await;

    assert_eq!(reply.status, 400);
    assert!(reply.body.contains("expired"));
    assert_eq!(
        rig.oauth.pending_counts().0,
        0,
        "the expired record must be gone"
    );
}

#[tokio::test]
async fn csrf_bound_to_parameters() {
    let rig = support::rig().await;
    let client_id = rig
        .client
        .register(&["http://127.0.0.1:5555/callback"])
        .await;
    let other_challenge = pkce("another-verifier-another-verifier-another");

    for (field, value) in [
        ("redirect_uri", "http://127.0.0.1:6666/callback"),
        ("code_challenge", other_challenge.as_str()),
        ("state", "forged"),
        ("scope", "example"),
    ] {
        let (form, _) = rig
            .client
            .consent(&authorize_params(
                &INFO,
                &client_id,
                "http://127.0.0.1:5555/callback",
            ))
            .await;
        let mut form = form.unwrap();
        set_param(&mut form, field, value);

        assert_ne!(
            rig.client.approve(&form, OWNER_PASSWORD).await.status,
            303,
            "altered {field} was accepted"
        );
    }

    assert_eq!(
        rig.probe.started(),
        0,
        "the password must not be checked for a tampered form"
    );
}

#[tokio::test]
async fn csrf_token_single_use() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;
    let form = form.unwrap();

    assert_eq!(rig.client.approve(&form, OWNER_PASSWORD).await.status, 303);
    assert_eq!(rig.client.approve(&form, OWNER_PASSWORD).await.status, 400);
}

#[tokio::test]
async fn wrong_password_no_code() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;
    let mut form = form.unwrap();

    let reply = rig.client.approve(&form, "wrong").await;

    assert_ne!(reply.status, 303);
    assert_eq!(reply.header("location"), "");
    assert!(reply.body.contains("Wrong password"));
    assert_eq!(rig.oauth.pending_counts().1, 0, "no code may be issued");

    let marker = "name=\"csrf\" value=\"";
    let start = reply
        .body
        .find(marker)
        .expect("the page after a wrong password carries a fresh CSRF token")
        + marker.len();
    let fresh = &reply.body[start..start + reply.body[start..].find('"').unwrap()];
    set_param(&mut form, "csrf", fresh);

    assert_eq!(rig.client.approve(&form, OWNER_PASSWORD).await.status, 303);
}

#[tokio::test]
async fn lockout_after_five_failures() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;

    async fn attempt(rig: &OAuthRig<TestState>, client_id: &str, password: &str) -> u16 {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, client_id, CLAUDE_CALLBACK))
            .await;

        rig.client.approve(&form.unwrap(), password).await.status
    }

    for _ in 0..5 {
        attempt(&rig, &client_id, "wrong").await;
    }

    let checks_after_failures = rig.probe.started();

    assert_ne!(
        attempt(&rig, &client_id, OWNER_PASSWORD).await,
        303,
        "refused during the lockout"
    );
    assert_eq!(
        rig.probe.started(),
        checks_after_failures,
        "not even checked during the lockout"
    );

    rig.clock.advance(SignedDuration::from_mins(14));
    assert_ne!(
        attempt(&rig, &client_id, OWNER_PASSWORD).await,
        303,
        "still locked at 14 minutes"
    );

    rig.clock.advance(SignedDuration::from_mins(2));
    assert_eq!(
        attempt(&rig, &client_id, OWNER_PASSWORD).await,
        303,
        "after the lockout the right password works"
    );
}

#[tokio::test]
async fn failures_older_than_window_do_not_count() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;

    for _ in 0..4 {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
            .await;
        rig.client.approve(&form.unwrap(), "wrong").await;
    }

    rig.clock.advance(SignedDuration::from_mins(16));
    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;
    rig.client.approve(&form.unwrap(), "wrong").await;

    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;

    assert_eq!(
        rig.client
            .approve(&form.unwrap(), OWNER_PASSWORD)
            .await
            .status,
        303
    );
}

#[tokio::test]
async fn no_password_set() {
    let rig = support::rig().await;

    rig.store
        .update(|state| {
            state.owner.password_hash.clear();

            Change::Write(())
        })
        .await
        .unwrap();

    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (form, _) = rig
        .client
        .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
        .await;
    let reply = rig.client.approve(&form.unwrap(), "anything").await;

    assert_ne!(reply.status, 303);
    assert!(
        reply
            .body
            .contains("Owner password not set. Run example-mcp set-password on the server.")
    );
}

#[tokio::test]
async fn code_exchange_pkce() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;

    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;
    let (reply, issued) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let issued = issued.unwrap();

    assert_eq!(reply.status, 200);
    assert_eq!(issued.raw["token_type"], "Bearer");
    assert_eq!(issued.raw["expires_in"], 86400);
    assert_eq!(issued.raw["scope"], "example offline_access");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("pragma"), "no-cache");
    assert!(
        issued.access_token.len() >= 43 && issued.refresh_token.len() >= 43,
        "at least 32 random bytes"
    );

    let wrong = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;
    let (reply, _) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &wrong, &"w".repeat(43))
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant"),
        "wrong verifier"
    );

    let mismatch = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;
    let (reply, _) = rig
        .client
        .exchange(
            &client_id,
            "https://claude.ai/api/mcp/other",
            &mismatch,
            VERIFIER,
        )
        .await;

    assert_eq!(reply.error_code(), "invalid_grant", "redirect mismatch");

    let other_client = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let stolen = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;
    let (reply, _) = rig
        .client
        .exchange(&other_client, CLAUDE_CALLBACK, &stolen, VERIFIER)
        .await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "a code from another client"
    );

    let loopback = rig
        .client
        .register(&["http://127.0.0.1:5555/callback"])
        .await;
    let other_port = "http://127.0.0.1:7777/callback";
    let code = rig.client.grant(&loopback, other_port).await;
    let (reply, issued) = rig
        .client
        .exchange(&loopback, other_port, &code, VERIFIER)
        .await;

    assert_eq!(reply.status, 200, "loopback with another port");
    assert!(issued.is_some());
}

#[tokio::test]
async fn code_exchange_resource() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;

    let reply = rig
        .client
        .post_form(
            "/token",
            &pairs(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", CLAUDE_CALLBACK),
                ("code_verifier", VERIFIER),
                ("resource", "https://other.example/mcp"),
            ]),
        )
        .await;

    assert_eq!(reply.error_code(), "invalid_target");
}

#[tokio::test]
async fn code_reuse_revokes() {
    let rig = support::rig().await;
    let (client_id, issued, code) = rig.client.full_flow().await;

    let (reply, _) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(
        !rig.valid(&issued.access_token).await,
        "the first access token must stop working"
    );

    let (reply, _) = rig.client.refresh(&client_id, &issued.refresh_token).await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "the first refresh token must stop working"
    );
}

async fn replay_should_revoke(
    rig: &OAuthRig<TestState>,
    client_id: &str,
    issued: &mcp_starter::test_support::oauth_flow::Tokens,
    code: &str,
) {
    let (_, rotated) = rig.client.refresh(client_id, &issued.refresh_token).await;
    let rotated = rotated.expect("rotation failed");

    let (reply, _) = rig
        .client
        .exchange(client_id, CLAUDE_CALLBACK, code, VERIFIER)
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant"),
        "replay"
    );
    assert!(!rig.valid(&issued.access_token).await);
    assert!(
        !rig.valid(&rotated.access_token).await,
        "descendant access tokens must stop working"
    );

    let (reply, _) = rig.client.refresh(client_id, &rotated.refresh_token).await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "descendant refresh token must stop working"
    );
}

#[tokio::test]
async fn code_replay_after_expiry_revokes() {
    let rig = support::rig().await;
    let (client_id, issued, code) = rig.client.full_flow().await;

    rig.clock.advance(SignedDuration::from_mins(6));

    replay_should_revoke(&rig, &client_id, &issued, &code).await;
}

#[tokio::test]
async fn code_replay_after_eviction_revokes() {
    let rig = support::rig().await;
    let (client_id, issued, code) = rig.client.full_flow().await;
    let other = rig.client.register(&[CLAUDE_CALLBACK]).await;

    for _ in 0..101 {
        rig.client.grant(&other, CLAUDE_CALLBACK).await;
    }

    assert!(rig.oauth.pending_counts().1 <= 100);

    replay_should_revoke(&rig, &client_id, &issued, &code).await;
}

#[tokio::test]
async fn code_replay_after_restart_revokes() {
    let mut rig = support::rig().await;
    let (client_id, issued, code) = rig.client.full_flow().await;

    rig.restart().await;

    replay_should_revoke(&rig, &client_id, &issued, &code).await;
}

#[tokio::test]
async fn unknown_code_invalid_grant() {
    let rig = support::rig().await;
    let (client_id, issued, _) = rig.client.full_flow().await;

    let (reply, _) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, "never-issued", VERIFIER)
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(
        rig.valid(&issued.access_token).await,
        "an unknown code must not revoke unrelated tokens"
    );
}

#[tokio::test]
async fn refresh_rotation() {
    let rig = support::rig().await;
    let (client_id, first, _) = rig.client.full_flow().await;

    let (reply, second) = rig.client.refresh(&client_id, &first.refresh_token).await;
    let second = second.unwrap();

    assert_eq!(reply.status, 200);
    assert_ne!(second.refresh_token, first.refresh_token);
    assert_ne!(second.access_token, first.access_token);
    assert!(rig.valid(&second.access_token).await);

    let (reply, _) = rig.client.refresh(&client_id, &first.refresh_token).await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(
        !rig.valid(&second.access_token).await,
        "replaying a rotated token revokes the new tokens"
    );

    let (reply, _) = rig.client.refresh(&client_id, &second.refresh_token).await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "the new refresh token is revoked too"
    );
}

async fn set_token_resource(rig: &OAuthRig<TestState>, resource: &str) {
    let resource = resource.to_string();

    rig.store
        .update(move |state| {
            for token in state.tokens.values_mut() {
                token.resource = resource.clone();
            }

            Change::Write(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn tokens_for_another_resource_rejected() {
    let rig = support::rig().await;
    let (client_id, issued, _) = rig.client.full_flow().await;

    set_token_resource(&rig, "https://old.example.com/mcp").await;

    assert!(
        !rig.valid(&issued.access_token).await,
        "an access token issued for another resource"
    );

    let (reply, _) = rig.client.refresh(&client_id, &issued.refresh_token).await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant"),
        "a refresh token issued for another resource"
    );
}

#[tokio::test]
async fn legacy_tokens_without_resource_accepted() {
    let rig = support::rig().await;
    let (client_id, issued, _) = rig.client.full_flow().await;

    set_token_resource(&rig, "").await;

    assert!(rig.valid(&issued.access_token).await);

    let (reply, refreshed) = rig.client.refresh(&client_id, &issued.refresh_token).await;
    let refreshed = refreshed.unwrap_or_else(|| panic!("refresh: {}", reply.body));

    assert!(rig.valid(&refreshed.access_token).await);

    let state = rig.state().await;
    let fresh: Vec<_> = state
        .tokens
        .values()
        .filter(|token| !token.rotated)
        .collect();

    assert!(
        fresh
            .iter()
            .filter(|token| token.expires_at > rig.now())
            .any(|token| token.resource == format!("{ISSUER}/mcp")),
        "the refreshed tokens are bound to this server's resource"
    );
}

#[tokio::test]
async fn refresh_wrong_client() {
    let rig = support::rig().await;
    let (_, issued, _) = rig.client.full_flow().await;
    let other = rig.client.register(&[CLAUDE_CALLBACK]).await;

    let (reply, _) = rig.client.refresh(&other, &issued.refresh_token).await;

    assert_eq!(reply.error_code(), "invalid_grant");
}

#[tokio::test]
async fn rotated_refresh_replay_after_own_expiry() {
    let mut rig = support::rig().await;
    let (client_id, first, _) = rig.client.full_flow().await;

    rig.clock.advance(SignedDuration::from_hours(59 * 24));
    let (reply, second) = rig.client.refresh(&client_id, &first.refresh_token).await;
    let second = second.unwrap();

    assert_eq!(reply.status, 200, "rotation on day 59");

    rig.clock.advance(SignedDuration::from_hours(2 * 24));
    rig.client.register(&[CLAUDE_CALLBACK]).await; // runs an oauth update, and with it the pruning
    rig.restart().await;

    let (reply, _) = rig.client.refresh(&client_id, &first.refresh_token).await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant"),
        "replay on day 61"
    );

    let (reply, _) = rig.client.refresh(&client_id, &second.refresh_token).await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "the day-59 descendants stop working after the replay"
    );
}

#[tokio::test]
async fn dead_family_pruned() {
    let rig = support::rig().await;
    let (client_id, first, _) = rig.client.full_flow().await;

    rig.client.refresh(&client_id, &first.refresh_token).await;

    assert_eq!(
        rig.state().await.tokens.len(),
        4,
        "2 access, 1 live refresh, 1 rotated"
    );

    rig.clock.advance(SignedDuration::from_hours(61 * 24));
    rig.client.register(&[CLAUDE_CALLBACK]).await;

    assert_eq!(
        rig.state().await.tokens.len(),
        0,
        "a dead family leaves no records"
    );
}

#[tokio::test]
async fn expired_access_token_rejected() {
    let rig = support::rig().await;
    let (_, issued, _) = rig.client.full_flow().await;

    rig.clock.advance(SignedDuration::from_hours(23));
    assert!(rig.valid(&issued.access_token).await, "valid for 24 hours");

    rig.clock.advance(SignedDuration::from_hours(2));
    assert!(
        !rig.valid(&issued.access_token).await,
        "expired after 24 hours"
    );
}

#[tokio::test]
async fn token_rejects_json() {
    let rig = support::rig().await;
    let body = json!({"grant_type": "refresh_token", "refresh_token": "x"});

    let reply = rig.client.post_json("/token", &body).await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_request")
    );
}

#[tokio::test]
async fn token_unsupported_grant_and_unknown_client() {
    let rig = support::rig().await;

    let reply = rig
        .client
        .post_form("/token", &pairs(&[("grant_type", "password")]))
        .await;

    assert_eq!(reply.error_code(), "unsupported_grant_type");

    let reply = rig
        .client
        .post_form(
            "/token",
            &pairs(&[
                ("grant_type", "authorization_code"),
                ("client_id", "nope"),
                ("code", "x"),
            ]),
        )
        .await;

    assert!(
        ["invalid_client", "invalid_grant"].contains(&reply.error_code().as_str()),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn revoke() {
    let rig = support::rig().await;
    let (client_id, issued, _) = rig.client.full_flow().await;

    let reply = rig
        .client
        .post_form("/revoke", &pairs(&[("token", &issued.access_token)]))
        .await;

    assert_eq!(reply.status, 200);
    assert!(!rig.valid(&issued.access_token).await);

    let reply = rig
        .client
        .post_form("/revoke", &pairs(&[("token", &issued.refresh_token)]))
        .await;

    assert_eq!(reply.status, 200);

    let (reply, _) = rig.client.refresh(&client_id, &issued.refresh_token).await;

    assert_eq!(
        reply.error_code(),
        "invalid_grant",
        "a revoked refresh token must not work"
    );
    assert_eq!(
        rig.client
            .post_form("/revoke", &pairs(&[("token", "never-issued")]))
            .await
            .status,
        200,
        "RFC 7009 says 200"
    );
}

#[tokio::test]
async fn no_raw_tokens_in_state() {
    let rig = support::rig().await;
    let (client_id, issued, code) = rig.client.full_flow().await;
    let (_, rotated) = rig.client.refresh(&client_id, &issued.refresh_token).await;
    let rotated = rotated.unwrap();
    let state = std::fs::read_to_string(rig.store.path()).unwrap();

    for (name, secret) in [
        ("access", issued.access_token.as_str()),
        ("refresh", issued.refresh_token.as_str()),
        ("rotated access", rotated.access_token.as_str()),
        ("rotated refresh", rotated.refresh_token.as_str()),
        ("code", code.as_str()),
        ("password", OWNER_PASSWORD),
    ] {
        assert!(!state.contains(secret), "state.json holds the raw {name}");
    }
}

/// Sends a request with a declared length or chunked and returns the status line's code.
async fn raw_post(address: &str, path: &str, content_type: &str, body: &str, chunked: bool) -> u16 {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nhost: {address}\r\ncontent-type: {content_type}\r\nconnection: close\r\n{}\r\n",
        if chunked {
            "transfer-encoding: chunked\r\n".to_string()
        } else {
            format!("content-length: {}\r\n", body.len())
        }
    );
    let payload = if chunked {
        format!("{head}{:x}\r\n{body}\r\n0\r\n\r\n", body.len())
    } else {
        format!("{head}{body}")
    };

    // The server may answer 413 and close before the whole body is written.
    let _ = stream.write_all(payload.as_bytes()).await;

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    let text = String::from_utf8_lossy(&response);

    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn oauth_body_limit_413() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let before = std::fs::read(rig.store.path()).unwrap();
    let oversize = "a".repeat(64 * 1024 + 1);
    let padded = format!(
        r#"{{"redirect_uris":["{CLAUDE_CALLBACK}"]}}{}"#,
        " ".repeat(64 * 1024)
    );
    let form = "application/x-www-form-urlencoded";
    let requests = [
        (
            "register",
            "/register",
            "application/json",
            format!(r#"{{"client_name":"{oversize}"}}"#),
        ),
        ("register padded", "/register", "application/json", padded),
        (
            "authorize",
            "/authorize",
            form,
            format!("password={oversize}"),
        ),
        (
            "token",
            "/token",
            form,
            format!("grant_type=refresh_token&refresh_token={oversize}&client_id={client_id}"),
        ),
        ("revoke", "/revoke", form, format!("token={oversize}")),
    ];

    for (name, path, content_type, body) in &requests {
        for chunked in [false, true] {
            let status = raw_post(&rig.address(), path, content_type, body, chunked).await;

            assert_eq!(status, 413, "{name} chunked={chunked}");
        }
    }

    assert_eq!(
        std::fs::read(rig.store.path()).unwrap(),
        before,
        "state.json changed"
    );
    assert_eq!(rig.probe.started(), 0, "the password checker was called");
}

#[tokio::test]
async fn set_password_and_revoke_all() {
    let rig = support::rig().await;
    let (_, issued, _) = rig.client.full_flow().await;

    set_password(&rig.store, "a brand new long password")
        .await
        .unwrap();

    let state = rig.state().await;

    assert!(bcrypt::verify("a brand new long password", &state.owner.password_hash).unwrap());
    assert!(
        state.owner.password_hash.starts_with("$2b$12$"),
        "bcrypt cost 12"
    );
    assert!(!rig.valid(&issued.access_token).await);
    assert!(
        state.tokens.is_empty(),
        "changing the password revokes every token"
    );

    let (_, issued, _) = rig
        .client
        .full_flow_with_password("a brand new long password")
        .await;

    revoke_all(&rig.store).await.unwrap();

    let state = rig.state().await;

    assert!(!rig.valid(&issued.access_token).await);
    assert!(state.tokens.is_empty() && state.clients.is_empty());
}

async fn submit_wrong_passwords(
    rig: &OAuthRig<TestState>,
    client_id: &str,
    count: usize,
) -> Vec<mcp_starter::test_support::oauth_flow::Reply> {
    let mut forms = Vec::new();

    for _ in 0..count {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, client_id, CLAUDE_CALLBACK))
            .await;
        forms.push(form.unwrap());
    }

    let mut tasks = Vec::new();

    for form in forms {
        let client = rig.client.clone();
        tasks.push(tokio::spawn(
            async move { client.approve(&form, "wrong").await },
        ));
    }

    let mut replies = Vec::new();

    for task in tasks {
        replies.push(task.await.unwrap());
    }

    replies
}

#[tokio::test]
async fn password_check_runs_off_thread() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let runtime_thread = std::thread::current().id();

    submit_wrong_passwords(&rig, &client_id, 3).await;

    assert_eq!(rig.probe.started(), 3);
    assert!(
        rig.probe
            .threads()
            .iter()
            .all(|thread| *thread != runtime_thread)
    );
    assert_eq!(rig.probe.max_running(), 1, "at most one check at a time");
}

#[tokio::test]
async fn lockout_holds_for_queued_attempts() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut forms = Vec::new();

    for _ in 0..6 {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
            .await;
        forms.push(form.unwrap());
    }

    rig.probe.hold();

    let mut tasks = Vec::new();

    for (index, form) in forms.into_iter().enumerate() {
        let client = rig.client.clone();
        let password = if index < 5 { "wrong" } else { OWNER_PASSWORD };
        tasks.push(tokio::spawn(async move {
            client.approve(&form, password).await
        }));
        sleep(Duration::from_millis(40)).await;
    }

    wait_until(Duration::from_secs(5), "the first check to start", || {
        rig.probe.started() >= 1
    })
    .await;
    sleep(Duration::from_millis(100)).await;
    rig.probe.release();

    let mut replies = Vec::new();

    for task in tasks {
        replies.push(task.await.unwrap());
    }

    for reply in &replies[..5] {
        assert!(reply.body.contains("Wrong password"), "{}", reply.body);
    }

    assert_eq!(
        replies[5].status, 429,
        "the sixth is refused with the lockout page"
    );
    assert!(replies[5].body.contains("Too many wrong passwords"));
    assert_eq!(rig.probe.started(), 5, "the checker ran exactly five times");
}

#[tokio::test]
async fn password_attempt_survives_cancel() {
    let rig = support::rig().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut forms = Vec::new();

    for _ in 0..6 {
        let (form, _) = rig
            .client
            .consent(&authorize_params(&INFO, &client_id, CLAUDE_CALLBACK))
            .await;
        forms.push(form.unwrap());
    }

    rig.probe.hold();

    for form in &forms[..5] {
        let dropped = tokio::time::timeout(
            Duration::from_millis(150),
            rig.client.approve(form, "wrong"),
        )
        .await;

        assert!(
            dropped.is_err(),
            "the request must be dropped while the checker runs"
        );
    }

    rig.probe.release();
    wait_until(Duration::from_secs(10), "five completed checks", || {
        rig.probe.completed() == 5
    })
    .await;
    assert_eq!(rig.probe.max_running(), 1);

    let reply = rig.client.approve(&forms[5], OWNER_PASSWORD).await;

    assert_eq!(
        reply.status, 429,
        "after five completed failures the next attempt is locked out"
    );
    assert_eq!(rig.probe.started(), 5);
}

/// A store whose writes can be stalled, and a flag that says one is stalled right now.
fn stalling_options() -> (StoreOptions, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let stalled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicUsize::new(0));
    let mut hooks = Hooks::default();
    let (flag, count) = (stalled.clone(), entered.clone());
    hooks.sync_file = Arc::new(move |file| {
        if flag.load(Ordering::SeqCst) {
            count.fetch_add(1, Ordering::SeqCst);
        }

        while flag.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }

        file.sync_all()
    });

    (
        StoreOptions {
            hooks,
            ..StoreOptions::default()
        },
        stalled,
        entered,
    )
}

struct LiftOnDrop(Arc<AtomicBool>);

impl Drop for LiftOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn concurrent_code_replay_revokes_all() {
    let (options, stalled, entered) = stalling_options();
    let _lift = LiftOnDrop(stalled.clone());
    let rig = support::rig_with(options).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;

    stalled.store(true, Ordering::SeqCst);

    let (first_client, first_code, first_id) =
        (rig.client.clone(), code.clone(), client_id.clone());
    let first = tokio::spawn(async move {
        first_client
            .exchange(&first_id, CLAUDE_CALLBACK, &first_code, VERIFIER)
            .await
    });
    wait_until(
        Duration::from_secs(5),
        "the first exchange's store job to stall",
        || entered.load(Ordering::SeqCst) >= 1,
    )
    .await;

    let (second_client, second_code, second_id) =
        (rig.client.clone(), code.clone(), client_id.clone());
    let second = tokio::spawn(async move {
        second_client
            .exchange(&second_id, CLAUDE_CALLBACK, &second_code, VERIFIER)
            .await
    });
    sleep(Duration::from_millis(150)).await;
    stalled.store(false, Ordering::SeqCst);

    let (first_reply, first_tokens) = first.await.unwrap();
    let (second_reply, second_tokens) = second.await.unwrap();

    assert_eq!(first_reply.status, 200, "the first exchange issued tokens");
    assert_eq!(
        (second_reply.status, second_reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(second_tokens.is_none());

    let first_tokens = first_tokens.unwrap();

    assert!(
        !rig.valid(&first_tokens.access_token).await,
        "the replay revoked the family"
    );

    let (reply, _) = rig
        .client
        .refresh(&client_id, &first_tokens.refresh_token)
        .await;

    assert_eq!(reply.error_code(), "invalid_grant");
}

#[tokio::test]
async fn concurrent_code_replay_survives_dropped_first_requester() {
    let (options, stalled, entered) = stalling_options();
    let _lift = LiftOnDrop(stalled.clone());
    let rig = support::rig_with(options).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;

    stalled.store(true, Ordering::SeqCst);

    let first = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER);
    let dropped = tokio::select! {
        _ = first => false,
        _ = wait_until(Duration::from_secs(5), "the stalled store job", || entered.load(Ordering::SeqCst) >= 1) => true,
    };

    assert!(
        dropped,
        "the first requester is dropped while its transaction is stalled"
    );

    let (second_client, second_code, second_id) =
        (rig.client.clone(), code.clone(), client_id.clone());
    let second = tokio::spawn(async move {
        second_client
            .exchange(&second_id, CLAUDE_CALLBACK, &second_code, VERIFIER)
            .await
    });
    sleep(Duration::from_millis(150)).await;
    stalled.store(false, Ordering::SeqCst);

    let (second_reply, _) = second.await.unwrap();

    assert_eq!(second_reply.error_code(), "invalid_grant");
    assert!(
        rig.state().await.tokens.is_empty(),
        "the tokens the dropped requester never saw are revoked"
    );
}

/// The store's file lock alone cannot order a replay's revoke after the first exchange's
/// commit when the first job has not taken that lock yet, so this test stalls the first job
/// before its `flock` (in the root-only owner lookup) and only the D50 grant lock makes the
/// replay wait.
#[tokio::test]
async fn concurrent_code_replay_revokes_all_before_the_store_lock() {
    let armed = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicUsize::new(0));
    let _lift = LiftOnDrop(stalled.clone());
    let mut hooks = Hooks::default();
    let (arm, flag, count) = (armed.clone(), stalled.clone(), entered.clone());
    hooks.euid = Arc::new(|| 0);
    hooks.chown = Arc::new(|_, _, _, _| Ok(()));
    hooks.dir_owner = Arc::new(move |_| {
        if arm.swap(false, Ordering::SeqCst) {
            count.fetch_add(1, Ordering::SeqCst);

            while flag.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        Ok((0, 0))
    });
    let rig = support::rig_with(StoreOptions {
        hooks,
        ..StoreOptions::default()
    })
    .await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;

    stalled.store(true, Ordering::SeqCst);
    armed.store(true, Ordering::SeqCst);

    let (first_client, first_code, first_id) =
        (rig.client.clone(), code.clone(), client_id.clone());
    let first = tokio::spawn(async move {
        first_client
            .exchange(&first_id, CLAUDE_CALLBACK, &first_code, VERIFIER)
            .await
    });
    wait_until(
        Duration::from_secs(5),
        "the first exchange's store job to stall before the file lock",
        || entered.load(Ordering::SeqCst) >= 1,
    )
    .await;

    let (second_client, second_code, second_id) =
        (rig.client.clone(), code.clone(), client_id.clone());
    let second = tokio::spawn(async move {
        second_client
            .exchange(&second_id, CLAUDE_CALLBACK, &second_code, VERIFIER)
            .await
    });
    sleep(Duration::from_millis(300)).await;
    stalled.store(false, Ordering::SeqCst);

    let (first_reply, first_tokens) = first.await.unwrap();
    let (second_reply, _) = second.await.unwrap();

    assert_eq!(first_reply.status, 200, "the first exchange issued tokens");
    assert_eq!(second_reply.error_code(), "invalid_grant");
    assert!(
        !rig.valid(&first_tokens.unwrap().access_token).await,
        "the replay revoked the family"
    );
}

#[tokio::test]
async fn garbage_refresh_tokens_do_not_write() {
    let rig = support::rig().await;
    let (client_id, _, _) = rig.client.full_flow().await;
    let before = std::fs::read(rig.store.path()).unwrap();

    for _ in 0..3 {
        let (reply, _) = rig.client.refresh(&client_id, "not-a-token").await;

        assert_eq!(reply.error_code(), "invalid_grant");
    }

    rig.client
        .post_form("/revoke", &pairs(&[("token", "nope")]))
        .await;

    assert_eq!(std::fs::read(rig.store.path()).unwrap(), before);
}

#[tokio::test]
async fn scope_and_names_come_from_service_info() {
    let rig = support::rig().await;
    let meta = rig
        .client
        .get("/.well-known/oauth-authorization-server")
        .await
        .json();

    assert_eq!(
        meta["scopes_supported"],
        json!(["example", "offline_access"])
    );

    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let mut params = authorize_params(&INFO, &client_id, CLAUDE_CALLBACK);
    set_param(&mut params, "scope", "");
    let (form, page) = rig.client.consent(&params).await;

    assert!(page.body.contains("<title>Connect to Example</title>"));
    assert!(page.body.contains("<h1>Connect to Example</h1>"));

    let approved = rig.client.approve(&form.unwrap(), OWNER_PASSWORD).await;
    let code = approved.location_param("code").unwrap();
    let (_, issued) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(
        issued.unwrap().raw["scope"],
        "example",
        "a request without scope is granted the service scope"
    );
}

#[tokio::test]
async fn service_names_are_html_escaped() {
    static OTHER: mcp_starter::ServiceInfo = mcp_starter::ServiceInfo {
        command: "other-mcp",
        display_name: "Other <Co> & Sons",
        env_prefix: "OTHER_MCP_",
        default_listen: "127.0.0.1:8091",
        default_data_dir: "/var/lib/other-mcp",
        default_tz: "UTC",
        scope: "other",
        favicon: &[],
    };

    let rig = OAuthRig::<TestState>::start(&OTHER).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (_, page) = rig
        .client
        .consent(&authorize_params(&OTHER, &client_id, CLAUDE_CALLBACK))
        .await;

    assert!(
        page.body
            .contains("<title>Connect to Other &lt;Co&gt; &amp; Sons</title>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<Co>"));
}
