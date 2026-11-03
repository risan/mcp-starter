//! The authorization server with an upstream sign-in: the browser-bound pending request, the
//! consent page remembered per subject and client, and ending a subject's grants.

mod support;

use axum::http::{HeaderMap, HeaderValue};
use jiff::SignedDuration;
use mcp_starter::oauth::{GrantStore, PendingError, Subject};
use mcp_starter::test_support::oauth_flow::{
    CLAUDE_CALLBACK, ISSUER, OAuthClient, SIGN_IN_COOKIE, VERIFIER, set_param,
};

const PAT: (&str, &str) = ("42", "Pat Jones");
const SAM: (&str, &str) = ("43", "Sam Lee");

async fn registered(
    rig: &mcp_starter::test_support::oauth_flow::OAuthRig<support::TestState>,
) -> String {
    rig.client.register(&[CLAUDE_CALLBACK]).await
}

fn cookie_header(cookie: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("{SIGN_IN_COOKIE}={cookie}")).unwrap(),
    );

    headers
}

#[tokio::test]
async fn authorize_sends_the_browser_upstream_with_a_pending_id_and_a_host_cookie() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let reply = rig
        .client
        .authorize_as(
            &rig.client.authorize_params(&client_id, CLAUDE_CALLBACK),
            None,
        )
        .await;
    let pending = reply.location_param("pending").unwrap();
    let cookie = reply.sign_in_cookie().unwrap();
    let set_cookie = reply.header("set-cookie");

    assert_eq!(reply.status, 302);
    assert!(
        reply
            .header("location")
            .starts_with("https://upstream.example/sign-in?pending="),
        "{}",
        reply.header("location")
    );
    assert_eq!(pending.len(), 43, "256 bits in base64url");
    assert_eq!(cookie.len(), 43, "256 bits in base64url");
    assert_ne!(pending, cookie);
    assert!(
        set_cookie.starts_with(&format!("{SIGN_IN_COOKIE}={cookie}; Path=/")),
        "{set_cookie}"
    );

    for attribute in ["; Secure", "; HttpOnly", "; SameSite=Lax"] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }

    assert!(!set_cookie.contains("Domain"), "{set_cookie}");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(rig.oauth.pending_sign_in_counts(), (1, 0));
}

#[tokio::test]
async fn authorize_validation_is_unchanged_in_upstream_mode() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let good = rig.client.authorize_params(&client_id, CLAUDE_CALLBACK);

    let mut unknown = good.clone();
    set_param(&mut unknown, "client_id", "nobody");
    let reply = rig.client.authorize_as(&unknown, None).await;

    assert_eq!(reply.status, 400);
    assert!(reply.body.contains("unknown client"), "{}", reply.body);
    assert_eq!(reply.header("location"), "");

    let mut unregistered = good.clone();
    set_param(&mut unregistered, "redirect_uri", "https://evil.example/cb");
    let reply = rig.client.authorize_as(&unregistered, None).await;

    assert_eq!(reply.status, 400);
    assert_eq!(reply.header("location"), "");

    for (name, value, error) in [
        ("response_type", "token", "unsupported_response_type"),
        ("code_challenge_method", "plain", "invalid_request"),
        ("code_challenge", "", "invalid_request"),
        ("resource", "https://other.example/mcp", "invalid_target"),
    ] {
        let mut params = good.clone();
        set_param(&mut params, name, value);
        let reply = rig.client.authorize_as(&params, None).await;

        assert_eq!(reply.status, 302, "{name}");
        assert_eq!(reply.location_param("error").as_deref(), Some(error));
        assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
        assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
        assert_eq!(reply.sign_in_cookie(), None, "{name}");
    }

    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 0));
}

#[tokio::test]
async fn an_oversized_request_is_refused_and_nothing_is_pending() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let mut params = rig.client.authorize_params(&client_id, CLAUDE_CALLBACK);

    set_param(&mut params, "state", &"s".repeat(5000));

    let reply = rig.client.authorize_as(&params, None).await;

    assert_eq!(reply.status, 400);
    assert_eq!(reply.header("location"), "");
    assert_eq!(reply.sign_in_cookie(), None);
    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 0));
}

#[tokio::test]
async fn a_cookie_already_set_is_reused_so_two_sign_ins_in_one_browser_both_finish() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (first, cookie) = rig
        .client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
        .await;
    let (second, same_cookie) = rig
        .client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, Some(&cookie))
        .await;

    assert_eq!(same_cookie, cookie);
    assert_ne!(second, first);

    for pending in [first, second] {
        let reply = rig
            .client
            .finish_sign_in(&pending, Some(&cookie), PAT.0, PAT.1)
            .await;

        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(OAuthClient::consent_ticket(&reply).is_some());
    }
}

#[tokio::test]
async fn take_pending_needs_the_browser_that_started_it() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (pending, cookie) = rig
        .client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
        .await;
    let other_cookie = "o".repeat(43);

    for wrong in [None, Some(other_cookie.as_str())] {
        let reply = rig
            .client
            .finish_sign_in(&pending, wrong, PAT.0, PAT.1)
            .await;

        assert_eq!(reply.status, 400, "{wrong:?}");
    }

    assert_eq!(
        rig.oauth.pending_sign_in_counts().0,
        1,
        "a cookie mismatch leaves the record usable"
    );

    let reply = rig
        .client
        .finish_sign_in(&pending, Some(&cookie), PAT.0, PAT.1)
        .await;

    assert_eq!(reply.status, 200, "{}", reply.body);

    let again = rig
        .client
        .finish_sign_in(&pending, Some(&cookie), PAT.0, PAT.1)
        .await;

    assert_eq!(again.status, 400, "a pending sign-in is used once");

    let unknown = rig
        .client
        .finish_sign_in("no-such-pending", Some(&cookie), PAT.0, PAT.1)
        .await;

    assert_eq!(unknown.status, 400);
}

#[tokio::test]
async fn a_pending_sign_in_remembers_when_it_started() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let started = rig.now();
    let (pending, cookie) = rig
        .client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
        .await;

    rig.clock.advance(SignedDuration::from_mins(3));

    let wrong = rig.oauth.take_pending(&HeaderMap::new(), &pending);

    assert!(matches!(wrong, Err(PendingError::Browser)));

    let taken = rig
        .oauth
        .take_pending(&cookie_header(&cookie), &pending)
        .unwrap();

    assert_eq!(taken.started_at(), started);
    assert!(matches!(
        rig.oauth.take_pending(&cookie_header(&cookie), &pending),
        Err(PendingError::Unknown)
    ));
}

#[tokio::test]
async fn pending_sign_ins_are_capped_and_expire() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;

    for _ in 0..105 {
        rig.client
            .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
            .await;
    }

    assert_eq!(rig.oauth.pending_sign_in_counts().0, 100);

    for number in 0..105 {
        rig.client
            .sign_in(&client_id, CLAUDE_CALLBACK, &format!("u{number}"), "U")
            .await;
    }

    assert_eq!(rig.oauth.pending_sign_in_counts().1, 100);

    rig.clock.advance(SignedDuration::from_mins(11));
    rig.client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
        .await;

    assert_eq!(
        rig.oauth.pending_sign_in_counts().0,
        1,
        "the old ones expired"
    );

    rig.client
        .sign_in(&client_id, CLAUDE_CALLBACK, "late", "Late")
        .await;

    assert_eq!(
        rig.oauth.pending_sign_in_counts().1,
        1,
        "the old tickets expired"
    );
}

#[tokio::test]
async fn the_first_sign_in_shows_the_consent_page() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (_, reply) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains(
            "Allow <strong>Claude</strong> (claude.ai) to use Example as <strong>Pat Jones</strong>?"
        ),
        "{}",
        reply.body
    );
    assert_eq!(reply.header("x-frame-options"), "DENY");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert!(
        reply
            .header("content-security-policy")
            .contains("form-action 'self' https://claude.ai"),
        "{}",
        reply.header("content-security-policy")
    );
    assert_eq!(reply.header("location"), "", "no redirect yet");
    assert!(!reply.body.contains("code="), "no code yet");
    assert_eq!(rig.oauth.pending_counts().1, 0, "no code is pending");
    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 1));
}

#[tokio::test]
async fn allow_remembers_the_consent_and_redirects_with_a_code() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (cookie, page) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let ticket = OAuthClient::consent_ticket(&page).unwrap();
    let reply = rig.client.decide(&ticket, "allow", Some(&cookie)).await;

    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
    assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
    assert!(
        reply
            .header("location")
            .starts_with("https://claude.ai/api/mcp/auth_callback?")
    );

    let code = reply.location_param("code").unwrap();
    let (exchanged, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(exchanged.status, 200, "{}", exchanged.body);
    assert!(rig.valid(&tokens.unwrap().access_token).await);
    assert!(rig.store.has_consent(PAT.0, &client_id).await.unwrap());
}

#[tokio::test]
async fn a_second_sign_in_from_the_same_client_goes_straight_back_with_a_code() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;

    rig.client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    let (_, reply) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert_eq!(reply.status, 303, "{}", reply.body);
    assert!(reply.location_param("code").is_some());
    assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
    assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
    assert_eq!(
        rig.oauth.pending_sign_in_counts(),
        (0, 0),
        "no ticket was kept"
    );
}

#[tokio::test]
async fn another_subject_on_the_same_client_is_asked_again() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;

    rig.client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    let (_, reply) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, SAM.0, SAM.1)
        .await;

    assert_eq!(reply.status, 200);
    assert!(
        reply.body.contains("<strong>Sam Lee</strong>"),
        "{}",
        reply.body
    );

    let other_client = registered(&rig).await;
    let (_, reply) = rig
        .client
        .sign_in(&other_client, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert_eq!(reply.status, 200, "another client is asked again too");
}

#[tokio::test]
async fn cancel_returns_access_denied_and_remembers_nothing() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (cookie, page) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let ticket = OAuthClient::consent_ticket(&page).unwrap();
    let reply = rig.client.decide(&ticket, "cancel", Some(&cookie)).await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.location_param("error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
    assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
    assert_eq!(reply.location_param("code"), None);
    assert!(!rig.store.has_consent(PAT.0, &client_id).await.unwrap());
    assert_eq!(rig.oauth.pending_counts().1, 0);

    let (_, again) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert_eq!(again.status, 200, "the page shows again");
}

#[tokio::test]
async fn a_consent_ticket_is_single_use_and_bound_to_the_browser() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (cookie, page) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let ticket = OAuthClient::consent_ticket(&page).unwrap();
    let other_cookie = "o".repeat(43);

    for wrong in [None, Some(other_cookie.as_str())] {
        let reply = rig.client.decide(&ticket, "allow", wrong).await;

        assert_eq!(reply.status, 400, "{wrong:?}");
        assert_eq!(reply.location_param("code"), None);
    }

    assert_eq!(
        rig.oauth.pending_counts().1,
        0,
        "no code for another browser"
    );
    assert!(!rig.store.has_consent(PAT.0, &client_id).await.unwrap());

    let nonsense = rig.client.decide(&ticket, "maybe", Some(&cookie)).await;

    assert_eq!(nonsense.status, 400);

    let allowed = rig.client.decide(&ticket, "allow", Some(&cookie)).await;

    assert_eq!(allowed.status, 303, "{}", allowed.body);

    let again = rig.client.decide(&ticket, "allow", Some(&cookie)).await;

    assert_eq!(again.status, 400, "a ticket is used once");
    assert_eq!(again.location_param("code"), None);

    let unknown = rig
        .client
        .decide("no-such-ticket", "allow", Some(&cookie))
        .await;

    assert_eq!(unknown.status, 400);
}

#[tokio::test]
async fn deny_returns_access_denied_with_the_clients_state() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (pending, cookie) = rig
        .client
        .start_sign_in(&client_id, CLAUDE_CALLBACK, None)
        .await;
    let reply = rig.client.deny_sign_in(&pending, Some(&cookie)).await;

    assert_eq!(reply.status, 302);
    assert_eq!(
        reply.location_param("error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(reply.location_param("state").as_deref(), Some("st-1"));
    assert_eq!(reply.location_param("iss").as_deref(), Some(ISSUER));
    assert!(
        reply
            .header("location")
            .starts_with("https://claude.ai/api/mcp/auth_callback?")
    );
    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 0));

    let again = rig.client.deny_sign_in(&pending, Some(&cookie)).await;

    assert_eq!(again.status, 400, "the pending sign-in is spent");
}

#[tokio::test]
async fn the_code_carries_the_subject_into_the_tokens() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let (_, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let tokens = tokens.unwrap();
    let info = rig.oauth.verify(&tokens.access_token).await.unwrap();

    assert_eq!(
        info.subject,
        Subject {
            id: PAT.0.to_string(),
            name: PAT.1.to_string()
        }
    );

    let (_, refreshed) = rig.client.refresh(&client_id, &tokens.refresh_token).await;
    let info = rig
        .oauth
        .verify(&refreshed.unwrap().access_token)
        .await
        .unwrap();

    assert_eq!(info.subject.id, PAT.0, "a refresh keeps the subject");
}

#[tokio::test]
async fn revoke_subject_ends_its_grants_and_pending_codes_and_keeps_other_subjects() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let mut tokens = Vec::new();

    for (id, name) in [PAT, SAM] {
        let (_, code) = rig
            .client
            .upstream_grant(&client_id, CLAUDE_CALLBACK, id, name)
            .await;
        let (_, issued) = rig
            .client
            .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
            .await;

        tokens.push(issued.unwrap());
    }

    let (_, pending_code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    rig.oauth.revoke_subject(PAT.0).await.unwrap();

    assert!(!rig.valid(&tokens[0].access_token).await);

    let (refresh, _) = rig
        .client
        .refresh(&client_id, &tokens[0].refresh_token)
        .await;

    assert_eq!(refresh.error_code(), "invalid_grant");

    let (exchange, _) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &pending_code, VERIFIER)
        .await;

    assert_eq!(
        exchange.error_code(),
        "invalid_grant",
        "its pending code is gone"
    );
    assert!(rig.valid(&tokens[1].access_token).await, "Sam is untouched");

    let (_, reply) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert_eq!(
        reply.status, 303,
        "the consent stays: it is trust in a client"
    );
}

#[tokio::test]
async fn forget_subject_drops_pending_codes_and_consent_tickets() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;
    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let (_, issued) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let (_, pending_code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let other_client = registered(&rig).await;
    let (pat_cookie, pat_page) = rig
        .client
        .sign_in(&other_client, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;
    let (sam_cookie, sam_page) = rig
        .client
        .sign_in(&other_client, CLAUDE_CALLBACK, SAM.0, SAM.1)
        .await;

    assert_eq!(rig.oauth.pending_counts().1, 1);
    assert_eq!(rig.oauth.pending_sign_in_counts().1, 2);

    rig.oauth.forget_subject(PAT.0);

    assert_eq!(rig.oauth.pending_counts().1, 0);
    assert_eq!(rig.oauth.pending_sign_in_counts().1, 1);

    let (exchange, _) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &pending_code, VERIFIER)
        .await;

    assert_eq!(exchange.error_code(), "invalid_grant");

    let pat_ticket = OAuthClient::consent_ticket(&pat_page).unwrap();
    let gone = rig
        .client
        .decide(&pat_ticket, "allow", Some(&pat_cookie))
        .await;

    assert_eq!(gone.status, 400);

    let sam_ticket = OAuthClient::consent_ticket(&sam_page).unwrap();
    let kept = rig
        .client
        .decide(&sam_ticket, "allow", Some(&sam_cookie))
        .await;

    assert_eq!(kept.status, 303);
    assert!(
        rig.valid(&issued.unwrap().access_token).await,
        "forgetting does not delete grants"
    );
}

#[tokio::test]
async fn an_evicted_client_takes_its_consents_with_it() {
    let rig = support::upstream_rig().await;
    let first = registered(&rig).await;

    rig.client
        .upstream_grant(&first, CLAUDE_CALLBACK, PAT.0, PAT.1)
        .await;

    assert!(rig.store.has_consent(PAT.0, &first).await.unwrap());

    for _ in 0..50 {
        rig.clock.advance(SignedDuration::from_secs(1));
        registered(&rig).await;
    }

    assert!(
        !rig.state().await.clients.contains_key(&first),
        "the client was evicted"
    );
    assert!(!rig.store.has_consent(PAT.0, &first).await.unwrap());

    let state = std::fs::read_to_string(rig.store.path()).unwrap();

    assert!(!state.contains("consented_subjects"), "{state}");
}

#[tokio::test]
async fn password_mode_sets_no_cookie_and_is_unchanged() {
    let rig = support::rig().await;
    let client_id = registered(&rig).await;
    let reply = rig
        .client
        .authorize_as(
            &rig.client.authorize_params(&client_id, CLAUDE_CALLBACK),
            None,
        )
        .await;

    assert_eq!(reply.status, 200);
    assert!(reply.body.contains("name=\"csrf\""), "{}", reply.body);
    assert!(reply.body.contains("name=\"password\""), "{}", reply.body);
    assert_eq!(reply.header("set-cookie"), "");
    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 0));

    let code = rig.client.grant(&client_id, CLAUDE_CALLBACK).await;

    assert!(!code.is_empty());
}

#[tokio::test]
async fn an_unusable_subject_is_refused_and_a_long_name_is_cut() {
    let rig = support::upstream_rig().await;
    let client_id = registered(&rig).await;

    for id in [String::new(), "7".repeat(257)] {
        let (_, reply) = rig
            .client
            .sign_in(&client_id, CLAUDE_CALLBACK, &id, "Nobody")
            .await;

        assert_eq!(reply.status, 500, "{} bytes", id.len());
        assert_eq!(reply.location_param("code"), None);
    }

    assert_eq!(rig.oauth.pending_sign_in_counts(), (0, 0));

    let (_, reply) = rig
        .client
        .sign_in(
            &client_id,
            CLAUDE_CALLBACK,
            &"7".repeat(256),
            &"n".repeat(300),
        )
        .await;

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains(&"n".repeat(256)));
    assert!(!reply.body.contains(&"n".repeat(257)));
}
