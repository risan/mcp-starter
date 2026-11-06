//! One contract every `GrantStore` must meet, run against each store.

use jiff::{SignedDuration, Timestamp};
use mcp_starter::oauth::{GrantStore, Granted, NewGrant, NewTokens, Registered, Rotation, Subject};
use mcp_starter::store::Client;
use sha2::{Digest, Sha256};

pub const RESOURCE: &str = "https://mcp.example.com/mcp";
const SCOPE: &str = "example offline_access";

pub fn hash(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn now() -> Timestamp {
    "2026-10-24T09:00:00Z".parse().unwrap()
}

pub fn client(id: &str) -> Client {
    Client {
        client_id: id.to_string(),
        client_name: "Claude".to_string(),
        redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
        registered_at: now(),
        last_used_at: None,
        consented_subjects: Vec::new(),
        extra: Default::default(),
    }
}

pub fn subject(id: &str) -> Subject {
    Subject {
        id: id.to_string(),
        name: format!("Person {id}"),
    }
}

/// Raw token names and the hashes the store sees for a label.
pub fn tokens(label: &str, at: Timestamp) -> NewTokens {
    NewTokens {
        access_hash: hash(&format!("{label}-access")),
        refresh_hash: hash(&format!("{label}-refresh")),
        access_expires_at: at + SignedDuration::from_hours(24),
        refresh_expires_at: at + SignedDuration::from_hours(60 * 24),
    }
}

pub fn grant(label: &str, client_id: &str, who: &str) -> NewGrant {
    NewGrant {
        family: hash(&format!("{label}-code")),
        client_id: client_id.to_string(),
        scope: SCOPE.to_string(),
        resource: RESOURCE.to_string(),
        subject: subject(who),
        owner_hash: None,
        tokens: tokens(label, now()),
    }
}

pub fn rotation(from: &NewTokens, client_id: &str, label: &str, at: Timestamp) -> Rotation {
    Rotation {
        presented_hash: from.refresh_hash.clone(),
        client_id: client_id.to_string(),
        resource: RESOURCE.to_string(),
        tokens: tokens(label, at),
    }
}

pub async fn verified<St: GrantStore>(store: &St, tokens: &NewTokens, at: Timestamp) -> bool {
    store
        .verify(&tokens.access_hash, RESOURCE, at)
        .await
        .unwrap()
        .is_some()
}

pub async fn contract<St: GrantStore>(store: &St) {
    register_and_find(store).await;
    exchange_and_verify(store).await;
    rotation_rules(store).await;
    revocation(store).await;
    consents(store).await;
    revoking_a_subject(store).await;
}

async fn register_and_find<St: GrantStore>(store: &St) {
    let mut registered = client("find-me");

    registered.client_name = "Claude Desktop".to_string();
    registered.redirect_uris = vec![
        "https://claude.ai/api/mcp/auth_callback".to_string(),
        "http://127.0.0.1:5555/callback".to_string(),
    ];

    assert_eq!(
        store
            .register_client(registered.clone(), now())
            .await
            .unwrap(),
        Registered::Accepted
    );

    let found = store.find_client("find-me").await.unwrap().unwrap();

    assert_eq!(found.client_id, "find-me");
    assert_eq!(found.client_name, "Claude Desktop");
    assert_eq!(found.redirect_uris, registered.redirect_uris);
    assert_eq!(found.registered_at, now());
    assert_eq!(found.last_used_at, None);
    assert!(store.find_client("nobody").await.unwrap().is_none());
}

async fn exchange_and_verify<St: GrantStore>(store: &St) {
    store.register_client(client("ex"), now()).await.unwrap();

    let missing = grant("ex-missing", "no-such-client", "7");

    assert_eq!(
        store.exchange_code(missing.clone(), now()).await.unwrap(),
        Granted::Refused
    );
    assert!(!verified(store, &missing.tokens, now()).await);

    let issued = grant("ex-one", "ex", "42");

    assert_eq!(
        store.exchange_code(issued.clone(), now()).await.unwrap(),
        Granted::Issued(())
    );

    let info = store
        .verify(&issued.tokens.access_hash, RESOURCE, now())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(info.scope, SCOPE);
    assert_eq!(info.subject, subject("42"));
    assert_eq!(info.expires_at, issued.tokens.access_expires_at);
    assert!(
        store
            .find_client("ex")
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some()
    );
    assert!(
        store
            .verify(
                &issued.tokens.access_hash,
                "https://other.example/mcp",
                now()
            )
            .await
            .unwrap()
            .is_none(),
        "another resource"
    );
    assert!(
        store
            .verify(&issued.tokens.refresh_hash, RESOURCE, now())
            .await
            .unwrap()
            .is_none(),
        "a refresh token is not an access token"
    );
    assert!(
        store
            .verify(&hash("unknown"), RESOURCE, now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !verified(
            store,
            &issued.tokens,
            issued.tokens.access_expires_at + SignedDuration::from_secs(1)
        )
        .await,
        "expired"
    );
}

async fn rotation_rules<St: GrantStore>(store: &St) {
    store.register_client(client("rot"), now()).await.unwrap();
    store
        .register_client(client("rot-other"), now())
        .await
        .unwrap();

    let first = grant("rot-1", "rot", "42");

    store.exchange_code(first.clone(), now()).await.unwrap();

    let second = rotation(&first.tokens, "rot", "rot-2", now());
    let granted = store.rotate_refresh(second.clone(), now()).await.unwrap();

    assert_eq!(granted, Granted::Issued(SCOPE.to_string()));
    assert!(verified(store, &second.tokens, now()).await);
    assert_eq!(
        store
            .verify(&second.tokens.access_hash, RESOURCE, now())
            .await
            .unwrap()
            .unwrap()
            .subject,
        subject("42"),
        "a rotation keeps the subject"
    );

    let replay = rotation(&first.tokens, "rot", "rot-3", now());

    assert_eq!(
        store.rotate_refresh(replay.clone(), now()).await.unwrap(),
        Granted::Refused
    );
    assert!(
        !verified(store, &second.tokens, now()).await,
        "replay revokes the family"
    );
    assert!(!verified(store, &replay.tokens, now()).await);
    assert_eq!(
        store
            .rotate_refresh(rotation(&second.tokens, "rot", "rot-4", now()), now())
            .await
            .unwrap(),
        Granted::Refused,
        "the family's newest refresh token is revoked too"
    );

    let other = grant("rot-b", "rot", "42");

    store.exchange_code(other.clone(), now()).await.unwrap();

    assert_eq!(
        store
            .rotate_refresh(rotation(&other.tokens, "rot-other", "rot-5", now()), now())
            .await
            .unwrap(),
        Granted::Refused,
        "another client"
    );
    assert!(
        verified(store, &other.tokens, now()).await,
        "a refused rotation changes nothing"
    );

    let late = other.tokens.refresh_expires_at + SignedDuration::from_secs(1);

    assert_eq!(
        store
            .rotate_refresh(rotation(&other.tokens, "rot", "rot-6", late), late)
            .await
            .unwrap(),
        Granted::Refused,
        "expired"
    );
    assert_eq!(
        store
            .rotate_refresh(
                Rotation {
                    resource: "https://other.example/mcp".to_string(),
                    ..rotation(&other.tokens, "rot", "rot-7", now())
                },
                now()
            )
            .await
            .unwrap(),
        Granted::Refused,
        "another resource"
    );
    assert_eq!(
        store
            .rotate_refresh(
                Rotation {
                    presented_hash: hash("never-issued"),
                    ..rotation(&other.tokens, "rot", "rot-8", now())
                },
                now()
            )
            .await
            .unwrap(),
        Granted::Refused,
        "unknown"
    );
    assert_eq!(
        store
            .rotate_refresh(
                Rotation {
                    presented_hash: other.tokens.access_hash.clone(),
                    ..rotation(&other.tokens, "rot", "rot-9", now())
                },
                now()
            )
            .await
            .unwrap(),
        Granted::Refused,
        "an access token is not a refresh token"
    );
}

async fn revocation<St: GrantStore>(store: &St) {
    store.register_client(client("rev"), now()).await.unwrap();

    let access_only = grant("rev-a", "rev", "42");

    store
        .exchange_code(access_only.clone(), now())
        .await
        .unwrap();
    store
        .revoke_token(&access_only.tokens.access_hash, now())
        .await
        .unwrap();

    assert!(!verified(store, &access_only.tokens, now()).await);
    assert_eq!(
        store
            .rotate_refresh(rotation(&access_only.tokens, "rev", "rev-a2", now()), now())
            .await
            .unwrap(),
        Granted::Issued(SCOPE.to_string()),
        "revoking an access token leaves the refresh token"
    );

    let whole = grant("rev-b", "rev", "42");

    store.exchange_code(whole.clone(), now()).await.unwrap();
    store
        .revoke_token(&whole.tokens.refresh_hash, now())
        .await
        .unwrap();

    assert!(
        !verified(store, &whole.tokens, now()).await,
        "revoking a refresh token revokes its family"
    );

    let by_family = grant("rev-c", "rev", "42");

    store.exchange_code(by_family.clone(), now()).await.unwrap();
    store.revoke_family(&by_family.family, now()).await.unwrap();

    assert!(!verified(store, &by_family.tokens, now()).await);

    store.revoke_token(&hash("unknown"), now()).await.unwrap();
    store.revoke_family("unknown", now()).await.unwrap();
}

async fn consents<St: GrantStore>(store: &St) {
    store.register_client(client("con"), now()).await.unwrap();
    store
        .register_client(client("con-other"), now())
        .await
        .unwrap();

    assert!(!store.has_consent("42", "con").await.unwrap());

    store.save_consent("42", "con", now()).await.unwrap();
    store.save_consent("42", "con", now()).await.unwrap();

    assert!(store.has_consent("42", "con").await.unwrap());
    assert!(
        !store.has_consent("43", "con").await.unwrap(),
        "another person"
    );
    assert!(
        !store.has_consent("42", "con-other").await.unwrap(),
        "another client"
    );
    assert!(!store.has_consent("42", "no-such-client").await.unwrap());

    store
        .save_consent("42", "no-such-client", now())
        .await
        .unwrap();

    assert!(!store.has_consent("42", "no-such-client").await.unwrap());
}

async fn revoking_a_subject<St: GrantStore>(store: &St) {
    store.register_client(client("sub"), now()).await.unwrap();

    let pat = grant("sub-pat", "sub", "pat");
    let pat_again = grant("sub-pat-2", "sub", "pat");
    let sam = grant("sub-sam", "sub", "sam");

    for each in [&pat, &pat_again, &sam] {
        store.exchange_code(each.clone(), now()).await.unwrap();
    }

    store.save_consent("pat", "sub", now()).await.unwrap();
    store.revoke_subject("pat", now()).await.unwrap();

    assert!(!verified(store, &pat.tokens, now()).await);
    assert!(!verified(store, &pat_again.tokens, now()).await);
    assert!(verified(store, &sam.tokens, now()).await);
    assert_eq!(
        store
            .rotate_refresh(rotation(&pat.tokens, "sub", "sub-x", now()), now())
            .await
            .unwrap(),
        Granted::Refused
    );
    assert!(
        store.has_consent("pat", "sub").await.unwrap(),
        "a consent is trust in a client, not a grant"
    );

    store.revoke_subject("nobody", now()).await.unwrap();
}
