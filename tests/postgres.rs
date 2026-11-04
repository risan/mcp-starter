//! The Postgres grant store against a real database: locking, limits and the whole flow.
#![cfg(feature = "postgres")]

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use jiff::SignedDuration;
use mcp_starter::oauth::postgres::PgStore;
use mcp_starter::oauth::{GrantStore, Granted, OAuth, Registered, SignIn};
use mcp_starter::test_support::TestClock;
use mcp_starter::test_support::oauth_flow::{
    CLAUDE_CALLBACK, ISSUER, OAuthClient, TestUpstream, VERIFIER, upstream_routes,
};
use mcp_starter::work::Work;
use support::INFO;
use support::grant_store::{RESOURCE, client, grant, hash, now, rotation, verified};
use support::postgres::Postgres;
use tokio::net::TcpListener;
use tokio_postgres::Client as Db;
use tokio_util::task::TaskTracker;

struct Rig {
    oauth: OAuth<PgStore>,
    client: OAuthClient,
    clock: TestClock,
}

async fn rig(postgres: &Postgres) -> Rig {
    rig_on(postgres.store()).await
}

async fn rig_on(store: PgStore) -> Rig {
    let clock = TestClock::new("2026-10-24T09:00:00Z");
    let oauth = OAuth::new(
        &INFO,
        store,
        ISSUER,
        clock.as_clock(),
        SignIn::Upstream(Arc::new(TestUpstream)),
        Work::new(TaskTracker::new()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = upstream_routes(oauth.clone());

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    Rig {
        oauth,
        client: OAuthClient::new(&INFO, &format!("http://{address}")),
        clock,
    }
}

async fn count(db: &Db, sql: &str) -> i64 {
    db.query_one(sql, &[]).await.unwrap().get(0)
}

/// How many backends wait for a lock right now.
async fn waiting(db: &Db) -> i64 {
    count(
        db,
        "select count(*) from pg_stat_activity where wait_event_type = 'Lock'",
    )
    .await
}

/// The prune runs after the exchange has answered, so its effect is waited for.
async fn wait_for_count(db: &Db, sql: &str, expected: i64) {
    let started = Instant::now();

    while count(db, sql).await != expected {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "never reached {expected}, have {}",
            count(db, sql).await
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_waiting(db: &Db, expected: i64) {
    let started = Instant::now();

    while waiting(db).await != expected {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "never reached {expected} waiting backends, have {}",
            waiting(db).await
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_schema_applies_on_a_fresh_database() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let db = postgres.superuser().await;
    let tables = count(
        &db,
        "select count(*) from information_schema.tables where table_name like 'oauth_%'",
    )
    .await;

    assert_eq!(tables, 4);
}

#[tokio::test]
async fn tokens_are_stored_only_as_hashes() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let rig = rig(&postgres).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, "42", "Pat Jones")
        .await;
    let (_, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let tokens = tokens.unwrap();
    let (_, rotated) = rig.client.refresh(&client_id, &tokens.refresh_token).await;
    let rotated = rotated.unwrap();
    let db = postgres.superuser().await;
    let mut dump = String::new();

    for table in [
        "oauth_clients",
        "oauth_consents",
        "oauth_families",
        "oauth_tokens",
    ] {
        let rows = db
            .query(&format!("select t::text from {table} t"), &[])
            .await
            .unwrap();

        for row in rows {
            dump.push_str(row.get::<_, &str>(0));
            dump.push('\n');
        }
    }

    for (name, secret) in [
        ("access", tokens.access_token.as_str()),
        ("refresh", tokens.refresh_token.as_str()),
        ("rotated access", rotated.access_token.as_str()),
        ("rotated refresh", rotated.refresh_token.as_str()),
        ("code", code.as_str()),
    ] {
        assert!(!dump.contains(secret), "the database holds the raw {name}");
    }

    assert!(
        dump.contains(&hash(&tokens.access_token)),
        "the hash is stored"
    );
    assert!(
        dump.contains(&hash(&tokens.refresh_token)),
        "the hash is stored"
    );
}

#[tokio::test]
async fn a_foreign_key_violation_on_insert_is_an_invalid_grant() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let db = postgres.superuser().await;

    db.batch_execute(
        "create table people (subject text primary key);
         alter table oauth_families add foreign key (subject) references people (subject)
             on delete cascade;",
    )
    .await
    .unwrap();

    let rig = rig(&postgres).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, "ghost", "Gone")
        .await;
    let (reply, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(tokens.is_none());
    assert_eq!(count(&db, "select count(*) from oauth_tokens").await, 0);

    db.execute("insert into people values ('ghost')", &[])
        .await
        .unwrap();

    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, "ghost", "Gone")
        .await;
    let (reply, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        rig.oauth
            .verify(&tokens.unwrap().access_token)
            .await
            .is_ok()
    );

    db.execute("delete from people where subject = 'ghost'", &[])
        .await
        .unwrap();

    assert_eq!(
        count(&db, "select count(*) from oauth_tokens").await,
        0,
        "the foreign key's cascade ends the person's grants"
    );
}

#[tokio::test]
async fn a_revocation_holds_on_the_next_check() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store();
    let db = postgres.superuser().await;

    store.register_client(client("c"), now()).await.unwrap();

    let by_hand = grant("by-hand", "c", "42");
    let by_call = grant("by-call", "c", "42");

    for each in [&by_hand, &by_call] {
        store.exchange_code(each.clone(), now()).await.unwrap();

        assert!(verified(&store, &each.tokens, now()).await);
    }

    db.execute(
        "delete from oauth_tokens where token_hash = $1",
        &[&by_hand.tokens.access_hash],
    )
    .await
    .unwrap();

    assert!(!verified(&store, &by_hand.tokens, now()).await);

    store
        .revoke_token(&by_call.tokens.access_hash, now())
        .await
        .unwrap();

    assert!(!verified(&store, &by_call.tokens, now()).await);
}

#[tokio::test]
async fn a_replay_racing_a_rotation_leaves_no_live_token() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = Arc::new(postgres.store());
    let mut holder = postgres.superuser().await;

    store.register_client(client("c"), now()).await.unwrap();

    let first = grant("race-1", "c", "42");

    store.exchange_code(first.clone(), now()).await.unwrap();

    let second = rotation(&first.tokens, "c", "race-2", now());

    store.rotate_refresh(second.clone(), now()).await.unwrap();

    let transaction = holder.transaction().await.unwrap();

    transaction
        .query(
            "select 1 from oauth_families where id = $1 for update",
            &[&first.family],
        )
        .await
        .unwrap();

    let replay = rotation(&first.tokens, "c", "race-3", now());
    let next = rotation(&second.tokens, "c", "race-4", now());
    let replaying = {
        let (store, replay) = (store.clone(), replay.clone());

        tokio::spawn(async move { store.rotate_refresh(replay, now()).await })
    };
    let rotating = {
        let (store, next) = (store.clone(), next.clone());

        tokio::spawn(async move { store.rotate_refresh(next, now()).await })
    };

    wait_for_waiting(&postgres.superuser().await, 2).await;
    transaction.commit().await.unwrap();
    replaying.await.unwrap().unwrap();
    rotating.await.unwrap().unwrap();

    for tokens in [&first.tokens, &second.tokens, &replay.tokens, &next.tokens] {
        assert!(!verified(&*store, tokens, now()).await);
        assert_eq!(
            store
                .rotate_refresh(rotation(tokens, "c", "race-5", now()), now())
                .await
                .unwrap(),
            Granted::Refused
        );
    }
}

#[tokio::test]
async fn two_concurrent_rotations_of_one_token_revoke_the_family() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store();

    store.register_client(client("c"), now()).await.unwrap();

    let first = grant("twice", "c", "42");

    store.exchange_code(first.clone(), now()).await.unwrap();

    let one = rotation(&first.tokens, "c", "twice-1", now());
    let two = rotation(&first.tokens, "c", "twice-2", now());
    let (left, right) = tokio::join!(
        store.rotate_refresh(one.clone(), now()),
        store.rotate_refresh(two.clone(), now())
    );
    let outcomes = [left.unwrap(), right.unwrap()];

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Granted::Issued(_)))
            .count(),
        1,
        "{outcomes:?}"
    );

    for tokens in [&first.tokens, &one.tokens, &two.tokens] {
        assert!(!verified(&store, tokens, now()).await);
    }
}

#[tokio::test]
async fn the_client_table_holds_at_most_1000() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let rig = rig(&postgres).await;
    let db = postgres.superuser().await;
    let day = 86_400;
    let at = now().as_second();

    db.batch_execute(&format!(
        "insert into oauth_clients select 'old-unused-' || g, 'n', array['https://x.example'], {old}, null
             from generate_series(1, 400) g;
         insert into oauth_clients select 'old-used-' || g, 'n', array['https://x.example'], {old}, {at}
             from generate_series(1, 300) g;
         insert into oauth_clients select 'recent-' || g, 'n', array['https://x.example'], {recent}, null
             from generate_series(1, 300) g;",
        old = at - 2 * day,
        recent = at - day / 2
    ))
    .await
    .unwrap();

    let full = rig
        .client
        .post_json(
            "/register",
            &serde_json::json!({"client_name": "C", "redirect_uris": [CLAUDE_CALLBACK]}),
        )
        .await;

    assert_eq!(
        full.status, 201,
        "never-used clients over a day old make room: {}",
        full.body
    );
    assert_eq!(
        count(
            &db,
            "select count(*) from oauth_clients where client_id like 'old-unused-%'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &db,
            "select count(*) from oauth_clients where client_id like 'old-used-%'"
        )
        .await,
        300
    );
    assert_eq!(
        count(
            &db,
            "select count(*) from oauth_clients where client_id like 'recent-%'"
        )
        .await,
        300
    );
    assert_eq!(count(&db, "select count(*) from oauth_clients").await, 601);

    db.batch_execute(&format!(
        "insert into oauth_clients select 'filler-' || g, 'n', array['https://x.example'], {recent}, null
             from generate_series(1, 399) g",
        recent = at - 60
    ))
    .await
    .unwrap();

    assert_eq!(count(&db, "select count(*) from oauth_clients").await, 1000);

    let refused = rig
        .client
        .post_json(
            "/register",
            &serde_json::json!({"client_name": "C", "redirect_uris": [CLAUDE_CALLBACK]}),
        )
        .await;

    assert_eq!(
        (refused.status, refused.error_code().as_str()),
        (400, "invalid_client_metadata"),
        "{}",
        refused.body
    );
    assert!(refused.body.contains("too many registered clients"));
    assert_eq!(count(&db, "select count(*) from oauth_clients").await, 1000);

    let store = postgres.store();

    assert_eq!(
        store
            .register_client(client("one-more"), now())
            .await
            .unwrap(),
        Registered::Full
    );
}

#[tokio::test]
async fn an_exchange_losing_its_client_to_the_cap_answers_invalid_grant() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let rig = rig(&postgres).await;
    let db = postgres.superuser().await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, "42", "Pat Jones")
        .await;

    db.execute(
        "update oauth_clients set registered_at = registered_at - 200000",
        &[],
    )
    .await
    .unwrap();
    rig.client.register(&[CLAUDE_CALLBACK]).await;

    assert_eq!(
        count(&db, "select count(*) from oauth_clients").await,
        1,
        "the unused old client was deleted by the next registration"
    );

    let (reply, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (400, "invalid_grant")
    );
    assert!(tokens.is_none());
    assert_eq!(count(&db, "select count(*) from oauth_families").await, 0);
}

#[tokio::test]
async fn a_code_exchange_prunes_families_expired_over_an_hour_ago() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store();
    let db = postgres.superuser().await;
    let at = now().as_second();

    store.register_client(client("c"), now()).await.unwrap();
    db.batch_execute(&format!(
        "insert into oauth_families
             select 'old-' || g, 'c', '42', 'Pat', 'example', '{RESOURCE}', {granted}, {old}
             from generate_series(1, 600) g;
         insert into oauth_tokens
             select 'old-token-' || g, 'old-' || g, 'refresh', {old}, false
             from generate_series(1, 600) g;
         insert into oauth_families values
             ('recent', 'c', '42', 'Pat', 'example', '{RESOURCE}', {granted}, {recent}),
             ('live', 'c', '42', 'Pat', 'example', '{RESOURCE}', {granted}, {live})",
        granted = at - 10_000_000,
        old = at - 7_200,
        recent = at - 1_800,
        live = at + 100_000,
    ))
    .await
    .unwrap();

    let old = "select count(*) from oauth_families where id like 'old-%'";

    store
        .exchange_code(grant("prune-1", "c", "42"), now())
        .await
        .unwrap();
    wait_for_count(&db, old, 100).await;

    assert_eq!(count(&db, old).await, 100, "500 went");
    assert_eq!(
        count(
            &db,
            "select count(*) from oauth_tokens where token_hash like 'old-token-%'"
        )
        .await,
        100,
        "their tokens went with them"
    );

    // A prune still winding down may swallow one exchange's prune, so exchange until the rest went.
    let started = Instant::now();
    let mut round = 0;

    while count(&db, old).await != 0 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the rest never went"
        );

        round += 1;
        store
            .exchange_code(grant(&format!("prune-more-{round}"), "c", "42"), now())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(count(&db, old).await, 0, "the rest went");
    assert_eq!(
        count(
            &db,
            "select count(*) from oauth_families where id in ('recent', 'live')"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn no_more_than_four_operations_run_at_once() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store =
        Arc::new(postgres.store_with_limits(Duration::from_millis(1500), Duration::from_secs(4)));
    let mut holder = postgres.superuser().await;
    let watcher = postgres.superuser().await;
    let blocked = holder.transaction().await.unwrap();

    blocked
        .batch_execute("lock table oauth_clients in access exclusive mode")
        .await
        .unwrap();

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let store = store.clone();

            tokio::spawn(async move { store.find_client("anyone").await })
        })
        .collect();

    wait_for_waiting(&watcher, 4).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(
        waiting(&watcher).await,
        4,
        "a fifth never reaches the database"
    );

    let mut busy = 0;

    for call in calls {
        let error = call.await.unwrap().unwrap_err().to_string();

        if error.contains("busy") {
            busy += 1;
        }
    }

    assert_eq!(busy, 1, "the fifth waited for a permit, then was refused");

    blocked.commit().await.unwrap();

    assert!(store.find_client("anyone").await.unwrap().is_none());
}

#[tokio::test]
async fn a_blocked_statement_ends_at_the_lock_timeout() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store_with_limits(Duration::from_secs(1), Duration::from_secs(2));
    let mut holder = postgres.superuser().await;
    let watcher = postgres.superuser().await;
    let blocked = holder.transaction().await.unwrap();

    blocked
        .batch_execute("lock table oauth_clients in access exclusive mode")
        .await
        .unwrap();

    let started = Instant::now();
    let call = tokio::spawn(async move { store.find_client("anyone").await });

    wait_for_waiting(&watcher, 1).await;

    assert!(call.await.unwrap().is_err());
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        waiting(&watcher).await,
        0,
        "the server stopped waiting although the lock is still held"
    );

    blocked.commit().await.unwrap();
}

#[tokio::test]
async fn a_silent_database_times_out_and_frees_its_permit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut held = Vec::new();

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        }
    });

    let mut config = tokio_postgres::Config::new();

    config
        .host("127.0.0.1")
        .port(port)
        .user("postgres")
        .dbname("postgres");

    let store = Arc::new(PgStore::with_limits(
        config,
        support::postgres::test_roots(),
        Duration::from_secs(5),
        Duration::from_secs(1),
    ));
    let started = Instant::now();
    let calls: Vec<_> = (0..4)
        .map(|_| {
            let store = store.clone();

            tokio::spawn(async move { store.verify(&hash("t"), RESOURCE, now()).await })
        })
        .collect();

    for call in calls {
        assert!(call.await.unwrap().is_err());
    }

    let first_round = started.elapsed();

    assert!(first_round >= Duration::from_millis(900), "{first_round:?}");
    assert!(first_round < Duration::from_secs(3), "{first_round:?}");

    let fifth_started = Instant::now();
    let error = store
        .verify(&hash("t"), RESOURCE, now())
        .await
        .unwrap_err()
        .to_string();

    assert!(!error.contains("busy"), "the permits were freed: {error}");
    assert!(fifth_started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn the_whole_upstream_flow_runs_on_postgres() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let rig = rig(&postgres).await;
    let client_id = rig.client.register(&[CLAUDE_CALLBACK]).await;
    let (cookie, page) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, "42", "Pat Jones")
        .await;

    assert_eq!(
        page.status, 200,
        "the first sign-in asks for consent: {}",
        page.body
    );

    let ticket = OAuthClient::consent_ticket(&page).unwrap();
    let allowed = rig.client.decide(&ticket, "allow", Some(&cookie)).await;

    assert_eq!(allowed.status, 303, "{}", allowed.body);

    let code = allowed.location_param("code").unwrap();
    let (reply, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let tokens = tokens.unwrap_or_else(|| panic!("exchange: {}", reply.body));
    let info = rig.oauth.verify(&tokens.access_token).await.unwrap();

    assert_eq!(info.subject.id, "42");
    assert_eq!(info.subject.name, "Pat Jones");

    let (_, replayed_code) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;

    assert!(replayed_code.is_none(), "a code is used once");
    assert!(
        rig.oauth.verify(&tokens.access_token).await.is_err(),
        "replaying a code revokes what it produced"
    );

    let (_, second) = rig
        .client
        .sign_in(&client_id, CLAUDE_CALLBACK, "42", "Pat Jones")
        .await;

    assert_eq!(
        second.status, 303,
        "the consent is remembered in the database"
    );

    let code = second.location_param("code").unwrap();
    let (_, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let tokens = tokens.unwrap();

    rig.clock.advance(SignedDuration::from_hours(1));

    let (_, rotated) = rig.client.refresh(&client_id, &tokens.refresh_token).await;
    let rotated = rotated.unwrap();

    assert!(rig.oauth.verify(&rotated.access_token).await.is_ok());

    let (replay, _) = rig.client.refresh(&client_id, &tokens.refresh_token).await;

    assert_eq!(replay.error_code(), "invalid_grant");
    assert!(
        rig.oauth.verify(&rotated.access_token).await.is_err(),
        "a replayed refresh token revokes its family"
    );

    let (_, code) = rig
        .client
        .upstream_grant(&client_id, CLAUDE_CALLBACK, "42", "Pat Jones")
        .await;
    let (_, tokens) = rig
        .client
        .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
        .await;
    let tokens = tokens.unwrap();

    rig.oauth.revoke_subject("42").await.unwrap();

    assert!(rig.oauth.verify(&tokens.access_token).await.is_err());
}

#[tokio::test]
async fn a_blocked_prune_does_not_lose_the_token_pair() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store_with_limits(Duration::from_secs(1), Duration::from_secs(3));
    let db = postgres.superuser().await;
    let mut holder = postgres.superuser().await;
    let at = now().as_second();

    store.register_client(client("c"), now()).await.unwrap();
    db.batch_execute(&format!(
        "insert into oauth_families
             values ('stuck', 'c', '42', 'Pat', 'example', '{RESOURCE}', {granted}, {old})",
        granted = at - 10_000_000,
        old = at - 7_200,
    ))
    .await
    .unwrap();

    // The prune wants to delete this family, and a lock holds it.
    let blocked = holder.transaction().await.unwrap();

    blocked
        .query(
            "select 1 from oauth_families where id = 'stuck' for update",
            &[],
        )
        .await
        .unwrap();

    let started = Instant::now();
    let issued = grant("pruned-around", "c", "42");
    let granted = store.exchange_code(issued.clone(), now()).await.unwrap();

    assert_eq!(granted, Granted::Issued(()));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the answer waited for the prune: {:?}",
        started.elapsed()
    );
    assert!(verified(&store, &issued.tokens, now()).await);

    blocked.commit().await.unwrap();
    wait_for_count(
        &db,
        "select count(*) from oauth_families where id = 'stuck'",
        0,
    )
    .await;
}

#[tokio::test]
async fn blocked_prunes_never_hold_more_than_one_permit() {
    let Some(postgres) = Postgres::ready().await else {
        return;
    };
    let store = postgres.store_with_limits(Duration::from_secs(1), Duration::from_secs(5));
    let db = postgres.superuser().await;
    let mut holder = postgres.superuser().await;
    let at = now().as_second();

    store.register_client(client("c"), now()).await.unwrap();
    db.batch_execute(&format!(
        "insert into oauth_families
             values ('stuck', 'c', '42', 'Pat', 'example', '{RESOURCE}', {granted}, {old})",
        granted = at - 10_000_000,
        old = at - 7_200,
    ))
    .await
    .unwrap();

    let blocked = holder.transaction().await.unwrap();

    blocked
        .query(
            "select 1 from oauth_families where id = 'stuck' for update",
            &[],
        )
        .await
        .unwrap();

    let exchanges = (0..6).map(|number| {
        let store = store.clone();
        let issued = grant(&format!("burst-{number}"), "c", "42");

        tokio::spawn(async move {
            let granted = store.exchange_code(issued.clone(), now()).await.unwrap();

            (granted, issued)
        })
    });
    let mut last = None;

    for exchange in exchanges.collect::<Vec<_>>() {
        let (granted, issued) = exchange.await.unwrap();

        assert_eq!(granted, Granted::Issued(()));

        last = Some(issued);
    }

    wait_for_waiting(&db, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(waiting(&db).await, 1, "more than one prune is running");
    assert!(verified(&store, &last.unwrap().tokens, now()).await);

    blocked.commit().await.unwrap();
    wait_for_count(
        &db,
        "select count(*) from oauth_families where id = 'stuck'",
        0,
    )
    .await;
}
