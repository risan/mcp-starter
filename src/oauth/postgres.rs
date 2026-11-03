//! A Postgres [`GrantStore`], for a service that signs many people in.
//!
//! Every operation opens its own TLS connection, runs unnamed statements (so a transaction
//! pooler works too) and holds one of four permits, so a flood of forged tokens costs at most
//! four queries at a time. Revoking a grant is deleting its family row; tokens, consents and
//! families cascade from the rows they belong to. A bearer check is one indexed query: there
//! is no cache, so a revocation holds on the next request.

use std::error::Error as _;
use std::sync::Arc;
#[cfg(feature = "test-support")]
use std::sync::Mutex;
use std::time::Duration;

use jiff::Timestamp;
use rustls::RootCertStore;
use tokio::sync::Semaphore;
use tokio_postgres::Client as Database;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::Type;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;

use super::{
    GrantStore, Granted, NewGrant, NewTokens, Registered, Rotation, Subject, TokenInfo,
    is_for_resource,
};
use crate::store::{Client, StoreError};

/// The tables the store needs, for the service to apply to its database. No role, no grants.
pub const SCHEMA: &str = include_str!("../../sql/postgres.sql");

const PERMITS: usize = 4;
const PERMIT_WAIT: Duration = Duration::from_secs(10);
const OPERATION_DEADLINE: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLIENTS: i64 = 1000;
const UNUSED_CLIENT_AGE_SECONDS: i64 = 24 * 60 * 60;
const PRUNE_AFTER_SECONDS: i64 = 60 * 60;
const PRUNE_BATCH: i64 = 500;

/// A client and the task that drives its socket. Dropping it aborts the task, which closes the
/// socket at once.
struct Connection {
    client: Database,
    _driver: AbortOnDropHandle<()>,
}

/// The grants of a service, in Postgres.
pub struct PgStore {
    config: tokio_postgres::Config,
    tls: MakeRustlsConnect,
    permits: Semaphore,
    permit_wait: Duration,
    deadline: Duration,
    #[cfg(feature = "test-support")]
    seeded: Mutex<std::collections::HashMap<String, TokenInfo>>,
}

impl PgStore {
    /// TLS is required whatever the configuration's `sslmode` says, and the server's
    /// certificate must chain to `roots`. The connection asks the server to stop a statement
    /// or a lock wait after 10 seconds, so the database stops what this side gave up on.
    ///
    /// The server must accept startup `options`: a pooled host may not, so use the direct one.
    pub fn new(config: tokio_postgres::Config, roots: RootCertStore) -> PgStore {
        PgStore::build(config, roots, PERMIT_WAIT, OPERATION_DEADLINE)
    }

    /// [`PgStore::new`] with its own limits, so a test of them does not take ten seconds.
    #[cfg(feature = "test-support")]
    pub fn with_limits(
        config: tokio_postgres::Config,
        roots: RootCertStore,
        permit_wait: Duration,
        deadline: Duration,
    ) -> PgStore {
        PgStore::build(config, roots, permit_wait, deadline)
    }

    fn build(
        mut config: tokio_postgres::Config,
        roots: RootCertStore,
        permit_wait: Duration,
        deadline: Duration,
    ) -> PgStore {
        let milliseconds = deadline.as_millis();

        config.ssl_mode(SslMode::Require);
        config.connect_timeout(CONNECT_TIMEOUT);
        config.options(format!(
            "-c statement_timeout={milliseconds} -c lock_timeout={milliseconds}"
        ));

        // The ring provider is named here so the connection never depends on a process-wide
        // default.
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        PgStore {
            config,
            tls: MakeRustlsConnect::new(tls),
            permits: Semaphore::new(PERMITS),
            permit_wait,
            deadline,
            #[cfg(feature = "test-support")]
            seeded: Mutex::new(Default::default()),
        }
    }

    /// Makes `verify` accept `token` as an access token for `info` without asking the
    /// database. For tests of a service's tools; it carries no stability promise.
    #[cfg(feature = "test-support")]
    pub fn seed_bearer(&self, token: &str, info: TokenInfo) {
        self.seeded
            .lock()
            .unwrap()
            .insert(super::hash_token(token), info);
    }

    async fn connect(&self) -> Result<Connection, tokio_postgres::Error> {
        let (client, connection) = self.config.connect(self.tls.clone()).await?;
        let driver = AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = connection.await;
        }));

        Ok(Connection {
            client,
            _driver: driver,
        })
    }

    /// Runs `work` on a fresh connection under a permit. The whole of it (connect, TLS, login,
    /// statements, commit) is inside one deadline. A timeout drops the connection, which aborts
    /// its driver, so the socket closes and the permit is free again.
    async fn run<T>(
        &self,
        work: impl AsyncFnOnce(&mut Database) -> Result<T, tokio_postgres::Error>,
    ) -> Result<T, StoreError> {
        let permit = match tokio::time::timeout(self.permit_wait, self.permits.acquire()).await {
            Ok(Ok(permit)) => permit,
            _ => {
                eprintln!("grant database busy");

                return Err(StoreError::message(
                    "the grant database is busy".to_string(),
                ));
            }
        };
        let outcome = tokio::time::timeout(self.deadline, async {
            let mut connection = self.connect().await?;

            work(&mut connection.client).await
        })
        .await;

        drop(permit);

        match outcome {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                eprintln!("grant database error: {}", database_cause(&error));

                Err(StoreError::message("the grant database failed".to_string()))
            }
            Err(_) => {
                eprintln!("grant database error: timeout");

                Err(StoreError::message(
                    "the grant database did not answer in time".to_string(),
                ))
            }
        }
    }
}

/// A database error gives only its severity, code and message: its detail, context and hint can
/// echo the failing row.
fn database_cause(error: &tokio_postgres::Error) -> String {
    if let Some(database) = error.as_db_error() {
        return format!(
            "{} {}: {}",
            database.severity(),
            database.code().code(),
            database.message()
        );
    }

    let mut cause = error.to_string();
    let mut source = error.source();

    while let Some(inner) = source {
        cause.push_str(": ");
        cause.push_str(&inner.to_string());
        source = inner.source();
    }

    cause
}

fn is_foreign_key_violation(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION)
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_second(seconds).unwrap_or(Timestamp::UNIX_EPOCH)
}

async fn insert_family(
    transaction: &tokio_postgres::Transaction<'_>,
    grant: &NewGrant,
    now: Timestamp,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .execute_typed(
            "insert into oauth_families
                 (id, client_id, subject, subject_name, scope, resource, granted_at, expires_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                (&grant.family, Type::TEXT),
                (&grant.client_id, Type::TEXT),
                (&grant.subject.id, Type::TEXT),
                (&grant.subject.name, Type::TEXT),
                (&grant.scope, Type::TEXT),
                (&grant.resource, Type::TEXT),
                (&now.as_second(), Type::INT8),
                (&grant.tokens.refresh_expires_at.as_second(), Type::INT8),
            ],
        )
        .await?;

    Ok(())
}

async fn insert_pair(
    transaction: &tokio_postgres::Transaction<'_>,
    family: &str,
    tokens: &NewTokens,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .execute_typed(
            "insert into oauth_tokens (token_hash, family, kind, expires_at)
             values ($1, $3, 'access', $4), ($2, $3, 'refresh', $5)",
            &[
                (&tokens.access_hash, Type::TEXT),
                (&tokens.refresh_hash, Type::TEXT),
                (&family, Type::TEXT),
                (&tokens.access_expires_at.as_second(), Type::INT8),
                (&tokens.refresh_expires_at.as_second(), Type::INT8),
            ],
        )
        .await?;

    Ok(())
}

/// Removes some families that expired over an hour ago, a batch at a time. A failure is
/// logged: the exchange it follows has already been committed.
async fn prune_families(database: &Database, now: Timestamp) {
    let cutoff = now.as_second() - PRUNE_AFTER_SECONDS;
    let pruned = database
        .execute_typed(
            "delete from oauth_families
             where id in (select id from oauth_families where expires_at < $1 limit $2)
               and expires_at < $1",
            &[(&cutoff, Type::INT8), (&PRUNE_BATCH, Type::INT8)],
        )
        .await;

    if let Err(error) = pruned {
        eprintln!("grant database prune failed: {}", database_cause(&error));
    }
}

impl GrantStore for PgStore {
    async fn find_client(&self, id: &str) -> Result<Option<Client>, StoreError> {
        self.run(async |database| {
            let rows = database
                .query_typed(
                    "select client_id, client_name, redirect_uris, registered_at, last_used_at
                     from oauth_clients where client_id = $1",
                    &[(&id, Type::TEXT)],
                )
                .await?;

            Ok(rows.first().map(|row| Client {
                client_id: row.get(0),
                client_name: row.get(1),
                redirect_uris: row.get(2),
                registered_at: timestamp(row.get(3)),
                last_used_at: row.get::<_, Option<i64>>(4).map(timestamp),
                consented_subjects: Vec::new(),
                extra: Default::default(),
            }))
        })
        .await
    }

    async fn register_client(
        &self,
        client: Client,
        now: Timestamp,
    ) -> Result<Registered, StoreError> {
        self.run(async |database| {
            let transaction = database.transaction().await?;

            // Two registrations at once would both see room for one more.
            transaction
                .execute_typed("lock table oauth_clients in share row exclusive mode", &[])
                .await?;
            transaction
                .execute_typed(
                    "delete from oauth_clients
                     where last_used_at is null and registered_at < $1",
                    &[(&(now.as_second() - UNUSED_CLIENT_AGE_SECONDS), Type::INT8)],
                )
                .await?;

            let held: i64 = transaction
                .query_typed("select count(*) from oauth_clients", &[])
                .await?[0]
                .get(0);

            if held >= MAX_CLIENTS {
                transaction.commit().await?;
                eprintln!("register: too many registered clients");

                return Ok(Registered::Full);
            }

            transaction
                .execute_typed(
                    "insert into oauth_clients
                         (client_id, client_name, redirect_uris, registered_at, last_used_at)
                     values ($1, $2, $3, $4, null)",
                    &[
                        (&client.client_id, Type::TEXT),
                        (&client.client_name, Type::TEXT),
                        (&client.redirect_uris, Type::TEXT_ARRAY),
                        (&client.registered_at.as_second(), Type::INT8),
                    ],
                )
                .await?;
            transaction.commit().await?;

            Ok(Registered::Accepted)
        })
        .await
    }

    async fn exchange_code(
        &self,
        grant: NewGrant,
        now: Timestamp,
    ) -> Result<Granted<()>, StoreError> {
        self.run(async |database| {
            let transaction = database.transaction().await?;
            let found = transaction
                .execute_typed(
                    "update oauth_clients set last_used_at = $2 where client_id = $1",
                    &[
                        (&grant.client_id, Type::TEXT),
                        (&now.as_second(), Type::INT8),
                    ],
                )
                .await?;

            if found == 0 {
                return Ok(Granted::Refused);
            }

            match insert_family(&transaction, &grant, now).await {
                Ok(()) => {}
                Err(error) if is_foreign_key_violation(&error) => return Ok(Granted::Refused),
                Err(error) => return Err(error),
            }

            insert_pair(&transaction, &grant.family, &grant.tokens).await?;
            transaction.commit().await?;
            prune_families(database, now).await;

            Ok(Granted::Issued(()))
        })
        .await
    }

    async fn rotate_refresh(
        &self,
        rotation: Rotation,
        now: Timestamp,
    ) -> Result<Granted<String>, StoreError> {
        self.run(async |database| {
            let transaction = database.transaction().await?;
            let presented = &rotation.presented_hash;
            let rows = transaction
                .query_typed(
                    "select family from oauth_tokens where token_hash = $1",
                    &[(presented, Type::TEXT)],
                )
                .await?;
            let Some(family) = rows.first().map(|row| row.get::<_, String>(0)) else {
                return Ok(Granted::Refused);
            };

            // The family row first, then its token rows, in every operation: the lock on the
            // family orders a rotation and a replay of the same family.
            let rows = transaction
                .query_typed(
                    "select client_id, scope, resource from oauth_families
                     where id = $1 for update",
                    &[(&family, Type::TEXT)],
                )
                .await?;
            let Some(row) = rows.first() else {
                return Ok(Granted::Refused);
            };
            let (family_client, scope, family_resource): (String, String, String) =
                (row.get(0), row.get(1), row.get(2));
            let rows = transaction
                .query_typed(
                    "select kind, expires_at, rotated from oauth_tokens
                     where token_hash = $1 for update",
                    &[(presented, Type::TEXT)],
                )
                .await?;
            let Some(row) = rows.first() else {
                return Ok(Granted::Refused);
            };
            let (kind, expires_at, rotated): (String, i64, bool) =
                (row.get(0), row.get(1), row.get(2));

            if kind != "refresh" {
                return Ok(Granted::Refused);
            }

            if rotated {
                transaction
                    .execute_typed(
                        "delete from oauth_families where id = $1",
                        &[(&family, Type::TEXT)],
                    )
                    .await?;
                transaction.commit().await?;

                return Ok(Granted::Refused);
            }

            if family_client != rotation.client_id
                || now.as_second() >= expires_at
                || !is_for_resource(&family_resource, &rotation.resource)
            {
                return Ok(Granted::Refused);
            }

            transaction
                .execute_typed(
                    "update oauth_tokens set rotated = true where token_hash = $1",
                    &[(presented, Type::TEXT)],
                )
                .await?;
            insert_pair(&transaction, &family, &rotation.tokens).await?;
            transaction
                .execute_typed(
                    "update oauth_families set expires_at = $2 where id = $1",
                    &[
                        (&family, Type::TEXT),
                        (&rotation.tokens.refresh_expires_at.as_second(), Type::INT8),
                    ],
                )
                .await?;
            transaction
                .execute_typed(
                    "update oauth_clients set last_used_at = $2 where client_id = $1",
                    &[
                        (&rotation.client_id, Type::TEXT),
                        (&now.as_second(), Type::INT8),
                    ],
                )
                .await?;
            transaction.commit().await?;

            Ok(Granted::Issued(scope))
        })
        .await
    }

    async fn revoke_family(&self, family: &str, _now: Timestamp) -> Result<(), StoreError> {
        self.run(async |database| {
            database
                .execute_typed(
                    "delete from oauth_families where id = $1",
                    &[(&family, Type::TEXT)],
                )
                .await?;

            Ok(())
        })
        .await
    }

    async fn revoke_token(&self, token_hash: &str, _now: Timestamp) -> Result<(), StoreError> {
        self.run(async |database| {
            database
                .execute_typed(
                    "delete from oauth_families
                     where id = (select family from oauth_tokens
                                 where token_hash = $1 and kind = 'refresh')",
                    &[(&token_hash, Type::TEXT)],
                )
                .await?;
            database
                .execute_typed(
                    "delete from oauth_tokens where token_hash = $1 and kind = 'access'",
                    &[(&token_hash, Type::TEXT)],
                )
                .await?;

            Ok(())
        })
        .await
    }

    async fn verify(
        &self,
        token_hash: &str,
        resource: &str,
        now: Timestamp,
    ) -> Result<Option<TokenInfo>, StoreError> {
        #[cfg(feature = "test-support")]
        if let Some(info) = self.seeded.lock().unwrap().get(token_hash) {
            return Ok(Some(info.clone()));
        }

        self.run(async |database| {
            let rows = database
                .query_typed(
                    "select t.expires_at, f.scope, f.subject, f.subject_name, f.resource
                     from oauth_tokens t join oauth_families f on f.id = t.family
                     where t.token_hash = $1 and t.kind = 'access'
                       and not t.rotated and t.expires_at > $2",
                    &[(&token_hash, Type::TEXT), (&now.as_second(), Type::INT8)],
                )
                .await?;

            Ok(rows.first().and_then(|row| {
                let family_resource: String = row.get(4);

                is_for_resource(&family_resource, resource).then(|| TokenInfo {
                    scope: row.get(1),
                    subject: Subject {
                        id: row.get(2),
                        name: row.get(3),
                    },
                    expires_at: timestamp(row.get(0)),
                })
            }))
        })
        .await
    }

    /// Password sign-in is for the state file: here no password is ever set.
    async fn owner_password_hash(&self) -> Result<String, StoreError> {
        Ok(String::new())
    }

    async fn has_consent(&self, subject: &str, client_id: &str) -> Result<bool, StoreError> {
        self.run(async |database| {
            let rows = database
                .query_typed(
                    "select 1 from oauth_consents where subject = $1 and client_id = $2",
                    &[(&subject, Type::TEXT), (&client_id, Type::TEXT)],
                )
                .await?;

            Ok(!rows.is_empty())
        })
        .await
    }

    async fn save_consent(
        &self,
        subject: &str,
        client_id: &str,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.run(async |database| {
            let saved = database
                .execute_typed(
                    "insert into oauth_consents (subject, client_id, approved_at)
                     values ($1, $2, $3) on conflict do nothing",
                    &[
                        (&subject, Type::TEXT),
                        (&client_id, Type::TEXT),
                        (&now.as_second(), Type::INT8),
                    ],
                )
                .await;

            match saved {
                Err(error) if !is_foreign_key_violation(&error) => Err(error),
                _ => Ok(()),
            }
        })
        .await
    }

    async fn revoke_subject(&self, subject: &str, _now: Timestamp) -> Result<(), StoreError> {
        self.run(async |database| {
            database
                .execute_typed(
                    "delete from oauth_families where subject = $1",
                    &[(&subject, Type::TEXT)],
                )
                .await?;

            Ok(())
        })
        .await
    }
}
