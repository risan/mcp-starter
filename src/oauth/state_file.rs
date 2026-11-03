//! The state file as a [`GrantStore`]: the single-owner server's storage, unchanged.

use std::collections::BTreeSet;

use jiff::Timestamp;

use super::{GrantStore, Granted, NewGrant, NewTokens, Registered, Rotation, Subject, TokenInfo};
use crate::store::{
    Change, Client, Section, State as StoreState, Store, StoreError, Token, TokenKind,
};

const MAX_CLIENTS: usize = 50;

/// Records written before tokens carried a resource have none; they stay valid.
fn is_for_resource(record_resource: &str, resource: &str) -> bool {
    record_resource.is_empty() || record_resource == resource
}

/// Drops expired tokens. A rotated refresh record stays only while its family still has a
/// live token, so replaying it keeps revoking the descendants; a family with nothing live
/// is removed whole. Returns whether anything was removed.
fn prune_tokens<S>(state: &mut StoreState<S>, now: Timestamp) -> bool {
    let live: BTreeSet<String> = state
        .tokens
        .values()
        .filter(|token| !token.rotated && now < token.expires_at)
        .map(|token| token.family.clone())
        .collect();
    let before = state.tokens.len();

    state.tokens.retain(|_, token| {
        if token.rotated {
            live.contains(&token.family)
        } else {
            now < token.expires_at
        }
    });

    state.tokens.len() != before
}

fn delete_family<S>(state: &mut StoreState<S>, family: &str) -> bool {
    let before = state.tokens.len();

    state.tokens.retain(|_, token| token.family != family);

    state.tokens.len() != before
}

/// Removes the client unused for longest: never-used clients first, oldest
/// registration first; otherwise the oldest grant. `keep` is spared. Returns whether a
/// client was removed.
fn evict_client<S>(state: &mut StoreState<S>, keep: &str) -> bool {
    let victim = state
        .clients
        .values()
        .filter(|client| client.client_id != keep)
        .min_by_key(|client| {
            (
                client.last_used_at.is_some(),
                client.last_used_at,
                client.registered_at,
            )
        })
        .map(|client| client.client_id.clone());

    let Some(victim) = victim else {
        return false;
    };

    state.clients.remove(&victim);
    state.tokens.retain(|_, token| token.client_id != victim);

    true
}

/// The owner is stored as an empty subject, so a single-owner state file never changes shape.
fn stored_subject(subject: &Subject) -> (String, String) {
    if *subject == Subject::owner() {
        return (String::new(), String::new());
    }

    (subject.id.clone(), subject.name.clone())
}

fn token_subject(token: &Token) -> Subject {
    if token.subject.is_empty() {
        return Subject::owner();
    }

    Subject {
        id: token.subject.clone(),
        name: token.subject_name.clone(),
    }
}

/// What the new tokens of a family have in common.
struct Family<'a> {
    id: &'a str,
    client_id: &'a str,
    scope: &'a str,
    resource: &'a str,
    subject: (String, String),
}

/// Adds an access and a refresh token to the family.
fn issue<S>(state: &mut StoreState<S>, family: &Family, tokens: &NewTokens) {
    let record = |kind, expires_at| Token {
        kind,
        client_id: family.client_id.to_string(),
        family: family.id.to_string(),
        scope: family.scope.to_string(),
        resource: family.resource.to_string(),
        subject: family.subject.0.clone(),
        subject_name: family.subject.1.clone(),
        expires_at,
        rotated: false,
        extra: Default::default(),
    };

    state.tokens.insert(
        tokens.access_hash.clone(),
        record(TokenKind::Access, tokens.access_expires_at),
    );
    state.tokens.insert(
        tokens.refresh_hash.clone(),
        record(TokenKind::Refresh, tokens.refresh_expires_at),
    );
}

fn changed_if<T>(changed: bool, value: T) -> Change<T> {
    if changed {
        Change::Write(value)
    } else {
        Change::Unchanged(value)
    }
}

impl<S: Section> GrantStore for Store<S> {
    async fn find_client(&self, id: &str) -> Result<Option<Client>, StoreError> {
        let id = id.to_string();

        self.read(move |state| state.clients.get(&id).cloned())
            .await
    }

    async fn register_client(
        &self,
        client: Client,
        now: Timestamp,
    ) -> Result<Registered, StoreError> {
        self.update(move |state| {
            let keep = client.client_id.clone();

            state.clients.insert(keep.clone(), client);

            while state.clients.len() > MAX_CLIENTS {
                if !evict_client(state, &keep) {
                    break;
                }
            }

            prune_tokens(state, now);

            Change::Write(Registered::Accepted)
        })
        .await
    }

    async fn exchange_code(
        &self,
        grant: NewGrant,
        now: Timestamp,
    ) -> Result<Granted<()>, StoreError> {
        self.update(move |state| {
            if state.owner.password_hash != grant.owner_hash {
                return Change::Unchanged(Granted::Refused);
            }

            let Some(client) = state.clients.get_mut(&grant.client_id) else {
                return Change::Unchanged(Granted::Refused);
            };

            client.last_used_at = Some(now);

            issue(
                state,
                &Family {
                    id: &grant.family,
                    client_id: &grant.client_id,
                    scope: &grant.scope,
                    resource: &grant.resource,
                    subject: stored_subject(&grant.subject),
                },
                &grant.tokens,
            );
            prune_tokens(state, now);

            Change::Write(Granted::Issued(()))
        })
        .await
    }

    async fn rotate_refresh(
        &self,
        rotation: Rotation,
        now: Timestamp,
    ) -> Result<Granted<String>, StoreError> {
        self.update(move |state| {
            let hash = &rotation.presented_hash;
            let client_id = &rotation.client_id;
            let (record_kind, rotated, family, record_client, expires_at, record_resource) =
                match state.tokens.get(hash) {
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

                return changed_if(pruned, Granted::Refused);
            }

            if rotated {
                delete_family(state, &family);
                prune_tokens(state, now);

                return Change::Write(Granted::Refused);
            }

            if &record_client != client_id
                || !state.clients.contains_key(client_id)
                || now >= expires_at
                || !is_for_resource(&record_resource, &rotation.resource)
            {
                let pruned = prune_tokens(state, now);

                return changed_if(pruned, Granted::Refused);
            }

            let (scope, subject) = match state.tokens.get_mut(hash) {
                Some(record) => {
                    record.rotated = true;

                    (
                        record.scope.clone(),
                        (record.subject.clone(), record.subject_name.clone()),
                    )
                }
                None => (String::new(), (String::new(), String::new())),
            };

            if let Some(client) = state.clients.get_mut(client_id) {
                client.last_used_at = Some(now);
            }

            issue(
                state,
                &Family {
                    id: &family,
                    client_id,
                    scope: &scope,
                    resource: &rotation.resource,
                    subject,
                },
                &rotation.tokens,
            );
            prune_tokens(state, now);

            Change::Write(Granted::Issued(scope))
        })
        .await
    }

    async fn revoke_family(&self, family: &str, now: Timestamp) -> Result<(), StoreError> {
        let family = family.to_string();

        self.update(move |state| {
            let removed = delete_family(state, &family);
            let pruned = prune_tokens(state, now);

            changed_if(removed || pruned, ())
        })
        .await
    }

    async fn revoke_token(&self, token_hash: &str, now: Timestamp) -> Result<(), StoreError> {
        let hash = token_hash.to_string();

        self.update(move |state| {
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
        .await
    }

    async fn verify(
        &self,
        token_hash: &str,
        resource: &str,
        now: Timestamp,
    ) -> Result<Option<TokenInfo>, StoreError> {
        let hash = token_hash.to_string();
        let resource = resource.to_string();

        self.read(move |state| {
            let record = state.tokens.get(&hash)?;

            (record.kind == TokenKind::Access
                && !record.rotated
                && now < record.expires_at
                && is_for_resource(&record.resource, &resource))
            .then(|| TokenInfo {
                scope: record.scope.clone(),
                subject: token_subject(record),
                expires_at: record.expires_at,
            })
        })
        .await
    }

    async fn owner_password_hash(&self) -> Result<String, StoreError> {
        self.read(|state| state.owner.password_hash.clone()).await
    }
}
