create table oauth_clients (
    client_id      text    primary key,
    client_name    text    not null,
    redirect_uris  text[]  not null,
    registered_at  bigint  not null,
    last_used_at   bigint                          -- null until its first code exchange
);

create table oauth_consents (
    subject      text    not null,
    client_id    text    not null references oauth_clients on delete cascade,
    approved_at  bigint  not null,
    primary key (subject, client_id)
);
create index oauth_consents_client on oauth_consents (client_id);

create table oauth_families (
    id            text    primary key,             -- SHA-256 hex of the code that began it
    client_id     text    not null references oauth_clients on delete cascade,
    subject       text    not null,
    subject_name  text    not null,
    scope         text    not null,
    resource      text    not null,
    granted_at    bigint  not null,
    expires_at    bigint  not null                 -- its newest refresh token's expiry
);
create index oauth_families_client on oauth_families (client_id);
create index oauth_families_subject on oauth_families (subject);
create index oauth_families_expires on oauth_families (expires_at);

create table oauth_tokens (
    token_hash  text     primary key,              -- SHA-256 hex of the token
    family      text     not null references oauth_families on delete cascade,
    kind        text     not null check (kind in ('access', 'refresh')),
    expires_at  bigint   not null,
    rotated     boolean  not null default false
);
create index oauth_tokens_family on oauth_tokens (family);
