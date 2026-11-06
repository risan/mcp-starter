# mcp-starter

## What it is

The infrastructure half of a small MCP server for the Claude apps, as building blocks you call
from your own service: an OAuth 2.1 authorization server for one owner (a password) or for many
people (your service signs them in), a JSON state file with a cross-process lock or, behind the
`postgres` feature, a Postgres store, an HTTP server with strict deadlines and bounded buffers,
a current-thread runtime, the CLI commands every such server needs (`set-password`,
`revoke-tokens`, `status`, `serve`), and the helpers that run an MCP tool as detached work with
a deadline.

It is not a framework. Your service keeps its own `main`, its command dispatch (about 50
lines), its tool handler and its client for whatever it talks to. The only things you give the
blocks are a `ServiceInfo` (command name, display name, environment prefix, defaults, scope,
favicon, home page), your section type for the state file, and a factory for your tool handler.

The code is the generic part of [mfp-mcp-rs](#credits), moved and generalized, not rewritten.

## Threat model

Built for one owner, a few requests per hour, behind a tunnel or reverse proxy that does the
TLS. That decides what it does and does not do. It has two modes; the bullets say which one
they describe.

- Owner mode (`SignIn::Password`): one owner password, hashed with bcrypt, checked on the OAuth
  consent page. Five wrong
  attempts lock the page for 15 minutes. Changing the password revokes every token and voids
  every authorization code approved under the old one. Dynamic client registration is open (Claude needs it),
  capped at 50 clients, with exact redirect URIs (Claude's two callbacks, on claude.ai and claude.com, ChatGPT's callbacks and loopback URLs only).
- Tokens are opaque and stored only as SHA-256 hashes. Refresh tokens rotate; replaying a used
  one revokes the whole family. A token works only for the resource (`{public URL}/mcp`) it
  was issued for.
- The data dir stays 0700 and `state.json` 0600: group or other read access is removed when
  the store opens the dir and reads the file. Group or other write access is refused instead
  (another user may have changed the file or still hold it open, and a chmod does not close
  their descriptor): the error asks the owner to stop the service, move the data dir aside and
  set it up again in a new dir, copying in only checked values. Its files are never opened through a symlink,
  `state.json` must belong to the dir's owner, and a root-run command hands over only a file
  root or that owner already owns, through the open descriptor.
- Many-people mode (`SignIn::Upstream`, see [Many people](#many-people)): the service signs
  people in somewhere else and tells the server who they are. The browser that started a
  sign-in is bound to it by a `__Host-` cookie, so an upstream link sent to someone else fails.
  Each person approves each client once on a consent page naming the client, its redirect host
  and the person. Every grant carries its subject, and a service ends a person's grants with
  `OAuth::revoke_subject` (or `forget_subject`, when it deletes the grants itself).
- Postgres store: tokens are stored as SHA-256 hashes, and a bearer check is one indexed query
  with no cache, so a revocation holds on the next request. Every database operation takes one of
  four permits, runs inside one 10 second deadline, and the connection asks the server to stop a
  statement or a lock wait after 10 seconds. At most 1000 registered clients (clients that were
  never used and are over a day old are dropped first), and each code exchange prunes up to 500
  grants that expired over an hour ago.
- No rate limiting beyond the owner-mode lockout, no TLS (put it behind a proxy), no sessions:
  every MCP request is stateless.
- Bounded everything: request bodies (1 MiB for `/mcp`, 64 KiB for OAuth), header size,
  connection count, per-request read and write deadlines, pending OAuth records. A slow or
  flooding client cannot make the process grow.

It is meant for one owner or a few dozen people, not heavy traffic.

## Resource use

Resource use is a design goal: the box this runs on hosts other services too. One thread runs
everything, and work happens only when a request arrives; in mfp-mcp-rs a single 24-hour
keep-alive timer is the only scheduled work. The numbers below are measured on mfp-mcp-rs (the
Rust server these blocks come from) by its release check, against a fake upstream over HTTPS,
with a state file of 50 clients and a year of rotated refresh tokens. x86-64, static musl
build, three runs:

| | Target | mfp-mcp-rs (3 runs) |
|---|---|---|
| Binary | at most 8 MB | 4.32 MB |
| Idle RSS (70 s after the last upstream call) | at most 8 MB | 4.64, 4.66, 4.66 MB |
| RSS after 50 tool calls and 10 token rotations | at most 12 MB | 6.83, 6.85, 6.86 MB |
| CPU time over 60 idle seconds | none | 0 ticks |
| Threads while idle | 1 | 1 |

A service built on mcp-starter adds its own upstream client and tools to those numbers; check
yours with a release check of your own (the `test-support` feature has the fake-over-HTTPS
pieces).

## How a service uses it

A complete service is in [`examples/minimal`](examples/minimal): `service.rs` holds the
`ServiceInfo`, the section type, four tools and the command dispatch, and `main.rs` is three
lines. `cargo test` compiles and runs it, and this crate's own tests drive it. In outline:

```rust,ignore
pub static SERVICE: ServiceInfo = ServiceInfo { /* command, prefix, defaults, scope, favicon, home page */ };

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MyState { /* your part of state.json */ }

impl Section for MyState {
    const KEY: &'static str = "my_service"; // not owner, clients or tokens
}

// serve: take the lease and the port, start your own loops, then hand over your tools.
let serving = Serving::start(&SERVICE, config, store, shutdown).await?;
serving.run(io, my_tools_factory).await
```

Tools run through `tools::run_tool`, which spawns the body as tracked detached work, waits
for it until a deadline, and answers with a plain tool error when the deadline passes. A
request the client drops does not cancel the body, and shutdown waits for it.

A service that authenticates some other way builds its own router instead of `server::build_router`.
It must put `server::buffer_body` on every route that reads a body, with
`middleware::from_fn_with_state(limit, buffer_body)` inside its own auth layer: `server::serve`
cuts a connection at shutdown unless that layer marked its request as read, so without it every
request in flight is dropped.

A service that needs an HTTP route of its own (an upload page, say) builds it as an axum `Router`
and passes it to `Serving::run_with_routes`. The routes are logged like the built-in ones and get
no body cap unless they add `server::buffer_body` themselves; a route that checks access adds that
check as a later `route_layer`, so it runs before the body is read.

## Many people

By default the server has one owner who types a password. A service that has its own users
(Help Scout staff, say) signs them in itself and uses the crate for everything else:

```rust,ignore
// Storage: Postgres. Apply `oauth::postgres::SCHEMA` to the database once.
let store = PgStore::new(database_config, root_certificates);

// Sign-in: the browser is sent to your upstream, which brings it back to your callback.
struct MySignIn;

impl Upstream for MySignIn {
    fn sign_in_url(&self, pending: &str) -> String { /* your login URL, `pending` as its state */ }
}

let oauth = OAuth::new(&SERVICE, store, &public_url, system_clock(), SignIn::Upstream(Arc::new(MySignIn)), work.clone());
let router = server::build_router_with(&SERVICE, oauth.clone(), work, mcp, my_routes);

// Your callback: take the pending request first, then find out who the person is.
let pending = oauth.take_pending(&headers, &state)?;          // before any upstream work
if upstream_refused {
    return oauth.deny(pending);                                // access_denied to the client
}

oauth.complete(pending, Subject { id, name }).await            // consent page, or a code
```

- `GET /authorize` validates the request (client, exact redirect URI, PKCE S256, resource) and
  keeps it in memory under a 256-bit pending id, bound to the browser by the `__Host-mcp-sign-in`
  cookie. At most 100 sign-ins wait at once, for 10 minutes, and a request over 4 KiB is refused.
  `take_pending` needs the cookie of the browser that started the sign-in; a mismatch leaves the
  sign-in usable. `Pending::started_at` says when it began.
- `complete` shows the consent page the first time a person signs in from a client, and
  remembers the approval per person and client (`oauth_consents`, or `consented_subjects` in
  the state file). A second sign-in goes straight back to the client with a code.
- Every code, token and refresh family carries the `Subject`. `OAuth::verify` returns it in
  `TokenInfo.subject`, and the bearer check puts the verified `TokenInfo` in the request
  extensions: `tools::request_token(&context)` reads it in a tool.
- `OAuth::revoke_subject(id)` deletes the person's grants and drops their pending codes and
  consent tickets; their remembered consents stay, because a consent is trust in a client, not
  a grant. A service that deletes the grants itself, through a foreign key from
  `oauth_families.subject` in its own transaction, calls only `OAuth::forget_subject(id)`.
- Password sign-in is for the state file. Over Postgres the owner password is never set, so
  password mode shows "owner password not set".

Dependencies: add the crate, and the test helpers (rigs, a fake clock, a throwaway TLS chain)
only under `[dev-dependencies]`:

```toml
[dependencies]
mcp-starter = "0.3.0"            # add features = ["postgres"] for many people

[dev-dependencies]
mcp-starter = { version = "0.3.0", features = ["test-support"] }
```

Moving an existing mfp-mcp-rs onto it: see [MIGRATING.md](MIGRATING.md).

## Develop

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
```

`unsafe` is denied in the crate except in `src/sys.rs`, which wraps `geteuid`.

## License

MIT, see [LICENSE](LICENSE).

## Credits

The blocks are the infrastructure of mfp-mcp-rs, a Rust MCP server for MyFitnessPal, which
itself began as a Rust rewrite of
[myfitnesspal-mcp-python](https://github.com/AdamWalt/myfitnesspal-mcp-python) by Adam (MIT
License). `tests/mfp_state_compat.rs` proves that a state file written by mfp-mcp-rs loads and
saves back through this crate byte for byte.
