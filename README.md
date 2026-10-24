# mcp-starter

## What it is

The infrastructure half of a small MCP server for the Claude apps, as building blocks you call
from your own service: a single-owner OAuth 2.1 authorization server, a JSON state file with a
cross-process lock, an HTTP server with strict deadlines and bounded buffers, a current-thread
runtime, the CLI commands every such server needs (`set-password`, `revoke-tokens`, `status`,
`serve`), and the helpers that run an MCP tool as detached work with a deadline.

It is not a framework. Your service keeps its own `main`, its command dispatch (about 50
lines), its tool handler and its client for whatever it talks to. The only things you give the
blocks are a `ServiceInfo` (command name, display name, environment prefix, defaults, scope,
favicon), your section type for the state file, and a factory for your tool handler.

The code is the generic part of [mfp-mcp-rs](#credits), moved and generalized, not rewritten.

## Threat model

Built for one owner, a few requests per hour, behind a tunnel or reverse proxy that does the
TLS. That decides what it does and does not do:

- One owner password, hashed with bcrypt, checked on the OAuth consent page. Five wrong
  attempts lock the page for 15 minutes. Dynamic client registration is open (Claude needs it),
  capped at 50 clients, with exact redirect URIs (Claude's callback and loopback URLs only).
- Tokens are opaque and stored only as SHA-256 hashes. Refresh tokens rotate; replaying a used
  one revokes the whole family.
- The data dir stays 0700 and `state.json` 0600: looser modes are tightened when the store
  opens the dir and reads the file. Its files are never opened through a symlink, and a
  root-run command changes their owner through the open descriptor only.
- No multi-user model, no rate limiting beyond the lockout, no TLS (put it behind a proxy), no
  sessions: every MCP request is stateless.
- Bounded everything: request bodies (1 MiB for `/mcp`, 64 KiB for OAuth), header size,
  connection count, per-request read and write deadlines, pending OAuth records. A slow or
  flooding client cannot make the process grow.

It is not meant for many users or heavy traffic.

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
`ServiceInfo`, the section type, three tools and the command dispatch, and `main.rs` is three
lines. `cargo test` compiles and runs it, and this crate's own tests drive it. In outline:

```rust,ignore
pub static SERVICE: ServiceInfo = ServiceInfo { /* command, prefix, defaults, scope, favicon */ };

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

Dependencies: add the crate from git, and the test helpers (rigs, a fake clock, a throwaway TLS
chain) only under `[dev-dependencies]`:

```toml
[dependencies]
mcp-starter = { git = "https://github.com/risan/mcp-starter", tag = "v0.1.0" }

[dev-dependencies]
mcp-starter = { git = "https://github.com/risan/mcp-starter", tag = "v0.1.0", features = ["test-support"] }
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
