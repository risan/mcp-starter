# Moving mfp-mcp-rs onto mcp-starter

For the session that migrates mfp-mcp-rs (written against its `main` at 3a064fc). The state
file does not change: with section key `mfp` and the section type below, mcp-starter reads and
writes the same JSON (`tests/mfp_state_compat.rs` proves it on files written by mfp-mcp-rs
itself).

## Module map

| mfp-mcp-rs | mcp-starter | Notes |
|---|---|---|
| `config.rs` | `config` | `Config::load(&info, getenv, require_public_url)`. Env names come from `ServiceInfo::env_prefix` (`MFP_MCP_`); the defaults from `ServiceInfo`. `Config::today` is unchanged. |
| `store.rs` | `store` | `State` becomes `State<S>`: the field `mfp` is now `section` (`State.mfp` -> `State.section`), written under `S::KEY` (`"mfp"`), first in the file as before. `MfpState` stays in mfp as the service's `Section` type, with its serde attributes (the Go-compat omissions and its own `extra`). `OwnerState`, `Client`, `Token`, `TokenKind`, `Store`, `StoreOptions`, `Hooks`, `Change`, `StoreError` move as they are (`Store` becomes `Store<S>`). |
| `mfp/mod.rs` `SessionLease` | `store::Lease` | `Lease::acquire(&store, &info)`. |
| `mfp/mod.rs` `Clock`, `system_clock` | `mcp_starter::{Clock, system_clock}` | `crate::mfp::Clock` -> `mcp_starter::Clock`. |
| `mfp/mod.rs` client builder, `describe`, `read_capped` | `http` | `client_builder(extra_root_pem)` has the D37 settings; `read_capped(response, limit)` takes the limit and returns a `String` error, so mfp wraps it into its own `CallError`. `MAX_RESPONSE_BYTES` is exported. |
| `oauth/*` | `oauth` | `OAuth<S>::new(&'static info, store, issuer, clock, checker, work)`. The scope, display name (consent page) and command hint come from `ServiceInfo`; `OAuth::issuer` is new. |
| `server.rs` | `server` | `mcp_service(public_url, tools_factory)`, `build_router(&info, oauth, work, mcp)` and `serve(work, ...)` take what `App` used to supply. The favicon bytes and the protected-resource scope come from `ServiceInfo`. |
| `app.rs` | `work` | `Work`, `ConnPermit`, `ShuttingDown` move. `App` stays in mfp as a service-owned struct holding `Work`, `Config`, the MFP client and the tool options; `App::spawn_work` is `Work::spawn`. The `water` lock stays in `App`. |
| `cli.rs` | `cli` | `Io`, `Getenv`, `Outcome`, `read_secret`, `set_password`, `revoke_tokens`, `shutdown_on_signals`, `Serving` (store check, lease, `Work`, `OAuth`, bind, shutdown token, the listening line, `serve`) and `oauth_status` (the three generic `status` lines). The command dispatch (`cli::run`) stays in mfp and calls these blocks. |
| `main.rs` | `runtime::run_main` | The current-thread runtime and exit sequence. mfp's `main.rs` becomes one call: `run_main(\|args, io, getenv\| cli::run(args, io, getenv, Settings::production()))`. |
| `tools.rs` | `tools` | `MfpTools::run` -> `run_tool(work, permit, deadline, tool, timeout_note, body)`; mfp passes `"; the change may have been saved: check mfp_get_day before trying again"` for writes and `""` for reads. The `call_tool` override -> `tools::call_tool` + `request_permit`. `success_result`, `error_result`, `ToolOutcome` are public. `date_or_today(config, now, date)` returns a `jiff::civil::Date` (mfp's returned a `String`). |
| `tests/support/*` | `test_support` (feature `test-support`) | `TestClock`, `wait_until`, `raw_http`, `Capture`, `store_bearer`, `serve_mcp`, `jsonrpc`, `oauth_flow`, `server_rig`, `tls`. Add it under `[dev-dependencies]` only. |

## What stays in mfp-mcp-rs

- `ToolOptions` (the clock, `tool_deadline`, `cleanup_timeout`, `readback_delay`) and every MFP
  tool, input type and description; `src/mfp/*` (the client, cookies, nutrients, water).
- `cli::run` dispatch, `set-session`, `parse_session_input` (and its unit tests), the `status`
  lines about the session, and `Settings`.
- The `testhooks` feature and its module (`MFP_MCP_TEST_*`), and `tests/shutdown_process.rs`.
- Go-compat serde omissions: they are attributes on `MfpState`, which is the `Section`.
- Tests: `tests/mfp_api.rs`, `tests/mfp_session.rs`, `tests/tools.rs`, `tests/live.rs`,
  `tests/live_cleanup.rs`, `tests/loadcheck.rs`, `tests/shutdown_process.rs`,
  `tests/deploy_kit.rs`; in `tests/server.rs`: `shutdown_during_readback_rolls_back`,
  `shutdown_during_diary_post`, `shutdown_with_queued_www_work`,
  `shutdown_ends_after_request_timeouts`, `two_concurrent_rollbacks_finish_before_exit`,
  `shutdown_waits_for_r4_tail`, `shutdown_waits_for_late_401_tail`; in `tests/cli.rs`:
  `set_session_bare_value`, `set_session_cookie_header`, `set_session_invalid_saves_nothing`,
  `set_session_token_failure_saves_nothing`, `status_makes_no_mfp_call`,
  `set_session_while_serving`.
- The rest of the tests moved to mcp-starter and run there against `examples/minimal`
  (`config`, `store`, `oauth`, `server`, `tests/oauth.rs`, `tests/server.rs`, `tests/cli.rs`).

## Wording that changed

Everything else keeps mfp's text.

- Store lock timeout: "another mfp-mcp command holds it" -> "another process holds it".
- Lease: "another mfp-mcp process is using this MyFitnessPal session; stop it first" ->
  "another {command} process is using this data dir; stop it first" (the lock file is still
  `session.lock`).
- Public URL example: `https://mfp.example.com` -> `https://mcp.example.com`.
- Consent page: the title and heading are `Connect to {display_name}` (HTML-escaped), and the
  line "wants to read and write your food diary" is now "wants access to your {display_name}
  data"; the no-password hint is "Run {command} set-password on the server."
- `http::read_capped` reports "response larger than {limit} bytes" (mfp: "larger than 4 MB").

## Smaller points

- `unsafe` is confined to `src/sys.rs` (`geteuid`); `Hooks::default().euid` uses it, so mfp can
  drop its own `libc` call and `#![forbid(unsafe_code)]` in `lib.rs` stays valid.
- `Section::KEY` must not be `owner`, `clients` or `tokens`; `Store::open` panics if it is.
- mcp-starter builds with tracing's `release_max_level_off`, which any binary that depends on it
  inherits.
