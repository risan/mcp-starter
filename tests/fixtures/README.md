# Test fixtures

These files are test values only. They are the proof that mcp-starter reads and writes the
state file exactly as mfp-mcp-rs does (`tests/mfp_state_compat.rs`).

## go-state-full.json, go-state-sparse.json

State files written by the Go build's own serializer, copied from mfp-mcp-rs main
(commit 3a064fc, `tests/fixtures/`). Token keys in `tokens` are the lowercase hex SHA-256 of
the raw token.

## mfp-rs-state-full.json, mfp-rs-state-sparse.json, mfp-rs-state-extras.json

State files written by mfp-mcp-rs main itself (commit 3a064fc): each input went through
`Store::update(|_| Change::Write(()))` of that crate, and the bytes it left on disk are the
fixture. The `extras` input is

    {"mfp":{"session_rev":2,"added_later":"x"},"owner":{"x":1},"clients":{},"tokens":{},"added_top":{"a":1}}

Regenerate without touching the mfp-mcp-rs repository:

    SRC=$(mktemp -d)
    git -C <mfp-mcp-rs> archive 3a064fc | tar -x -C "$SRC"
    # add $SRC/tests/write_state_fixtures.rs: a resave(input) that writes input as state.json
    # in a temp dir, opens mfp_mcp::store::Store, runs update(|_| Change::Write(())) on a
    # current-thread runtime and returns the file bytes; one test writes resave(go-state-full)
    # -> mfp-rs-state-full.json, resave(go-state-sparse) -> mfp-rs-state-sparse.json and
    # resave(<extras input above>) -> mfp-rs-state-extras.json, all into $FIXTURE_OUT
    FIXTURE_OUT=$PWD/tests/fixtures cargo test --manifest-path "$SRC/Cargo.toml" --test write_state_fixtures
    rm -rf "$SRC"

### Raw values inside the fixtures

| What | Value |
|---|---|
| full: access token | `fixture-access-token-full` |
| full: live refresh token | `fixture-refresh-token-full` |
| full: already rotated refresh token | `fixture-refresh-token-old` |
| full: client id | `client-full` (redirect `https://claude.ai/api/mcp/auth_callback`) |
| full: family | `family-full`, resource `https://mfp.example.com/mcp`, scope `mfp` |
| full: cookie `__Secure-next-auth.session-token.0` | `fixture-cookie-chunk-zero` |
| full: cookie `__Secure-next-auth.session-token.1` | `fixture-cookie-chunk-one` |
| full: bearer token / user id | `fixture-mfp-bearer-token` / `fixture-user-1` |
| sparse: access token | `fixture-access-token-sparse` |
| sparse: refresh token | `fixture-refresh-token-sparse` |
| sparse: client id | `client-sparse` (redirect `http://127.0.0.1:5555/callback`) |

Every expiry is in 2099, so a test clock at any realistic time sees the tokens as valid.
