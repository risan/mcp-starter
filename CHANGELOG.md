# Changelog

## 0.2.0

The authorization server now serves many people as well as one owner. A single-owner service
changes a few lines; its state file does not change.

New:

- `oauth::GrantStore`, where clients and grants live. The state file (`Store<S>`) implements it;
  `oauth::postgres::PgStore` (feature `postgres`, schema in `oauth::postgres::SCHEMA`) is the
  other implementation.
- `oauth::SignIn::Upstream` for a service that signs people in itself: `OAuth::take_pending`,
  `OAuth::deny`, `OAuth::complete`, a consent page remembered per person and client, a
  `__Host-` cookie that binds a sign-in to its browser.
- `Subject` on every code, token and refresh family. `OAuth::revoke_subject` and
  `OAuth::forget_subject` end a person's grants.
- `tools::request_token` reads the verified `TokenInfo` inside a tool.
- Claude's `https://claude.com/api/mcp/auth_callback` joins the redirect allowlist.

Changed (single-owner services, a few lines):

- `OAuth::new(.., checker, ..)` takes a `SignIn`: pass `SignIn::Password(checker)`.
- `OAuth<S>` is `OAuth<Store<S>>` wherever you name the type (`Serving::oauth` is already so).
  `server::build_router` and `build_router_with` take any `OAuth<St: GrantStore>`.
- `TokenInfo` has a `subject`. In owner mode it is `Subject::owner()`.
- `store::Token` has optional `subject` and `subject_name`, and `store::Client` has an optional
  `consented_subjects`. All three are left out of `state.json` when empty, so a state file
  written before 0.2.0 loads and saves unchanged.
- A struct literal of `Token` or `Client` (in a test, say) needs the new fields.
- `Section` keys, the CLI commands and the HTTP routes are unchanged.
