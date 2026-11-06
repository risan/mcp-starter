# Changelog

## 0.3.1

- The consent pages fold the callback and client id into a closed "Technical details" section,
  so people see the application, its host and their own name first. The upstream consent page
  shows the warning before that section.

## 0.3.0

- `tools::success_result` (and so `run_tool`) also puts the summary line into the structured
  output, under `_summary` (`tools::SUMMARY_KEY`). Claude Code shows the model only the
  structured output, so the summary used to reach it only through clients that show the text.
  The key is added only to an object output that has no `_summary` of its own, and only when
  the summary is not empty. The text content is unchanged.
- Breaking: a structured output now carries a key the tool did not return. A tool that declares an
  output schema must allow an optional `_summary` string, and a client that reads the structured
  output into a closed type must ignore it.

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
