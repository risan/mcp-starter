//! The README and MIGRATING.md say what the spec requires of them.

use std::fs;
use std::path::Path;

fn read(name: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(name))
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn assert_mentions(document: &str, name: &str, needles: &[&str]) {
    for needle in needles {
        assert!(document.contains(needle), "{name} lacks {needle:?}");
    }
}

#[test]
fn readme_covers_k7() {
    let readme = read("README.md");

    assert_mentions(
        &readme,
        "README.md",
        &[
            "## What it is",
            "## Threat model",
            "one owner, a few requests per hour",
            "## Resource use",
            "4.64",
            "8 MB",
            "## How a service uses it",
            "examples/minimal",
            "## License",
            "MIT",
            "mfp-mcp-rs",
        ],
    );
}

#[test]
fn migrating_maps_every_module() {
    let migrating = read("MIGRATING.md");

    assert_mentions(
        &migrating,
        "MIGRATING.md",
        &[
            "`config`",
            "`store`",
            "`oauth`",
            "`server`",
            "`app.rs`",
            "`cli`",
            "`main.rs`",
            "`tools.rs`",
            "State.mfp",
            "SessionLease",
            "ToolOptions",
            "testhooks",
            "tests/mfp_api.rs",
            "tests/mfp_session.rs",
            "tests/tools.rs",
            "tests/live",
            "tests/loadcheck.rs",
            "tests/shutdown_process.rs",
            "tests/deploy_kit.rs",
            "shutdown_during_readback_rolls_back",
            "shutdown_during_diary_post",
            "shutdown_with_queued_www_work",
            "shutdown_ends_after_request_timeouts",
            "two_concurrent_rollbacks_finish_before_exit",
            "shutdown_waits_for_r4_tail",
            "shutdown_waits_for_late_401_tail",
            "set_session_bare_value",
            "set_session_cookie_header",
            "set_session_invalid_saves_nothing",
            "set_session_token_failure_saves_nothing",
            "status_makes_no_mfp_call",
            "set_session_while_serving",
            "parse_session_input",
        ],
    );
}
