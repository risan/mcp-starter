//! The process entry: the current-thread runtime and the exit sequence.

use std::future::Future;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::{Getenv, Io, Outcome};

/// Runs `run` with the process's arguments, terminal and environment on a current-thread
/// runtime, then exits with the code it returns.
///
/// One thread runs everything. The two blocking threads (DNS, bcrypt, the state file) end five
/// seconds after their last job, so an idle process shows one thread. A store job left stuck
/// in fsync must not hold the process, so the runtime is given five seconds to shut down; the
/// lease is dropped only after that.
pub fn run_main<F, Fut>(run: F) -> !
where
    F: FnOnce(Vec<String>, Io, Getenv) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .thread_keep_alive(Duration::from_secs(5))
        .build()
        .expect("the runtime settings are valid");
    let stdin = std::io::stdin();
    let io = Io {
        stdin_is_tty: stdin.is_terminal(),
        stdin: Box::new(std::io::BufReader::new(stdin)),
        stdout: Box::new(std::io::stdout()),
        stderr: Box::new(std::io::stderr()),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let getenv: Getenv = Arc::new(|key| std::env::var(key).unwrap_or_default());

    let outcome = runtime.block_on(run(args, io, getenv));

    runtime.shutdown_timeout(Duration::from_secs(5));
    drop(outcome.lease);

    std::process::exit(outcome.code);
}
