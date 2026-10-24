//! The command-line blocks every service shares: the terminal and process plumbing, the
//! owner-password and revoke commands, the generic part of `status`, and the `serve` runner.
//!
//! A service keeps its own `main` and its own command dispatch (see `examples/minimal`), and
//! calls these blocks from it. `run` functions take everything they read from the outside as
//! arguments, so tests drive them in-process.

use std::io::{BufRead, Write};
use std::sync::Arc;

use jiff::Timestamp;
use rmcp::ServerHandler;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Config;
use crate::oauth::{self, OAuth, bcrypt_checker};
use crate::server::{ServerOptions, build_router, mcp_service, serve};
use crate::store::{Lease, Section, State, Store};
use crate::work::Work;
use crate::{ServiceInfo, system_clock};

const MIN_PASSWORD_LENGTH: usize = 12;

/// Reads an environment variable by name; an unset one reads as an empty string.
pub type Getenv = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Everything a command reads from and writes to.
pub struct Io {
    /// Where input lines come from.
    pub stdin: Box<dyn BufRead + Send>,
    /// A terminal gets a prompt without echo; anything else is read as plain lines.
    pub stdin_is_tty: bool,
    /// Where results go.
    pub stdout: Box<dyn Write + Send>,
    /// Where prompts, errors and the listening line go.
    pub stderr: Box<dyn Write + Send>,
}

/// How a command ended.
pub struct Outcome {
    /// The process exit code.
    pub code: i32,
    /// `serve` hands the lease back so `main` can hold it until the runtime has shut down.
    pub lease: Option<Lease>,
}

impl Outcome {
    /// An outcome with an exit code and no lease.
    pub fn code(code: i32) -> Outcome {
        Outcome { code, lease: None }
    }
}

/// Reads one line without echo on a terminal, else plainly.
pub fn read_secret(io: &mut Io, prompt: &str) -> Result<String, String> {
    if io.stdin_is_tty {
        let _ = write!(io.stderr, "{prompt}");
        let _ = io.stderr.flush();
        let secret = rpassword::read_password().map_err(|error| format!("read input: {error}"));
        let _ = writeln!(io.stderr);

        return secret;
    }

    let mut line = String::new();

    io.stdin
        .read_line(&mut line)
        .map_err(|error| format!("read input: {error}"))?;

    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// `set-password`: reads the new owner password twice, stores its hash and revokes every token.
pub async fn set_password<S: Section>(io: &mut Io, store: &Store<S>) -> Result<(), String> {
    let first = read_secret(io, "New owner password: ")?;
    let second = read_secret(io, "Repeat it: ")?;

    if first.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "the password must have at least {MIN_PASSWORD_LENGTH} characters"
        ));
    }

    if first != second {
        return Err("the two passwords do not match".to_string());
    }

    oauth::set_password(store, &first).await?;

    let _ = writeln!(
        io.stdout,
        "Owner password set. All OAuth tokens were revoked; reconnect from Claude."
    );

    Ok(())
}

/// `revoke-tokens`: deletes every OAuth token and registered client.
pub async fn revoke_tokens<S: Section>(io: &mut Io, store: &Store<S>) -> Result<(), String> {
    oauth::revoke_all(store)
        .await
        .map_err(|error| error.to_string())?;

    let _ = writeln!(
        io.stdout,
        "All OAuth tokens and registered clients were deleted."
    );

    Ok(())
}

/// The three `status` lines every service prints: whether the owner password is set, how many
/// OAuth clients are registered and how many tokens are live. Never a secret.
pub fn oauth_status<S>(state: &State<S>, now: Timestamp) -> String {
    let live = state
        .tokens
        .values()
        .filter(|token| !token.rotated && now < token.expires_at)
        .count();

    format!(
        "Owner password set: {}\nOAuth clients: {}\nLive OAuth tokens: {live}\n",
        if state.owner.password_hash.is_empty() {
            "no"
        } else {
            "yes"
        },
        state.clients.len(),
    )
}

/// Cancels the returned token on the first SIGINT or SIGTERM.
pub fn shutdown_on_signals() -> Result<CancellationToken, String> {
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| error.to_string())?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|error| error.to_string())?;
    let token = CancellationToken::new();
    let on_signal = token.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }

        on_signal.cancel();
    });

    Ok(token)
}

/// A server that has taken its lease and its port but is not yet serving. The service can
/// start its background loops on `work.tracker()` between [`Serving::start`] and
/// [`Serving::run`]; they end with `shutdown` and `serve` waits for them.
pub struct Serving<S> {
    /// The configuration the server runs with.
    pub config: Config,
    /// The state file.
    pub store: Store<S>,
    /// The detached work the server tracks.
    pub work: Arc<Work>,
    /// The OAuth server.
    pub oauth: OAuth<S>,
    /// Cancelled to start the shutdown sequence.
    pub shutdown: CancellationToken,
    info: &'static ServiceInfo,
    listener: TcpListener,
    lease: Lease,
}

impl<S: Section> Serving<S> {
    /// Checks that the state file loads, takes the lease, builds the work tracker and the OAuth
    /// server and binds the listen address. `shutdown` ends the server; without it the server
    /// ends on SIGINT or SIGTERM.
    pub async fn start(
        info: &'static ServiceInfo,
        config: Config,
        store: Store<S>,
        shutdown: Option<CancellationToken>,
    ) -> Result<Serving<S>, String> {
        store
            .read(|_| ())
            .await
            .map_err(|error| error.to_string())?;

        let lease = Lease::acquire(&store, info).map_err(|error| error.to_string())?;
        let work = Work::new(TaskTracker::new());
        let oauth = OAuth::new(
            info,
            store.clone(),
            &config.public_url,
            system_clock(),
            bcrypt_checker(),
            work.clone(),
        );
        let listener = TcpListener::bind(&config.listen)
            .await
            .map_err(|error| format!("listen on {}: {error}", config.listen))?;
        let shutdown = match shutdown {
            Some(token) => token,
            None => shutdown_on_signals()?,
        };

        Ok(Serving {
            config,
            store,
            work,
            oauth,
            shutdown,
            info,
            listener,
            lease,
        })
    }

    /// Serves until `shutdown`, then drains, and hands the lease back for `main` to hold until
    /// the runtime is gone. `tools` hands each request a tool handler.
    pub async fn run<H>(
        self,
        io: &mut Io,
        tools: impl Fn() -> H + Send + Sync + 'static,
    ) -> Result<Lease, String>
    where
        H: ServerHandler + Send + 'static,
    {
        let address = self
            .listener
            .local_addr()
            .map_err(|error| error.to_string())?;
        let public_url = self.config.public_url.clone();
        let _ = writeln!(
            io.stderr,
            "{} listening on {address} for {public_url}",
            self.info.command
        );

        let mcp = mcp_service(&public_url, tools);
        let router = build_router(self.info, self.oauth, self.work.clone(), mcp);

        serve(
            self.work,
            self.listener,
            router,
            ServerOptions::default(),
            self.shutdown,
        )
        .await;

        Ok(self.lease)
    }
}
