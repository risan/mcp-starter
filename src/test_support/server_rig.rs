//! The whole server on a real socket: router, bearer middleware, body layer, connection
//! driver and the shutdown sequence, with the service's own tool handler behind it.

use std::sync::Arc;

use rmcp::ServerHandler;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::TestClock;
use super::jsonrpc::McpClient;
use super::oauth_flow::{CLAUDE_CALLBACK, OAuthClient, OWNER_PASSWORD, Probe, VERIFIER};
use crate::config::Config;
use crate::oauth::OAuth;
use crate::server::{ServerOptions, build_router, mcp_service, serve};
use crate::store::{Change, Section, State, Store, StoreOptions};
use crate::work::Work;
use crate::{Clock, ServiceInfo};

/// How a rig is set up.
pub struct RigSetup {
    /// The connection driver's deadlines and cap.
    pub server: ServerOptions,
    /// The state file's lock wait and hooks.
    pub store: StoreOptions,
    /// The public URL the server believes it is served at.
    pub public_url: String,
}

impl Default for RigSetup {
    fn default() -> RigSetup {
        RigSetup {
            server: ServerOptions::default(),
            store: StoreOptions::default(),
            public_url: "https://mcp.example.com".to_string(),
        }
    }
}

/// What a service needs to build its tool handler inside a rig.
pub struct RigContext<S> {
    /// The state file.
    pub store: Store<S>,
    /// The detached work the server tracks.
    pub work: Arc<Work>,
    /// The rig's clock.
    pub clock: Clock,
    /// The configuration the rig runs with.
    pub config: Config,
}

/// A running server with a fresh data dir and the owner password set.
pub struct ServerRig<S> {
    /// The data dir.
    pub dir: TempDir,
    /// The state file.
    pub store: Store<S>,
    /// The detached work the server tracks.
    pub work: Arc<Work>,
    /// The clock the server reads.
    pub clock: TestClock,
    /// Counts and gates password checks.
    pub probe: Arc<Probe>,
    /// The `host:port` the server listens on.
    pub address: String,
    /// A client for the OAuth endpoints.
    pub oauth_client: OAuthClient,
    /// Cancel it to start the shutdown sequence.
    pub shutdown: CancellationToken,
    /// The `serve` task, until [`ServerRig::stop`] awaits it.
    pub stopped: Option<JoinHandle<()>>,
}

impl<S: Section> ServerRig<S> {
    /// Starts a server. `seed` fills the state before it starts serving; `make_tools` builds
    /// the factory that hands each request a tool handler.
    pub async fn start<H, M, F>(
        info: &'static ServiceInfo,
        setup: RigSetup,
        seed: impl FnOnce(&mut State<S>) + Send + 'static,
        make_tools: M,
    ) -> ServerRig<S>
    where
        H: ServerHandler + Send + 'static,
        M: FnOnce(&RigContext<S>) -> F,
        F: Fn() -> H + Send + Sync + 'static,
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), setup.store).unwrap();
        let hash = bcrypt::hash(OWNER_PASSWORD, 4).unwrap();

        store
            .update(move |state| {
                seed(state);
                state.owner.password_hash = hash;

                Change::Write(())
            })
            .await
            .unwrap();

        let clock = TestClock::new("2026-10-24T09:00:00Z");
        let probe = Arc::new(Probe::default());
        let work = Work::new(TaskTracker::new());
        let prefix = info.env_prefix;
        let public_url = setup.public_url.clone();
        let config = Config::load(
            info,
            &move |key| {
                if key == format!("{prefix}PUBLIC_URL") {
                    return public_url.clone();
                }

                String::new()
            },
            true,
        )
        .unwrap();
        let oauth = OAuth::new(
            info,
            store.clone(),
            &setup.public_url,
            clock.as_clock(),
            probe.checker(),
            work.clone(),
        );
        let context = RigContext {
            store: store.clone(),
            work: work.clone(),
            clock: clock.as_clock(),
            config,
        };
        let tools = make_tools(&context);
        let mcp = mcp_service(&setup.public_url, tools);
        let router = build_router(info, oauth, work.clone(), mcp);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let shutdown = CancellationToken::new();
        let stopped = tokio::spawn(serve(
            work.clone(),
            listener,
            router,
            setup.server,
            shutdown.clone(),
        ));

        ServerRig {
            dir,
            store,
            work,
            clock,
            probe,
            oauth_client: OAuthClient::new(info, &format!("http://{address}")),
            address,
            shutdown,
            stopped: Some(stopped),
        }
    }

    /// The URL of a path on the server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// Runs the whole OAuth flow and returns an MCP client holding a fresh bearer token.
    pub async fn mcp(&self) -> McpClient {
        let client_id = self.oauth_client.register(&[CLAUDE_CALLBACK]).await;
        let code = self.oauth_client.grant(&client_id, CLAUDE_CALLBACK).await;
        let (reply, tokens) = self
            .oauth_client
            .exchange(&client_id, CLAUDE_CALLBACK, &code, VERIFIER)
            .await;
        let tokens = tokens.unwrap_or_else(|| panic!("no tokens: {}", reply.body));
        let mcp = McpClient::new(&self.url("/mcp")).with_bearer(&tokens.access_token);

        mcp.initialize().await;

        mcp
    }

    /// Fires the shutdown trigger and waits for `serve` to return.
    pub async fn stop(&mut self) {
        self.shutdown.cancel();
        self.stopped
            .take()
            .expect("serve was already awaited")
            .await
            .unwrap();
    }
}
