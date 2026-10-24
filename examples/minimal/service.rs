//! A whole service on mcp-starter: its identity, its section of the state file and three
//! tools. `main.rs` runs it; the tests of this crate include this file and drive it.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use mcp_starter::cli::{self, Getenv, Io, Outcome, Serving};
use mcp_starter::config::Config;
use mcp_starter::store::{Change, Lease, Section, Store, StoreOptions};
use mcp_starter::tools::{
    ToolOutcome, call_tool, date_or_today, error_result, request_permit, run_tool,
};
use mcp_starter::work::{ConnPermit, Work};
use mcp_starter::{Clock, ServiceInfo, system_clock};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;

/// What the blocks need to know about this service.
pub static SERVICE: ServiceInfo = ServiceInfo {
    command: "example-mcp",
    display_name: "Example",
    env_prefix: "EXAMPLE_MCP_",
    default_listen: "127.0.0.1:8090",
    default_data_dir: "/var/lib/example-mcp",
    default_tz: "Asia/Jakarta",
    scope: "example",
    favicon: include_bytes!("favicon.ico"),
};

/// The service's part of the state file, stored under the key `example`.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExampleState {
    /// How many times `example_count` has been called.
    #[serde(default)]
    pub count: u64,
}

impl Section for ExampleState {
    const KEY: &'static str = "example";
}

/// What every tool call shares.
pub struct App {
    pub store: Store<ExampleState>,
    pub config: Config,
    pub work: Arc<Work>,
    pub now: Clock,
    pub tool_deadline: Duration,
}

const DESCRIPTION_ECHO: &str = "Echo the text back with the date it was asked for (default today).";
const DESCRIPTION_COUNT: &str = "Add one to a counter kept in the state file and return it.";
const DESCRIPTION_WAIT: &str = "Wait for the given number of milliseconds (0 to 30000), to show a tool that outlives its caller.";
const MAX_WAIT_MILLISECONDS: u64 = 30_000;

#[derive(Debug, Deserialize, JsonSchema)]
struct EchoInput {
    /// The text to echo
    text: String,
    /// Date YYYY-MM-DD (default today in the owner's timezone)
    date: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WaitInput {
    /// How long to wait, 0 to 30000
    milliseconds: u64,
}

/// The tool handler: one copy per request, all sharing the app and the tool router.
#[derive(Clone)]
pub struct ExampleTools {
    app: Arc<App>,
    router: Arc<ToolRouter<ExampleTools>>,
    /// The connection slot of the request being served, so a tool task keeps it until the
    /// task ends.
    permit: ConnPermit,
}

impl ExampleTools {
    /// The factory `mcp_service` takes. The tool router (and its schemas) is built once.
    pub fn factory(app: Arc<App>) -> impl Fn() -> ExampleTools + Send + Sync + 'static {
        let router = Arc::new(ExampleTools::tool_router());

        move || ExampleTools {
            app: app.clone(),
            router: router.clone(),
            permit: ConnPermit::default(),
        }
    }
}

#[tool_router]
impl ExampleTools {
    #[tool(
        name = "example_echo",
        description = DESCRIPTION_ECHO,
        annotations(title = "Echo", read_only_hint = true, idempotent_hint = true)
    )]
    async fn echo(&self, Parameters(input): Parameters<EchoInput>) -> CallToolResult {
        let date = match date_or_today(&self.app.config, (self.app.now)(), input.date.as_deref()) {
            Ok(date) => date,
            Err(message) => return error_result(message),
        };
        let outcome: ToolOutcome = Ok((
            format!("Echoed {:?} for {date}.", input.text),
            json!({"text": input.text, "date": date.to_string()}),
        ));

        run_tool(
            &self.app.work,
            self.permit.clone(),
            self.app.tool_deadline,
            "example_echo",
            "",
            async move { outcome },
        )
        .await
    }

    #[tool(
        name = "example_count",
        description = DESCRIPTION_COUNT,
        annotations(title = "Count", read_only_hint = false, destructive_hint = false)
    )]
    async fn count(&self) -> CallToolResult {
        let store = self.app.store.clone();

        run_tool(
            &self.app.work,
            self.permit.clone(),
            self.app.tool_deadline,
            "example_count",
            "; the count may have been incremented: call example_count again to read it",
            async move {
                let count = store
                    .update(|state| {
                        state.section.count += 1;

                        Change::Write(state.section.count)
                    })
                    .await
                    .map_err(|error| error.to_string())?;

                Ok((format!("Count is {count}."), json!({"count": count})))
            },
        )
        .await
    }

    #[tool(
        name = "example_wait",
        description = DESCRIPTION_WAIT,
        annotations(title = "Wait", read_only_hint = true, idempotent_hint = true)
    )]
    async fn wait(&self, Parameters(input): Parameters<WaitInput>) -> CallToolResult {
        if input.milliseconds > MAX_WAIT_MILLISECONDS {
            return error_result(format!(
                "milliseconds must be between 0 and {MAX_WAIT_MILLISECONDS} (got {})",
                input.milliseconds
            ));
        }

        run_tool(
            &self.app.work,
            self.permit.clone(),
            self.app.tool_deadline,
            "example_wait",
            "",
            async move {
                tokio::time::sleep(Duration::from_millis(input.milliseconds)).await;

                Ok((
                    format!("Waited {} ms.", input.milliseconds),
                    json!({"waited_ms": input.milliseconds}),
                ))
            },
        )
        .await
    }
}

#[tool_handler(router = self.router, name = "example-mcp")]
impl ServerHandler for ExampleTools {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tools = ExampleTools {
            permit: request_permit(&context),
            ..self.clone()
        };

        call_tool(&self.router, &tools, request, context).await
    }
}

const USAGE: &str = "usage: example-mcp [command]

commands:
  serve          run the MCP server (default)
  set-password   set the owner password for the consent page
  status         show the counter, password and token state (no secrets)
  revoke-tokens  delete all OAuth tokens and registered clients
";
const TOOL_DEADLINE: Duration = Duration::from_secs(40);

/// The command dispatch a service writes for itself: the blocks do the work, the service picks
/// which blocks its commands call. `shutdown` ends `serve`; without it `serve` waits for
/// SIGINT or SIGTERM.
pub async fn run(
    args: Vec<String>,
    mut io: Io,
    getenv: Getenv,
    shutdown: Option<CancellationToken>,
) -> Outcome {
    let command = args.first().map_or("serve", String::as_str);

    if matches!(command, "help" | "-h" | "--help") {
        let _ = write!(io.stdout, "{USAGE}");

        return Outcome::code(0);
    }

    if !matches!(
        command,
        "serve" | "set-password" | "status" | "revoke-tokens"
    ) {
        let _ = write!(io.stderr, "unknown command {command:?}\n{USAGE}");

        return Outcome::code(2);
    }

    match dispatch(command, &mut io, getenv, shutdown).await {
        Ok(lease) => Outcome { code: 0, lease },
        Err(message) => {
            let _ = writeln!(io.stderr, "{} {command}: {message}", SERVICE.command);

            Outcome::code(1)
        }
    }
}

async fn dispatch(
    command: &str,
    io: &mut Io,
    getenv: Getenv,
    shutdown: Option<CancellationToken>,
) -> Result<Option<Lease>, String> {
    let config =
        Config::load(&SERVICE, &*getenv, command == "serve").map_err(|error| error.to_string())?;
    let store = Store::open(&config.data_dir, StoreOptions::default())
        .map_err(|error| error.to_string())?;

    match command {
        "serve" => serve(io, config, store, shutdown).await.map(Some),
        "set-password" => cli::set_password(io, &store).await.map(|()| None),
        "status" => status(io, &store).await.map(|()| None),
        _ => cli::revoke_tokens(io, &store).await.map(|()| None),
    }
}

async fn serve(
    io: &mut Io,
    config: Config,
    store: Store<ExampleState>,
    shutdown: Option<CancellationToken>,
) -> Result<Lease, String> {
    let serving = Serving::start(&SERVICE, config, store, shutdown).await?;
    let app = Arc::new(App {
        store: serving.store.clone(),
        config: serving.config.clone(),
        work: serving.work.clone(),
        now: system_clock(),
        tool_deadline: TOOL_DEADLINE,
    });

    serving.run(io, ExampleTools::factory(app)).await
}

async fn status(io: &mut Io, store: &Store<ExampleState>) -> Result<(), String> {
    let now = Timestamp::now();
    let report = store
        .read(move |state| {
            format!(
                "Count: {}\n{}",
                state.section.count,
                cli::oauth_status(state, now)
            )
        })
        .await
        .map_err(|error| error.to_string())?;

    let _ = write!(io.stdout, "{report}");

    Ok(())
}
