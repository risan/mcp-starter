//! Helpers for the tool handler a service writes with rmcp: running a tool body as detached
//! work with a deadline, building results, and turning bad input into a tool error.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::http::request::Parts;
use jiff::Timestamp;
use jiff::civil::Date;
use rmcp::handler::server::tool::{ToolCallContext, ToolRouter};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use serde_json::Value;

use crate::config::Config;
use crate::work::{ConnPermit, Work};

/// What a tool body returns: the summary line and the structured output, or the error text.
pub type ToolOutcome = Result<(String, Value), String>;

/// Runs `body` as detached, tracked work holding the request's connection slot, and waits for
/// it until `deadline`. A dropped request or a late reply never cancels the body.
///
/// A body that is not done at the deadline gives a tool error
/// `"{tool} did not finish within {deadline:?}{timeout_note}"`: a write passes a note that
/// tells the model to check whether the change landed, a read passes `""`.
pub async fn run_tool<F>(
    work: &Arc<Work>,
    permit: ConnPermit,
    deadline: Duration,
    tool: &str,
    timeout_note: &str,
    body: F,
) -> CallToolResult
where
    F: Future<Output = ToolOutcome> + Send + 'static,
{
    let handle = match work.spawn(async move {
        let _slot = permit;

        body.await
    }) {
        Ok(handle) => handle,
        Err(shutting_down) => return error_result(shutting_down.to_string()),
    };

    match tokio::time::timeout(deadline, handle).await {
        Ok(Ok(Ok((summary, output)))) => success_result(summary, output),
        Ok(Ok(Err(message))) => error_result(message),
        Ok(Err(_)) => error_result(format!("{tool} failed unexpectedly")),
        Err(_) => error_result(format!(
            "{tool} did not finish within {deadline:?}{timeout_note}"
        )),
    }
}

/// A successful result: structured output, and the same JSON after the summary in the text,
/// because some clients show the model only the text content.
pub fn success_result(summary: String, output: Value) -> CallToolResult {
    let mut result = CallToolResult::structured(Value::Null);

    result.content = vec![ContentBlock::text(format!("{summary}\n{output}"))];
    result.structured_content = Some(output);

    result
}

/// A tool error with a plain message.
pub fn error_result(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

/// The connection slot of the request being served, to hand to [`run_tool`]. Requests that
/// do not come through the server's accept loop carry none.
pub fn request_permit(context: &RequestContext<RoleServer>) -> ConnPermit {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<ConnPermit>())
        .cloned()
        .unwrap_or_default()
}

/// Calls the tool the request names. Input that does not fit a tool's schema comes back as a
/// tool error the model can read and fix, instead of an opaque protocol error.
///
/// Meant for the body of [`rmcp::ServerHandler::call_tool`]; `handler` is the service's
/// handler, usually a copy that holds [`request_permit`] of this request.
pub async fn call_tool<T>(
    router: &ToolRouter<T>,
    handler: &T,
    request: CallToolRequestParams,
    context: RequestContext<RoleServer>,
) -> Result<CallToolResponse, ErrorData>
where
    T: Send + Sync + 'static,
{
    let call = ToolCallContext::new(handler, request, context);

    match router.call(call).await {
        Err(error) if error.code == ErrorCode::INVALID_PARAMS => {
            Ok(error_result(error.message.to_string()).into())
        }
        other => other,
    }
}

/// The date a tool works on: `date` in strict `YYYY-MM-DD`, or today in the configured zone
/// when it is `None` or empty.
pub fn date_or_today(config: &Config, now: Timestamp, date: Option<&str>) -> Result<Date, String> {
    let Some(date) = date.filter(|date| !date.is_empty()) else {
        return Ok(now.to_zoned(config.tz.clone()).date());
    };

    match date.parse::<Date>() {
        Ok(parsed) if parsed.to_string() == date => Ok(parsed),
        _ => Err(format!("invalid date {date:?}: use YYYY-MM-DD")),
    }
}

#[cfg(test)]
mod tests {
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::ServiceInfo;

    const INFO: ServiceInfo = ServiceInfo {
        command: "example-mcp",
        display_name: "Example",
        env_prefix: "EXAMPLE_MCP_",
        default_listen: "127.0.0.1:8090",
        default_data_dir: "/var/lib/example-mcp",
        default_tz: "Asia/Jakarta",
        scope: "example",
        favicon: &[],
    };

    fn config() -> Config {
        Config::load(&INFO, &|_| String::new(), false).unwrap()
    }

    #[test]
    fn date_or_today_strict() {
        let config = config();
        let now: Timestamp = "2026-10-23T18:30:00Z".parse().unwrap();

        for bad in ["2026-02-30", "2026-1-5", "26-01-05", "today", " 2026-01-05"] {
            let error = date_or_today(&config, now, Some(bad)).unwrap_err();

            assert!(error.contains("use YYYY-MM-DD"), "{bad}: {error}");
        }

        assert_eq!(
            date_or_today(&config, now, Some("2026-01-05"))
                .unwrap()
                .to_string(),
            "2026-01-05"
        );

        for missing in [None, Some("")] {
            assert_eq!(
                date_or_today(&config, now, missing).unwrap().to_string(),
                "2026-10-24",
                "{missing:?}"
            );
        }
    }

    async fn run_slow(deadline: Duration, note: &str) -> CallToolResult {
        let work = Work::new(TaskTracker::new());

        run_tool(
            &work,
            ConnPermit::default(),
            deadline,
            "example_wait",
            note,
            async {
                tokio::time::sleep(Duration::from_secs(2)).await;

                Ok(("done".to_string(), Value::Null))
            },
        )
        .await
    }

    fn text_of(result: &CallToolResult) -> String {
        serde_json::to_value(result).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn run_tool_timeout_text() {
        let result = run_slow(Duration::from_millis(200), "").await;

        assert_eq!(result.is_error, Some(true));
        assert_eq!(text_of(&result), "example_wait did not finish within 200ms");

        let result = run_slow(Duration::from_millis(200), "; check before retrying").await;

        assert_eq!(
            text_of(&result),
            "example_wait did not finish within 200ms; check before retrying"
        );
    }

    #[tokio::test]
    async fn run_tool_success_and_error() {
        let work = Work::new(TaskTracker::new());
        let ok = run_tool(
            &work,
            ConnPermit::default(),
            Duration::from_secs(1),
            "t",
            "",
            async { Ok(("summary".to_string(), serde_json::json!({"a": 1}))) },
        )
        .await;
        let failed = run_tool(
            &work,
            ConnPermit::default(),
            Duration::from_secs(1),
            "t",
            "",
            async { Err("nope".to_string()) },
        )
        .await;

        assert_ne!(ok.is_error, Some(true));
        assert_eq!(text_of(&ok), "summary\n{\"a\":1}");
        assert_eq!(ok.structured_content, Some(serde_json::json!({"a": 1})));
        assert_eq!(text_of(&failed), "nope");
        assert_eq!(failed.is_error, Some(true));
    }

    #[tokio::test]
    async fn run_tool_refused_after_shutdown() {
        let work = Work::new(TaskTracker::new());

        work.begin_shutdown();

        let result = run_tool(
            &work,
            ConnPermit::default(),
            Duration::from_secs(1),
            "t",
            "",
            async { Ok((String::new(), Value::Null)) },
        )
        .await;

        assert!(text_of(&result).contains("server is shutting down"));
    }
}
