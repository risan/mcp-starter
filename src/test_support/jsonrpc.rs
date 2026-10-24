//! A minimal MCP client on reqwest: initialize, tools/list and tools/call over the real HTTP
//! endpoint, so no MCP client feature is compiled into the dev build.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-06-18";

/// The outcome of a tool call.
#[derive(Debug)]
pub struct ToolResult {
    /// Whether the tool reported an error.
    pub is_error: bool,
    /// The text content, joined.
    pub text: String,
    /// The structured content, `null` when there is none.
    pub structured: Value,
}

/// A JSON-RPC client for one MCP endpoint.
#[derive(Clone)]
pub struct McpClient {
    http: reqwest::Client,
    url: String,
    bearer: Option<String>,
    next_id: Arc<AtomicU64>,
}

impl McpClient {
    /// A client for the endpoint at `url`, without a bearer token.
    pub fn new(url: &str) -> McpClient {
        super::install_crypto_provider();

        McpClient {
            http: reqwest::Client::new(),
            url: url.to_string(),
            bearer: None,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// The same client, sending `token` as its bearer.
    pub fn with_bearer(mut self, token: &str) -> McpClient {
        self.bearer = Some(token.to_string());

        self
    }

    /// A request builder with the MCP headers and the bearer, for tests that send raw bodies.
    pub fn request(&self, body: &Value) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .post(&self.url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .body(body.to_string());

        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token);
        }

        request
    }

    /// Sends one JSON-RPC request and returns the whole reply object.
    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let response = self.request(&body).send().await.unwrap();

        assert_eq!(response.status(), 200, "{method}");

        response.json().await.unwrap()
    }

    /// Sends `initialize`.
    pub async fn initialize(&self) -> Value {
        self.rpc(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }),
        )
        .await
    }

    /// The tools the server lists.
    pub async fn list_tools(&self) -> Vec<Value> {
        let reply = self.rpc("tools/list", json!({})).await;

        reply["result"]["tools"].as_array().unwrap().clone()
    }

    /// Calls a tool. A JSON-RPC protocol error counts as a tool error with its message.
    pub async fn call(&self, name: &str, arguments: Value) -> ToolResult {
        let reply = self
            .rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await;

        if let Some(error) = reply.get("error") {
            return ToolResult {
                is_error: true,
                text: error["message"].as_str().unwrap_or_default().to_string(),
                structured: Value::Null,
            };
        }

        let result = &reply["result"];
        let text = result["content"]
            .as_array()
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|part| part["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        ToolResult {
            is_error: result["isError"].as_bool().unwrap_or(false),
            text,
            structured: result["structuredContent"].clone(),
        }
    }
}
