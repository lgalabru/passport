//! MCP server for passport. A thin dispatch layer over `passport-core`: every
//! tool calls into core and serializes its result.

use passport_core::setup::{self, SetupOptions};
use rmcp::{
    ErrorData, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities,
        ServerConfig,
    },
    schemars::{self, JsonSchema},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

const INSTRUCTIONS: &str = "passport is configured from ~/.config/passport/config.yaml. Call \
                            `setup` to create that config and install the passport agent skill \
                            and MCP registration for Claude Code and Codex.";

/// Serve over stdio until the client disconnects.
pub async fn run_server() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let service = PassportMcp::new()
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .map_err(|e| e.to_string())?;
    service
        .waiting()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub struct PassportMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for PassportMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SetupParams {
    /// Skip installing the agent skill (recorded in a new config).
    #[serde(default)]
    pub no_skill: bool,
    /// Skip registering the MCP server with agent CLIs (recorded in a new config).
    #[serde(default)]
    pub no_mcp: bool,
    /// Rewrite an existing config with defaults.
    #[serde(default)]
    pub force: bool,
}

type ToolResult = Result<CallToolResult, ErrorData>;

fn json(value: serde_json::Value) -> ToolResult {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&value).unwrap_or_default(),
    )]))
}

fn fail(message: impl Into<String>) -> ToolResult {
    Ok(CallToolResult::error(vec![ContentBlock::text(
        message.into(),
    )]))
}

#[tool_router]
impl PassportMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Set up passport: write ~/.config/passport/config.yaml (kept if it exists unless force), install the passport agent skill via skills.sh, and register this MCP server with Claude Code and Codex. Returns what each step did; failed steps include a command the user can retry with."
    )]
    async fn setup(&self, Parameters(p): Parameters<SetupParams>) -> ToolResult {
        let opts = SetupOptions {
            no_skill: p.no_skill,
            no_mcp: p.no_mcp,
            force: p.force,
            bin: None,
        };
        let result = tokio::task::spawn_blocking(move || setup::run(&opts))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
        match result {
            Ok(report) => json(serde_json::to_value(&report).unwrap_or_default()),
            Err(e) => fail(e),
        }
    }
}

/// Names of the tools this server exposes, in registration order; used by
/// `passport setup` to tell the user what their agent just gained.
pub fn tool_names() -> Vec<String> {
    PassportMcp::new()
        .tool_router
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect()
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PassportMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_06_18)
            .with_server_info(
                Implementation::new("passport", env!("CARGO_PKG_VERSION")).with_title("Passport"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposes_setup() {
        assert_eq!(super::tool_names(), ["setup"]);
    }
}
