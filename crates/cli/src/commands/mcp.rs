use clap::Args;
use passport_core::{CoreError, Result};

/// Serve the passport MCP server over stdio.
#[derive(Args, Debug, Default)]
pub struct McpCommand {}

impl McpCommand {
    pub fn execute(&self) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| CoreError::message(format!("failed to start runtime: {e}")))?;
        rt.block_on(passport_mcp::run_server())
            .map_err(CoreError::message)
    }
}
