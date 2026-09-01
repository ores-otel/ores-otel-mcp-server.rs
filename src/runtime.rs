//! Transport composition and lifecycle ownership.

use ore_mcp_org_server::run_augmented_stdio;

use crate::{
    flags, parity,
    server::{ORESOTELMCPServer, SERVER_NAME, SERVER_NAMESPACE},
};

/// Initialize telemetry and serve bounded MCP frames on stdio.
///
/// # Errors
///
/// Returns an error when command-line resolution, lifecycle initialization,
/// or MCP transport startup, service, or shutdown fails.
pub async fn run_stdio() -> anyhow::Result<()> {
    let config = flags::resolve().map_err(|error| {
        eprintln!("invalid command-line configuration: {error:#}");
        error
    })?;
    let _telemetry = ores_mcp_server_core_libs::observability::init(SERVER_NAME, SERVER_NAMESPACE);
    let server = ORESOTELMCPServer::from_config(config).map_err(anyhow::Error::msg)?;
    run_augmented_stdio(server, parity::org_spec())
        .await
        .map_err(|error| anyhow::anyhow!("MCP runtime failed: {error}"))?;
    Ok(())
}
