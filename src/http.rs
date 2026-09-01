//! Shared-Auth-protected Streamable HTTP entrypoint for remote MCP clients.

use ore_mcp_org_server::run_augmented_http;
use ores_otel_mcp_server::{
    flags, parity,
    server::{ORESOTELMCPServer, SERVER_NAME, SERVER_NAMESPACE},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = flags::resolve().map_err(|error| {
        eprintln!("invalid command-line configuration: {error:#}");
        error
    })?;
    let _telemetry = ores_mcp_server_core_libs::observability::init(SERVER_NAME, SERVER_NAMESPACE);
    let server = ORESOTELMCPServer::from_config(config).map_err(anyhow::Error::msg)?;
    run_augmented_http(server, parity::org_spec()).await
}
