//! Typed, read-only MCP tool, resource, and prompt routing.

use std::sync::Arc;

use ores_mcp_server_core_libs::observability::{ToolClass, ToolMetrics, ToolOutcome};
use ores_mcp_server_core_libs::state_machine::{LifecycleController, LifecycleEvent};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
        ListResourcesResult, PaginatedRequestParams, Prompt, PromptMessage,
        ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, Role,
        ServerCapabilities, ServerInfo, ToolAnnotations,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    domain::{self, PlanInput},
    flags::RuntimeConfig,
    knowledge,
};

pub const SERVER_NAME: &str = "ores-otel-mcp-server";
pub const SERVER_NAMESPACE: &str = "ores-otel";
const MAX_TOOL_OUTPUT_BYTES: usize = 40_960;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

#[derive(Clone)]
pub struct ORESOTELMCPServer {
    tool_router: ToolRouter<Self>,
    metrics: ToolMetrics,
    lifecycle: Arc<LifecycleController>,
    lifecycle_audit_capacity: usize,
}

impl ORESOTELMCPServer {
    /// Build one ready, bounded server from immutable boundary configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle controller cannot be created or
    /// its formally checked startup transitions fail.
    pub fn from_config(config: RuntimeConfig) -> Result<Self, String> {
        let lifecycle = LifecycleController::new(config.lifecycle_audit_capacity)
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(LifecycleEvent::Start)
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(LifecycleEvent::Started)
            .map_err(|error| error.to_string())?;

        let mut tool_router = Self::tool_router();
        for route in tool_router.map.values_mut() {
            route.attr.annotations = Some(
                ToolAnnotations::new()
                    .read_only(true)
                    .destructive(false)
                    .idempotent(true)
                    .open_world(false),
            );
        }
        Ok(Self {
            tool_router,
            metrics: ToolMetrics::global(),
            lifecycle: Arc::new(lifecycle),
            lifecycle_audit_capacity: config.lifecycle_audit_capacity,
        })
    }
}

#[tool_router]
impl ORESOTELMCPServer {
    #[tool(
        description = "Return the ORES OTEL-owned repository topology and component roles. Pure, local, and read-only."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_fleet_map", mcp.tool.class = "inventory"))]
    fn ores_otel_fleet_map(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Inventory);
        let output = render(&domain::fleet_map());
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }

    #[tool(
        description = "Calculate a bounded, deterministic telemetry plan from a closed workload enum and numeric units. Never executes, exports, or mutates anything."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_plan", mcp.tool.class = "details"))]
    fn ores_otel_plan(&self, Parameters(input): Parameters<PlanInput>) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Details);
        let result = domain::plan(input).and_then(|value| render(&value));
        timer.finish(if result.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Rejected
        });
        result
    }

    #[tool(
        description = "Report the exact MCP protocol, transports, clients, Shared Auth boundary, provider states, and bounded lifecycle capacity."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_runtime_readiness", mcp.tool.class = "health"))]
    fn ores_otel_runtime_readiness(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Health);
        let output = render(&domain::runtime_readiness(self.lifecycle_audit_capacity));
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }

    #[tool(
        description = "Return the exact redaction, correlation, cardinality, authentication, backpressure, and lifecycle invariants for ORES telemetry. Pure and read-only."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_signal_contract", mcp.tool.class = "details"))]
    fn ores_otel_signal_contract(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Details);
        let output = render(&knowledge::signal_contract());
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }

    #[tool(
        description = "Return the required Dart, Rust, and TypeScript telemetry SDK capabilities and compatibility policy. Pure, bounded, and read-only."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_sdk_matrix", mcp.tool.class = "details"))]
    fn ores_otel_sdk_matrix(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Details);
        let output = render(&knowledge::sdk_matrix());
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }

    #[tool(
        description = "Return bounded shared knowledge for ORE Kubernetes, shared definitions, dpm, Cloudflare/Squarespace, Supabase, and Fiducia. Descriptive only."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_shared_platform", mcp.tool.class = "inventory"))]
    fn ores_otel_shared_platform(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Inventory);
        let output = render(&knowledge::shared_platform());
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }

    #[tool(
        description = "Return the formal runtime lifecycle state, monotonic revision, and bounded transition audit. Callers cannot trigger transitions."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_lifecycle_state", mcp.tool.class = "health"))]
    fn ores_otel_lifecycle_state(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Health);
        let result = self
            .lifecycle
            .snapshot_and_audit()
            .map_err(|error| error.to_string())
            .and_then(|(snapshot, audit)| {
                render(&serde_json::json!({
                    "state": snapshot.state(),
                    "revision": snapshot.revision(),
                    "transitions": audit,
                    "readOnly": true
                }))
            });
        timer.finish(if result.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        result
    }

    #[tool(
        description = "Return the ORES OTEL-specific safety and privacy boundary. Pure, local, and read-only."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "ores_otel_safety_boundary", mcp.tool.class = "inventory"))]
    fn ores_otel_safety_boundary(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> Result<String, String> {
        let timer = self.metrics.start(ToolClass::Inventory);
        let output = render(&domain::safety_boundary());
        timer.finish(if output.is_ok() {
            ToolOutcome::Ok
        } else {
            ToolOutcome::Error
        });
        output
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ORESOTELMCPServer {
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(
            knowledge::resources()
                .iter()
                .map(|resource| {
                    Resource::new(resource.uri, resource.name)
                        .with_description(resource.description)
                        .with_mime_type(resource.mime_type)
                })
                .collect(),
        ))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let resource = knowledge::resource(&request.uri)
            .ok_or_else(|| McpError::resource_not_found("unknown ORES OTEL resource", None))?;
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(resource.body, resource.uri).with_mime_type(resource.mime_type),
        ]))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult::with_all_items(
            knowledge::prompts()
                .iter()
                .map(|prompt| Prompt::new(prompt.name, Some(prompt.description), None))
                .collect(),
        ))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        let prompt = knowledge::prompt(&request.name)
            .ok_or_else(|| McpError::invalid_params("unknown ORES OTEL prompt", None))?;
        Ok(
            GetPromptResult::new(vec![PromptMessage::new_text(Role::User, prompt.text)])
                .with_description(prompt.description),
        )
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")).with_title("ORES OTEL MCP Server"))
            .with_instructions("Read-only ORES OTEL diagnostics for telemetry signal contracts, redaction, correlation, SDK compatibility, and provider posture. The exact same MCP 2025-11-25 catalog is served to Cursor, ChatGPT/OpenAI, Claude/Anthropic, Gemini, Grok, and Qwen over stdio or Shared-Auth-protected Streamable HTTP. Start with organization_posture for GitHub, AWS, GCP, Supabase, Neon, Cloudflare, ORESoftware/k8s-cluster, and NATS; missing configuration is never success.")
    }
}

fn render(value: &Value) -> Result<String, String> {
    let rendered = serde_json::to_string(value)
        .map_err(|_| "failed to serialize bounded ORES OTEL result".to_owned())?;
    enforce_output_bound(rendered)
}

fn enforce_output_bound(rendered: String) -> Result<String, String> {
    if rendered.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err("ORES OTEL tool result exceeded the fixed output bound".to_owned());
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_prefixed_tool_catalog_is_exposed() {
        let server = ORESOTELMCPServer::from_config(RuntimeConfig {
            lifecycle_audit_capacity: 8,
        })
        .expect("valid server");
        let names = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "ores_otel_fleet_map",
                "ores_otel_lifecycle_state",
                "ores_otel_plan",
                "ores_otel_runtime_readiness",
                "ores_otel_safety_boundary",
                "ores_otel_sdk_matrix",
                "ores_otel_shared_platform",
                "ores_otel_signal_contract",
            ]
        );
    }

    #[test]
    fn metadata_is_read_only_and_namespaced() {
        let server = ORESOTELMCPServer::from_config(RuntimeConfig {
            lifecycle_audit_capacity: 8,
        })
        .expect("valid server");
        let info = server.get_info();
        assert_eq!(info.server_info.name, SERVER_NAME);
        assert!(
            info.instructions
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().contains("read-only"))
        );
        assert!(server.tool_router.list_all().iter().all(|tool| {
            tool.annotations.as_ref().is_some_and(|annotations| {
                annotations.read_only_hint == Some(true)
                    && annotations.destructive_hint == Some(false)
                    && annotations.idempotent_hint == Some(true)
            })
        }));
    }

    #[test]
    fn output_bound_fails_closed() {
        assert!(enforce_output_bound("x".repeat(MAX_TOOL_OUTPUT_BYTES)).is_ok());
        assert!(enforce_output_bound("x".repeat(MAX_TOOL_OUTPUT_BYTES + 1)).is_err());
    }
}
