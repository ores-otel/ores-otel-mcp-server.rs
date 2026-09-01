use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one real-process test keeps the exact negotiated catalogs and five-state provider assertion atomic"
)]
async fn real_process_exposes_exact_augmented_catalog_without_stdout_noise() {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_ores-otel-mcp-server"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for key in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "ORE_MCP_GITHUB_TOKEN",
        "ORE_MCP_AWS_ACCOUNT_ID",
        "ORE_MCP_AWS_EKS_CLUSTERS",
        "ORE_MCP_GCP_PROJECT_ID",
        "ORE_MCP_GCP_PROJECT_NUMBER",
        "ORE_MCP_GCP_ACCESS_TOKEN",
        "ORE_MCP_SUPABASE_URL",
        "ORE_MCP_SUPABASE_SERVICE_ROLE_KEY",
        "ORE_MCP_NEON_ORGANIZATION_ID",
        "ORE_MCP_NEON_PROJECT_ID",
        "ORE_MCP_NEON_API_KEY",
        "ORE_MCP_CLOUDFLARE_ZONE",
        "ORE_MCP_CLOUDFLARE_ZONE_ID",
        "ORE_MCP_CLOUDFLARE_API_TOKEN",
        "ORE_MCP_K8S_ENABLED",
        "ORE_MCP_K8S_NAMESPACE",
        "ORE_MCP_NATS_URL",
    ] {
        command.env_remove(key);
    }
    let mut child = command.spawn().expect("spawn MCP server");

    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(
            concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fleet-smoke","version":"1"}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":4,"method":"prompts/list","params":{}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"organization_posture","arguments":{}}}"#,
                "\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write MCP frames");
    drop(stdin);

    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("server exits after stdin EOF")
        .expect("collect output");
    assert!(
        output.status.success(),
        "server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout UTF-8");
    let frames = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("stdout contains JSON-RPC only"))
        .collect::<Vec<_>>();
    let response = |id| {
        frames
            .iter()
            .find(|frame| frame["id"] == id)
            .unwrap_or_else(|| panic!("missing response {id}"))
    };
    let initialize = response(1);
    assert_eq!(
        initialize.pointer("/result/protocolVersion"),
        Some(&Value::String("2025-11-25".to_owned()))
    );
    let instructions = initialize
        .pointer("/result/instructions")
        .and_then(Value::as_str)
        .expect("server instructions");
    for client in [
        "Cursor",
        "ChatGPT/OpenAI",
        "Claude/Anthropic",
        "Gemini",
        "Grok",
        "Qwen",
    ] {
        assert!(
            instructions.contains(client),
            "missing client {client}: {instructions}"
        );
    }
    for provider in [
        "GitHub",
        "AWS",
        "GCP",
        "Supabase",
        "Neon",
        "Cloudflare",
        "k8s-cluster",
        "NATS",
    ] {
        assert!(
            instructions.contains(provider),
            "missing provider {provider}: {instructions}"
        );
    }

    let tools = response(2)
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tools/list array");
    let tool_names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        tool_names,
        [
            "aws_posture",
            "cloudflare_posture",
            "environment_policy",
            "gcp_posture",
            "github_posture",
            "k8s_posture",
            "nats_posture",
            "neon_posture",
            "ores_otel_fleet_map",
            "ores_otel_lifecycle_state",
            "ores_otel_plan",
            "ores_otel_runtime_readiness",
            "ores_otel_safety_boundary",
            "ores_otel_sdk_matrix",
            "ores_otel_shared_platform",
            "ores_otel_signal_contract",
            "org_identity",
            "organization_posture",
            "security_baseline",
            "shared_auth_policy",
            "supabase_posture",
            "telemetry_status",
            "zed_dependency_graph",
        ]
    );
    for tool in tools {
        assert_eq!(
            tool.pointer("/inputSchema/additionalProperties"),
            Some(&Value::Bool(false)),
            "open input schema for {}",
            tool["name"]
        );
        assert_eq!(
            tool.pointer("/annotations/readOnlyHint"),
            Some(&Value::Bool(true)),
            "read-only annotation for {}",
            tool["name"]
        );
        assert_eq!(
            tool.pointer("/annotations/destructiveHint"),
            Some(&Value::Bool(false)),
            "destructive annotation for {}",
            tool["name"]
        );
    }

    let resource_uris = response(3)
        .pointer("/result/resources")
        .and_then(Value::as_array)
        .expect("resources/list array")
        .iter()
        .filter_map(|resource| resource.get("uri").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        resource_uris,
        [
            "contract://ores-otel/mcp-clients",
            "contract://ores-otel/providers",
            "docs://ores-otel-signals",
            "orgmap://ores-otel",
            "schema://ores-otel-envelope",
        ]
    );

    let prompt_names = response(4)
        .pointer("/result/prompts")
        .and_then(Value::as_array)
        .expect("prompts/list array")
        .iter()
        .filter_map(|prompt| prompt.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        prompt_names,
        [
            "dependency_review",
            "deploy_readiness",
            "provider_triage",
            "telemetry_contract_review",
            "telemetry_incident_triage",
        ]
    );

    let posture_text = response(5)
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("organization_posture text");
    let posture: Value = serde_json::from_str(posture_text).expect("posture JSON");
    assert_eq!(posture["providerCount"], 8);
    assert_eq!(posture["readyProviders"], 0);
    assert_eq!(posture["state"], "not_configured");
    assert!(posture["providers"].as_array().is_some_and(|providers| {
        providers
            .iter()
            .all(|provider| provider["state"] == "not_configured")
    }));
}

#[test]
fn architecture_reserves_stdout_and_uses_explicit_low_cardinality_telemetry() {
    let main = include_str!("../src/main.rs");
    let runtime = include_str!("../src/runtime.rs");
    let server = include_str!("../src/server.rs");
    let manifest = include_str!("../Cargo.toml");
    let writes_stdout = |source: &str| {
        source
            .lines()
            .any(|line| line.trim_start().starts_with("println!"))
    };
    assert!(!writes_stdout(main));
    assert!(!writes_stdout(runtime));
    assert!(!writes_stdout(server));
    assert!(server.contains("ToolMetrics"));
    assert!(server.contains("tracing::instrument"));
    assert!(server.contains("skip_all"));
    assert!(!server.contains("mcp.tool.arguments"));
    assert!(!server.contains("mcp.tool.result"));
    assert!(manifest.contains("7db434c7849ad153342e0daaac8a8f6f1d2dea5e"));
    assert!(manifest.contains("377bff1a4e7424eb98377997a232ddc0fc700f59"));
}

#[test]
fn shared_knowledge_names_every_required_boundary() {
    let source = include_str!("../src/knowledge.rs");
    for required in [
        "oreKubernetes",
        "sharedDefinitions",
        "dpm",
        "cloudflareSquarespace",
        "supabase",
        "fiducia",
    ] {
        assert!(
            source.contains(required),
            "missing shared boundary {required}"
        );
    }
}
