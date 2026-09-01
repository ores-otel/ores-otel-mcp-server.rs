//! Shared fleet knowledge. This is descriptive and exposes no mutation path.

use serde_json::{Value, json};

pub struct ResourceDocument {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mime_type: &'static str,
    pub body: &'static str,
}

pub struct PromptDocument {
    pub name: &'static str,
    pub description: &'static str,
    pub text: &'static str,
}

const RESOURCES: &[ResourceDocument] = &[
    ResourceDocument {
        uri: "docs://ores-otel-signals",
        name: "ORES OTEL signal contract",
        description: "Redaction, correlation, cardinality, lifecycle, authentication, and backpressure rules for logs, traces, and metrics.",
        mime_type: "text/markdown",
        body: "# ORES OTEL signal contract\n\n- Logs, traces, and metrics share stable correlation identifiers but remain distinct signals.\n- Credentials, authorization headers, raw payloads, and unbounded user values are redacted before export.\n- Metric labels and span attributes use explicit low-cardinality allowlists.\n- Export is authenticated independently from application identity and never inherits an MCP caller token.\n- Export queues and retry windows are bounded; backpressure degrades explicitly instead of dropping silently.\n- Runtime lifecycle transitions are revisioned and auditable.\n",
    },
    ResourceDocument {
        uri: "orgmap://ores-otel",
        name: "ORES OTEL organization map",
        description: "Exact repositories, contracts, deployment authority, and shared service boundaries for ORES OTEL.",
        mime_type: "text/markdown",
        body: "# ores-otel organization\n\n- `ores.otel.log`: canonical polyglot logging and authenticated telemetry SDKs\n- `ores-mcp-server-core-libs.rs`: MCP transport, observability, redaction, and lifecycle core\n- `ores-lib-core`: polyglot security, redaction, and correlation adapters\n- `ores-interfaces`: identity, authorization, request, error, and security-event contracts\n- `ores-otel-mcp-server.rs`: read-only diagnostics\n- `ORESoftware/k8s-cluster`: deployment authority\n- `shared-auth`: identity authority, not telemetry authorization\n- `opto-sync`: cross-boundary synchronization\n- `zed-pkg`: dependency intent\n",
    },
    ResourceDocument {
        uri: "schema://ores-otel-envelope",
        name: "ORES OTEL safe envelope outline",
        description: "Bounded JSON-schema outline for correlated, redacted, low-cardinality telemetry envelopes.",
        mime_type: "application/json",
        body: r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"OresTelemetryEnvelopeOutline","type":"object","additionalProperties":false,"required":["signal","serviceName","timestamp","correlationId"],"properties":{"signal":{"enum":["log","trace","metric"]},"serviceName":{"type":"string","minLength":1,"maxLength":128},"timestamp":{"type":"string","format":"date-time"},"correlationId":{"type":"string","minLength":1,"maxLength":128},"severity":{"enum":["trace","debug","info","warn","error","fatal"]},"attributes":{"type":"object","maxProperties":64}}}"#,
    },
];

const PROMPTS: &[PromptDocument] = &[
    PromptDocument {
        name: "deploy_readiness",
        description: "Decide whether the ORES OTEL MCP and telemetry provider stack have sufficient bounded evidence to deploy.",
        text: "Evaluate organization_posture, ores_otel_runtime_readiness, ores_otel_lifecycle_state, ores_otel_signal_contract, and github_posture. Treat not_configured, degraded, unauthorized, and forbidden as distinct states. Verify redaction, low-cardinality attributes, authenticated export, bounded queues, and exact dependency pins before a go/no-go decision.",
    },
    PromptDocument {
        name: "telemetry_contract_review",
        description: "Review one telemetry integration against ORES OTEL signal and SDK compatibility contracts.",
        text: "Use ores_otel_signal_contract, ores_otel_sdk_matrix, zed_dependency_graph, and the docs://ores-otel-signals resource. Check signal separation, correlation, pre-export redaction, low-cardinality labels, authenticated export, bounded retry/backpressure, and Rust/Dart/TypeScript contract parity. Cite evidence and do not ingest raw telemetry.",
    },
    PromptDocument {
        name: "telemetry_incident_triage",
        description: "Triage telemetry-plane degradation without requesting payloads, credentials, or provider mutation.",
        text: "Call organization_posture and dedicated provider posture tools, then correlate ores_otel_lifecycle_state and ores_otel_runtime_readiness. Distinguish missing configuration, authentication, authorization, provider degradation, exporter backpressure, and contract mismatch. Never request raw logs, traces, metrics, tokens, or secret values.",
    },
];

#[must_use]
pub fn shared_platform() -> Value {
    json!({
        "oreKubernetes": {
            "role": "GitOps deployment and runtime topology",
            "diagnosticsOnly": true,
            "clusterMutationExposed": false
        },
        "sharedDefinitions": {
            "role": "shared service and infrastructure contracts",
            "consumerMustPinReviewedRevision": true
        },
        "dpm": {
            "role": "declarative migration planning and verification",
            "databaseMutationExposed": false
        },
        "cloudflareSquarespace": {
            "role": "edge, DNS, and site-handoff context",
            "credentials": "environment only",
            "mutationExposed": false
        },
        "supabase": {
            "role": "data and authentication boundary where adopted",
            "credentials": "environment/header only",
            "payloadTelemetry": false
        },
        "fiducia": {
            "role": "secret and lease delivery boundary",
            "credentials": "environment/header only",
            "secretValuesExposed": false
        }
    })
}

#[must_use]
pub fn signal_contract() -> Value {
    json!({
        "contract": "ores-otel",
        "signals": ["logs", "metrics", "traces"],
        "invariants": [
            {"id": "redact_before_export", "required": true},
            {"id": "exclude_credentials_and_payloads", "required": true},
            {"id": "low_cardinality_allowlist", "required": true},
            {"id": "stable_correlation_identity", "required": true},
            {"id": "telemetry_authorization_is_separate", "required": true},
            {"id": "bounded_queue_and_retry", "required": true},
            {"id": "degradation_is_explicit", "required": true},
            {"id": "lifecycle_is_revisioned", "required": true}
        ],
        "payloadIngestionExposed": false,
        "mutationExposed": false
    })
}

#[must_use]
pub fn sdk_matrix() -> Value {
    json!({
        "schemaAuthority": "ores-otel/ores-interfaces",
        "sdkRepository": "ores-otel/ores.otel.log",
        "internalRuntimes": [
            {"language": "dart", "required": ["logs", "traces", "metrics", "redaction", "correlation", "authenticated_export"]},
            {"language": "rust", "required": ["logs", "traces", "metrics", "redaction", "correlation", "authenticated_export"]},
            {"language": "typescript", "required": ["logs", "traces", "metrics", "redaction", "correlation", "authenticated_export"]}
        ],
        "externalSdkPolicy": "generated contracts may support additional languages without weakening the shared envelope",
        "readOnly": true
    })
}

#[must_use]
pub fn resources() -> &'static [ResourceDocument] {
    RESOURCES
}

#[must_use]
pub fn resource(uri: &str) -> Option<&'static ResourceDocument> {
    RESOURCES.iter().find(|resource| resource.uri == uri)
}

#[must_use]
pub fn prompts() -> &'static [PromptDocument] {
    PROMPTS
}

#[must_use]
pub fn prompt(name: &str) -> Option<&'static PromptDocument> {
    PROMPTS.iter().find(|prompt| prompt.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_knowledge_catalogs_are_exact_sorted_and_bounded() {
        assert_eq!(
            resources().iter().map(|item| item.uri).collect::<Vec<_>>(),
            [
                "docs://ores-otel-signals",
                "orgmap://ores-otel",
                "schema://ores-otel-envelope"
            ]
        );
        assert_eq!(
            prompts().iter().map(|item| item.name).collect::<Vec<_>>(),
            [
                "deploy_readiness",
                "telemetry_contract_review",
                "telemetry_incident_triage"
            ]
        );
        assert!(resources().iter().all(|item| item.body.len() < 16_384));
        assert_eq!(signal_contract()["payloadIngestionExposed"], false);
        assert_eq!(sdk_matrix()["readOnly"], true);
    }
}
