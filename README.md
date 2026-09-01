# ORES OTEL MCP Server

Read-only, organization-specific MCP diagnostics for telemetry signal
contracts, redaction, correlation, lifecycle assurance, SDK compatibility, and
infrastructure posture. The final MCP `2025-11-25` protocol is exposed over
stdout-pure stdio and OAuth-protected Streamable HTTP at `/mcp`; both
transports expose the exact same tool, resource, and prompt catalog.

Cursor, ChatGPT/OpenAI, Anthropic Claude, Google Gemini, xAI Grok, and Alibaba
Qwen are MCP clients of this server. GitHub, AWS, GCP, Supabase, Neon,
Cloudflare, `ORESoftware/k8s-cluster`, and NATS are bounded read-only provider
integrations behind the shared posture tools. Those roles are deliberately
separate: the server never relays a caller's Shared Auth token to a provider.

## Run

```sh
# Local clients: JSON-RPC on stdout; diagnostics on stderr.
cargo run --locked --bin ores-otel-mcp-server

# Remote clients: Shared-Auth-protected Streamable HTTP at /mcp.
cargo run --locked --bin ores-otel-mcp-http
```

Remote HTTP fails before binding unless its public resource, exact issuer/JWKS,
authorized clients, origin policy, project realm, required scopes/roles, and
AAL2 policy are valid. Local stdio authentication remains the spawning process
boundary. The same `tools/list`, `resources/list`, and `prompts/list` catalogs
are independently tested through the real stdio binary.

## Tools

The shared parity layer contributes these 15 read-only tools to every hardened
organization server:

- `aws_posture`
- `cloudflare_posture`
- `environment_policy`
- `gcp_posture`
- `github_posture`
- `k8s_posture`
- `nats_posture`
- `neon_posture`
- `org_identity`
- `organization_posture`
- `security_baseline`
- `shared_auth_policy`
- `supabase_posture`
- `telemetry_status`
- `zed_dependency_graph`

Every provider result has exactly one honest state: `ready`, `not_configured`,
`degraded`, `unauthorized`, or `forbidden`. Missing configuration is never
reported as success. `organization_posture` composes all eight providers while
retaining each provider's individual evidence and state.

The ORES OTEL domain layer contributes eight additional read-only tools:

- `ores_otel_fleet_map` — exact telemetry repositories and component responsibilities.
- `ores_otel_lifecycle_state` — current formal lifecycle state, monotonic revision, and bounded transition audit.
- `ores_otel_plan` — deterministic telemetry-capacity planning from a closed workload enum and bounded numeric inputs; it never executes the plan.
- `ores_otel_runtime_readiness` — exact protocol, transport, client, Shared Auth, provider-state, and lifecycle configuration.
- `ores_otel_safety_boundary` — explicit prohibited mutation, arbitrary-command, arbitrary-URL, payload, credential, and secret surfaces.
- `ores_otel_sdk_matrix` — required Dart, Rust, and TypeScript SDK capabilities and compatibility policy.
- `ores_otel_shared_platform` — bounded context for Kubernetes, shared definitions, declarative migrations, Cloudflare, Supabase, and Fiducia.
- `ores_otel_signal_contract` — redaction, correlation, cardinality, authentication, backpressure, and lifecycle invariants.

Every input schema rejects unknown fields. Every tool declares read-only,
non-destructive, idempotent annotations. Final tool results are capped at
40,960 bytes; shared provider responses and transport frames have their own
strict bounds.

## Resources and prompts

Domain resources:

- `docs://ores-otel-signals`
- `orgmap://ores-otel`
- `schema://ores-otel-envelope`

The parity layer adds `contract://ores-otel/mcp-clients` and
`contract://ores-otel/providers`; the richer domain organization map wins the
intentional `orgmap://ores-otel` collision.

Domain prompts are `deploy_readiness`, `telemetry_contract_review`, and
`telemetry_incident_triage`. Shared `dependency_review` and `provider_triage`
prompts are also present; the richer ORES OTEL `deploy_readiness` prompt wins
that intentional name collision.

## Configuration

The only CLI option is the non-secret operational
`--lifecycle-audit-capacity` (`ORES_OTEL_MCP_AUDIT_CAPACITY`, default `128`,
range `8..=4096`). It is declared in [`.cli-flags.toml`](.cli-flags.toml),
parsed by `flags-2-env`, resolved immutably at the argv boundary, and passed
inward. Unknown, mistyped, out-of-range, and credential-shaped CLI options fail
closed. Credentials are environment-only because argv is visible in process
listings and shell history.

Shared provider scope is configured only through explicit `ORE_MCP_*` keys:
`ORE_MCP_GITHUB_TOKEN`, `ORE_MCP_AWS_ACCOUNT_ID`,
`ORE_MCP_AWS_EKS_CLUSTERS`, `ORE_MCP_GCP_PROJECT_ID`,
`ORE_MCP_GCP_PROJECT_NUMBER`, `ORE_MCP_GCP_ACCESS_TOKEN`,
`ORE_MCP_SUPABASE_URL`, `ORE_MCP_SUPABASE_SERVICE_ROLE_KEY`,
`ORE_MCP_NEON_ORGANIZATION_ID`, `ORE_MCP_NEON_PROJECT_ID`,
`ORE_MCP_NEON_API_KEY`, `ORE_MCP_CLOUDFLARE_ZONE`,
`ORE_MCP_CLOUDFLARE_ZONE_ID`, `ORE_MCP_CLOUDFLARE_API_TOKEN`,
`ORE_MCP_K8S_ENABLED=1`, `ORE_MCP_K8S_NAMESPACE`, and `ORE_MCP_NATS_URL`.
Each adapter accepts only its exact configured account/project/zone/namespace
or subject scope and returns bounded projections rather than raw provider
responses.

Remote HTTP additionally uses `ORE_MCP_PUBLIC_RESOURCE`, `SHARED_AUTH_ISSUER`,
`SHARED_AUTH_JWKS_URL`, optional `ORE_MCP_OAUTH_CLIENT_IDS` and
`ORE_MCP_ALLOWED_ORIGINS`, and `ORE_MCP_HTTP_BIND` (default
`127.0.0.1:8090`). Shared Auth verification is local ES256/JWKS validation with
exact issuer, audience, authorized-client, project-realm, session, scope, role,
and AAL2 checks. Bearer clients use exact host allowlists, no credentialed
redirects, no ambient proxy, and bounded bodies.

## Security and observability

This server never accepts or exports arbitrary logs, traces, metrics, events,
credentials, payloads, URLs, or commands. It never changes GitHub or cloud
state and never mutates Kubernetes or NATS. Secrets are neither tool inputs nor
outputs and are never logged. The eight domain tools retain explicit
low-cardinality spans and metrics from `ores-otel`; tool arguments and results
are excluded. Stdout is reserved exclusively for MCP JSON-RPC and all
diagnostics go to stderr.

## Validate

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release --all-features
cargo audit --deny warnings
```
