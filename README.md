# ORES OTEL MCP Server

    Read-only MCP diagnostics for ORES telemetry contracts, lifecycle assurance, redaction, and fleet integration. The server is a Rust MCP process over stdio. Stdout is exclusively the JSON-RPC wire; structured diagnostics go to stderr and optional OTLP.

    ## Tools

    - `ores_otel_fleet_map`
- `ores_otel_plan`
- `ores_otel_runtime_readiness`
- `ores_otel_shared_platform`
- `ores_otel_lifecycle_state`
- `ores_otel_safety_boundary`

    Every tool is read-only. Planning accepts a closed workload enum plus bounded numeric fields. The server has no arbitrary URL, command, filesystem, database, GitHub mutation, cluster mutation, or secret-value input.

    ## Product topology

    - `ores.otel.log` — canonical polyglot logging and authenticated telemetry SDKs
- `ores-mcp-server-core-libs.rs` — secure MCP transport, observability, and lifecycle core
- `ores-lib-core` — polyglot security, redaction, and correlation adapters
- `ores-interfaces` — identity, authorization, request, error, and security-event contracts

    ## Security boundary

    - No tool accepts telemetry payloads, arbitrary URLs, credentials, logs, traces, or metrics.
- Shared Auth is an identity boundary and does not grant telemetry authorization.
- Redaction and lifecycle claims are bounded to the immutable shared-core revision.

    The shared core is pinned at `c6101656c8227251d1dbd61df54f03a186b42ade`. It provides bounded MCP framing, explicit OTLP/gRPC traces, metrics and logs, JSON stderr diagnostics, redaction, low-cardinality tool metrics, and the formal runtime lifecycle. Each tool also owns an explicit span with `skip_all`; arguments and results are never recorded. Configuration readiness reports environment-variable presence only and performs no authentication or network request.

    This server contains no authenticated HTTP client. If a future tool adds one, it must use fixed or strictly validated HTTP(S) origins, reject credentials/query/fragment/private/metadata targets, disable redirects and ambient proxies, keep credentials in sensitive headers, cap every response, and add adversarial tests before merge.

    ## Shared platform knowledge

    The bounded `shared_platform` tool documents ORE Kubernetes, shared definitions, dpm, Cloudflare/Squarespace, Supabase, and Fiducia without exposing a mutation or credential surface.

    ## Validate

    ```sh
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-targets --all-features
    cargo build --locked --release
    cargo audit --deny warnings
    ```
