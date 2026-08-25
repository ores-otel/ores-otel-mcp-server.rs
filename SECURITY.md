# Security policy

    Report vulnerabilities privately to the `ores-otel` maintainers. Never include secrets, customer data, source payloads, or exploit material in a public issue.

    ## Runtime boundary

    - stdio is the only transport and stdout is the MCP wire;
    - tools are deterministic, read-only, and fail closed on unknown fields or out-of-range numbers;
    - no tool accepts arbitrary URLs, commands, source payloads, credentials, or mutation instructions;
    - readiness exposes presence booleans only;
    - telemetry excludes arguments, results, identities, secrets, and high-cardinality values.

    - No tool accepts telemetry payloads, arbitrary URLs, credentials, logs, traces, or metrics.
- Shared Auth is an identity boundary and does not grant telemetry authorization.
- Redaction and lifecycle claims are bounded to the immutable shared-core revision.
