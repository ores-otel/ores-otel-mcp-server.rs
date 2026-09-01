//! Exact fleet-parity identity and dependency graph for ORES OTEL.

use ore_mcp_org_server::OrgSpec;

const DEPENDENCIES: &[&str] = &[
    "ORESoftware/k8s-cluster",
    "ORESoftware/k8s-libs-and-shared-defs",
    "ORESoftware/mcp-rust-libs",
    "declarative-migrations/dpm",
    "opto-sync/opto-sync-lib",
    "ores-otel/ores-interfaces",
    "ores-otel/ores-lib-core",
    "ores-otel/ores-mcp-server-core-libs.rs",
    "ores-otel/ores.otel.log",
    "shared-auth/shared-auth-clients",
    "shared-auth/shared-auth-interfaces",
    "shared-auth/shared-auth-lib",
    "zed-pkg/zed-cli",
];

/// Exact read operations implemented by the shared provider adapters.
pub const PROVIDER_OPERATIONS: &[&str] = &[
    "read_auth_settings",
    "read_caller_identity",
    "read_data_api_schema",
    "read_dependency_snapshot",
    "read_deployments",
    "read_dns_records",
    "read_eks_clusters",
    "read_enabled_services",
    "read_latest_workflow_run",
    "read_organization",
    "read_pods",
    "read_project",
    "read_project_branches",
    "read_projects",
    "read_service_snapshot",
    "read_zone",
];

/// Return the immutable organization, repository, package, and dependency identity.
#[must_use]
pub fn org_spec() -> OrgSpec {
    OrgSpec {
        organization: "ores-otel",
        repository: "ores-otel/ores-otel-mcp-server.rs",
        service_name: "ores-otel-mcp-server",
        package_name: env!("CARGO_PKG_NAME"),
        dependencies: DEPENDENCIES,
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_dependencies_and_provider_contract_are_exact() {
        let spec = org_spec();
        assert_eq!(spec.organization, "ores-otel");
        assert_eq!(spec.repository, "ores-otel/ores-otel-mcp-server.rs");
        assert!(DEPENDENCIES.contains(&"ores-otel/ores.otel.log"));
        assert!(DEPENDENCIES.contains(&"ores-otel/ores-mcp-server-core-libs.rs"));
        assert!(DEPENDENCIES.contains(&"shared-auth/shared-auth-lib"));
        assert!(DEPENDENCIES.contains(&"ORESoftware/k8s-cluster"));
        assert_eq!(PROVIDER_OPERATIONS.len(), 16);
        assert!(PROVIDER_OPERATIONS.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
