//! Strict, immutable command-line normalization for both MCP transports.

use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use flags2env::BundledFlags2Env;

const DEFAULT_AUDIT_CAPACITY: usize = 128;
const MIN_AUDIT_CAPACITY: usize = 8;
const MAX_AUDIT_CAPACITY: usize = 4_096;

/// Immutable operational configuration resolved once at the argv boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub lifecycle_audit_capacity: usize,
}

/// Resolve process argv and environment without mutating global state.
///
/// # Errors
///
/// Returns an error when the contract cannot be loaded, argv contains an
/// unknown or invalid option, or the resolved audit capacity is out of range.
pub fn resolve() -> Result<RuntimeConfig> {
    let config_path = std::env::current_dir()
        .context("read current working directory")?
        .join(".cli-flags.toml");
    let argv = std::env::args().collect::<Vec<_>>();
    let environment = std::env::vars().collect::<HashMap<_, _>>();
    resolve_from(&argv, &config_path, &environment)
}

fn resolve_from(
    argv: &[String],
    config_path: &Path,
    environment: &HashMap<String, String>,
) -> Result<RuntimeConfig> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        eprintln!(
            "ores-otel-mcp-server options (stderr only; stdout is MCP JSON-RPC):\n  --lifecycle-audit-capacity  ORES_OTEL_MCP_AUDIT_CAPACITY (8-4096)\nCredentials, provider URLs, access tokens, OTLP headers, and kubeconfig remain environment-only."
        );
        bail!("help requested");
    }

    let config_path = config_path
        .to_str()
        .context(".cli-flags.toml path is not valid UTF-8")?;
    let parser = BundledFlags2Env::new();
    parser
        .audit_config(Some(config_path))
        .map_err(|error| anyhow!("flags-2-env configuration audit failed: {error}"))?;
    let parsed = parser
        .parse_structured(argv, Some(config_path))
        .map_err(|error| anyhow!("flags-2-env parse failed: {error}"))?;
    if !parsed.unknown_options.is_empty() {
        bail!(
            "unknown command-line option(s): {}",
            parsed.unknown_options.join(", ")
        );
    }
    if !parsed.errors.is_empty() {
        bail!(
            "invalid command-line value(s): {}",
            parsed.errors.join("; ")
        );
    }

    let raw_capacity = parsed
        .flags
        .get("ORES_OTEL_MCP_AUDIT_CAPACITY")
        .or_else(|| environment.get("ORES_OTEL_MCP_AUDIT_CAPACITY"));
    let lifecycle_audit_capacity = match raw_capacity {
        Some(raw) => raw
            .parse::<usize>()
            .with_context(|| "ORES_OTEL_MCP_AUDIT_CAPACITY must be an integer")?,
        None => DEFAULT_AUDIT_CAPACITY,
    };
    if !(MIN_AUDIT_CAPACITY..=MAX_AUDIT_CAPACITY).contains(&lifecycle_audit_capacity) {
        bail!(
            "ORES_OTEL_MCP_AUDIT_CAPACITY must be between {MIN_AUDIT_CAPACITY} and {MAX_AUDIT_CAPACITY}"
        );
    }
    Ok(RuntimeConfig {
        lifecycle_audit_capacity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cli-flags.toml")
    }

    #[test]
    fn operational_flag_overrides_environment_immutably() {
        let before = std::env::var_os("ORES_OTEL_MCP_AUDIT_CAPACITY");
        let environment =
            HashMap::from([("ORES_OTEL_MCP_AUDIT_CAPACITY".to_owned(), "64".to_owned())]);
        let resolved = resolve_from(
            &[
                "ores-otel-mcp-server".into(),
                "--lifecycle-audit-capacity=256".into(),
            ],
            &config_path(),
            &environment,
        )
        .expect("valid explicit operational flag");
        assert_eq!(resolved.lifecycle_audit_capacity, 256);
        assert_eq!(std::env::var_os("ORES_OTEL_MCP_AUDIT_CAPACITY"), before);
    }

    #[test]
    fn invalid_values_unknown_options_and_secret_flags_fail_closed() {
        for arg in [
            "--lifecycle-audit-capacity=0",
            "--lifecycle-audit-capacity=4097",
            "--github-token=forbidden",
            "--unknown-option=true",
        ] {
            assert!(
                resolve_from(
                    &["ores-otel-mcp-server".into(), arg.into()],
                    &config_path(),
                    &HashMap::new()
                )
                .is_err(),
                "{arg} must fail closed"
            );
        }
    }

    #[test]
    fn default_is_bounded_and_help_never_starts_the_protocol() {
        let resolved = resolve_from(
            &["ores-otel-mcp-server".into()],
            &config_path(),
            &HashMap::new(),
        )
        .expect("valid default");
        assert_eq!(resolved.lifecycle_audit_capacity, DEFAULT_AUDIT_CAPACITY);
        assert!(
            resolve_from(
                &["ores-otel-mcp-server".into(), "--help".into()],
                &config_path(),
                &HashMap::new()
            )
            .is_err()
        );
    }
}
