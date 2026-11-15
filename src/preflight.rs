//! Read-only, metadata-only telemetry admission preflight.
//! No payload, URL, credential, export, or mutation capabilities are accepted.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

pub const MAX_BATCH_BYTES: u32 = 1_048_576;
pub const MAX_ATTRIBUTE_BYTES: u32 = 16_384;
pub const MAX_ATTRIBUTES: u16 = 64;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TelemetrySignal {
    Logs,
    Traces,
    Metrics,
}

impl TelemetrySignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Traces => "traces",
            Self::Metrics => "metrics",
        }
    }
}

/// Numeric metadata only. Payload contents and arbitrary attributes are prohibited.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightInput {
    pub signal: TelemetrySignal,
    #[schemars(range(min = 1, max = 1_048_576))]
    pub batch_bytes: u32,
    #[schemars(range(min = 0, max = 64))]
    pub attribute_count: u16,
    #[schemars(range(min = 0, max = 16384))]
    pub attribute_bytes: u32,
}

/// Classify local transport-envelope bounds without sending or storing data.
///
/// # Errors
///
/// Rejects empty or oversized batches, cardinality and attribute-budget
/// violations, and attribute bytes exceeding the claimed batch size.
pub fn preflight(input: PreflightInput) -> Result<Value, String> {
    if input.batch_bytes == 0 || input.batch_bytes > MAX_BATCH_BYTES {
        return Err("batch_bytes must be between 1 and 1048576".to_owned());
    }
    if input.attribute_count > MAX_ATTRIBUTES {
        return Err("attribute_count must not exceed 64".to_owned());
    }
    if input.attribute_bytes > MAX_ATTRIBUTE_BYTES {
        return Err("attribute_bytes must not exceed 16384".to_owned());
    }
    if input.attribute_bytes > input.batch_bytes {
        return Err("attribute_bytes must not exceed batch_bytes".to_owned());
    }
    Ok(json!({
        "signal": input.signal.as_str(),
        "admitted": true,
        "batchBytes": input.batch_bytes,
        "attributeCount": input.attribute_count,
        "attributeBytes": input.attribute_bytes,
        "limits": {
            "maxBatchBytes": MAX_BATCH_BYTES,
            "maxAttributes": MAX_ATTRIBUTES,
            "maxAttributeBytes": MAX_ATTRIBUTE_BYTES
        },
        "admissionOnly": true,
        "readOnly": true,
        "executed": false,
        "exported": false
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn input(value: Value) -> PreflightInput {
        serde_json::from_value(value).expect("valid metadata-only input")
    }

    #[test]
    fn accepts_exact_bounds_for_all_three_signals() {
        for signal in ["logs", "traces", "metrics"] {
            let receipt = preflight(input(json!({
                "signal": signal,
                "batch_bytes": MAX_BATCH_BYTES,
                "attribute_count": MAX_ATTRIBUTES,
                "attribute_bytes": MAX_ATTRIBUTE_BYTES
            })))
            .expect("bounded preflight");
            assert_eq!(receipt["signal"], signal);
            assert_eq!(receipt["admitted"], true);
            assert_eq!(receipt["admissionOnly"], true);
            assert_eq!(receipt["executed"], false);
            assert_eq!(receipt["exported"], false);
        }
    }

    #[test]
    fn rejects_empty_and_oversized_batches() {
        for size in [0, MAX_BATCH_BYTES + 1] {
            assert!(
                preflight(input(json!({
                    "signal": "logs",
                    "batch_bytes": size,
                    "attribute_count": 0,
                    "attribute_bytes": 0
                })))
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_excessive_cardinality_and_attribute_bytes() {
        for (count, bytes, size) in [
            (MAX_ATTRIBUTES + 1, 0, 100),
            (0, MAX_ATTRIBUTE_BYTES + 1, MAX_BATCH_BYTES),
            (0, 101, 100),
        ] {
            assert!(
                preflight(input(json!({
                    "signal": "traces",
                    "batch_bytes": size,
                    "attribute_count": count,
                    "attribute_bytes": bytes
                })))
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_untrusted_content() {
        for field in ["payload", "authorization", "endpoint", "attributes"] {
            let mut candidate = json!({
                "signal": "metrics",
                "batch_bytes": 100,
                "attribute_count": 1,
                "attribute_bytes": 10
            });
            candidate[field] = json!("opaque-secret");
            assert!(serde_json::from_value::<PreflightInput>(candidate).is_err());
        }
        assert!(
            serde_json::from_value::<PreflightInput>(json!({
                "signal": "unknown",
                "batch_bytes": 100,
                "attribute_count": 0,
                "attribute_bytes": 0
            }))
            .is_err()
        );
    }
}
