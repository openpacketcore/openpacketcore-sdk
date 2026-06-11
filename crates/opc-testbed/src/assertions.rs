//! Assertion model and engine (RFC 012 §13).
//!
//! Supports protocol state, SBI responses, metrics, and scenario context
//! assertions. Expressions are declarative and should be order-independent
//! unless explicitly marked.
//!
//! Assertions may be written as bare strings (`amf.state == REGISTERED`) or
//! as structured objects (`{ expr: "...", order_independent: true }`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An assertion expression to be evaluated against scenario state or simulator.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Assertion {
    /// The expression, e.g. "amf.ue_context.state == REGISTERED"
    pub expr: String,
    /// Reserved for future use by the scenario executor; currently not evaluated.
    pub order_independent: bool,
}

impl<'de> Deserialize<'de> for Assertion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;

        // Bare string form: "amf.ue_context.state == REGISTERED"
        if let Some(expr) = value.as_str() {
            return Ok(Assertion {
                expr: expr.to_string(),
                order_independent: false,
            });
        }

        // Structured object form.
        let tagged: TaggedAssertion = serde_json::from_value(value)
            .map_err(|e| D::Error::custom(format!("invalid assertion: {e}")))?;
        Ok(Assertion {
            expr: tagged.expr,
            order_independent: tagged.order_independent,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaggedAssertion {
    expr: String,
    #[serde(default)]
    order_independent: bool,
}

/// Basic result of assertion evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionOutcome {
    Pass,
    Fail { reason: &'static str },
    Skipped,
}

/// Evaluate an assertion against a flat state map.
///
/// Supported syntax (minimal): `path.to.key == EXPECTED`.
/// The key must exist in the state map exactly as written; there is no
/// fallback to partial path matching.
pub fn evaluate(assertion: &Assertion, state: &HashMap<String, String>) -> AssertionOutcome {
    let expr = assertion.expr.trim();
    if expr.is_empty() {
        return AssertionOutcome::Fail {
            reason: "empty assertion",
        };
    }

    // Very small expression parser for the common "left == right" form.
    if let Some((left, right)) = parse_equality(expr) {
        let left = left.trim();
        let right = right.trim().trim_matches('"').trim_matches('\'');

        if let Some(actual) = state.get(left) {
            if actual == right {
                AssertionOutcome::Pass
            } else {
                AssertionOutcome::Fail {
                    reason: "value mismatch",
                }
            }
        } else {
            AssertionOutcome::Fail {
                reason: "key not found in context",
            }
        }
    } else {
        // Unknown expression form for skeleton: mark skipped so it does not
        // silently pass complex assertions.
        AssertionOutcome::Skipped
    }
}

fn parse_equality(expr: &str) -> Option<(&str, &str)> {
    let idx = expr.find("==")?;
    Some((&expr[..idx], &expr[idx + 2..]))
}
