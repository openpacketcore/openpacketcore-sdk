//! Declarative, idempotency-aware retry and exponential-backoff policy for
//! outbound SBI requests (RFC 007 §12).
//!
//! The central invariant: non-idempotent requests are **never** retried
//! unless they carry an `idempotency-key` header. Policies are constructed
//! programmatically or parsed from the `key=value;...` string form emitted
//! by canonical YANG config (delays are expressed in milliseconds there).

use crate::headers::HEADER_IDEMPOTENCY_KEY;
use http::{Method, Request, StatusCode};
use std::{str::FromStr, time::Duration};
use thiserror::Error;

/// Randomization applied to the exponential backoff delay so that many
/// consumers failing at once do not retry in lockstep against an already
/// struggling producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jitter {
    /// No randomization: the deterministic capped exponential delay is used
    /// as-is. Predictable, but offers no thundering-herd protection.
    None,
    /// Full jitter: a uniform random delay in `[0, computed_delay)`. The
    /// actual sleep can be far shorter than the nominal backoff, including
    /// zero.
    Full,
    /// Equal jitter: half the computed delay is guaranteed, the other half
    /// is uniform random, i.e. `[delay/2, delay)`. Bounds the minimum wait
    /// while still de-synchronizing retries.
    Equal,
}

impl FromStr for Jitter {
    type Err = RetryPolicyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::None),
            "full" => Ok(Self::Full),
            "equal" => Ok(Self::Equal),
            _ => Err(RetryPolicyParseError::InvalidJitter(value.to_owned())),
        }
    }
}

/// Classification of a completed request attempt, fed into
/// `RetryPolicy::should_retry` to decide whether another attempt is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    /// An HTTP response was received with this status; retried only if the
    /// status appears in `RetryPolicy::retry_on_status`.
    Status(StatusCode),
    /// No HTTP response was received (connect failure, TLS failure, timeout,
    /// or HTTP/2 stream reset); retried only if
    /// `RetryPolicy::retry_on_transport_error` is set.
    TransportError,
}

/// Declarative retry policy for outbound SBI requests (RFC 007 §12.1):
/// capped exponential backoff with configurable jitter, gated on response
/// status / transport errors and on request idempotency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempt budget including the first attempt; `should_retry`
    /// returns `false` once `attempt >= max_attempts`, so e.g. `3` means at
    /// most two retries after the initial request.
    pub max_attempts: u8,
    /// Nominal delay before the first retry; subsequent retries double it
    /// (`base_delay * 2^(attempt-1)`) before capping and jitter.
    pub base_delay: Duration,
    /// Upper bound applied to the exponential delay **before** jitter; with
    /// `Jitter::Full` the actual sleep may still be anywhere below this cap.
    pub max_delay: Duration,
    /// Randomization strategy applied to the capped exponential delay.
    pub jitter: Jitter,
    /// HTTP statuses considered retryable. `RetryPolicy::new` seeds this
    /// with 429 (rate limited) and 503 (overloaded) per RFC 007 §13.2;
    /// any status not listed fails the request immediately.
    pub retry_on_status: Vec<StatusCode>,
    /// Whether attempts that produced no HTTP response at all (connect/TLS
    /// failure, timeout, stream reset) may be retried.
    pub retry_on_transport_error: bool,
}

impl RetryPolicy {
    /// Build a policy with the given attempt budget and backoff shape, using
    /// the default retryable set: statuses 429 and 503, plus transport
    /// errors. Use the struct fields directly for non-default sets.
    pub fn new(
        max_attempts: u8,
        base_delay: Duration,
        max_delay: Duration,
        jitter: Jitter,
    ) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay,
            jitter,
            retry_on_status: vec![
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ],
            retry_on_transport_error: true,
        }
    }

    /// Compute the sleep before the given attempt number.
    ///
    /// `attempt` is 1-based for retries: attempt `0` returns
    /// `Duration::ZERO`, attempt `n >= 1` yields
    /// `min(base_delay * 2^(n-1), max_delay)` with the configured jitter
    /// applied afterwards (so `Jitter::Full` can shrink the wait below
    /// `base_delay`, down to zero). Saturating arithmetic prevents overflow
    /// for large attempt counts.
    pub fn backoff_delay(&self, attempt: u8) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1) as u32);
        let base_ns = self.base_delay.as_nanos();
        let calculated_ns = base_ns.saturating_mul(factor as u128);

        let calculated = if calculated_ns > self.max_delay.as_nanos() {
            self.max_delay
        } else {
            Duration::from_nanos(calculated_ns as u64)
        };

        match self.jitter {
            Jitter::None => calculated,
            Jitter::Full => {
                let ms = calculated.as_millis() as u64;
                if ms == 0 {
                    Duration::ZERO
                } else {
                    let rand_ms = rand::random_range(0..ms);
                    Duration::from_millis(rand_ms)
                }
            }
            Jitter::Equal => {
                let half = calculated / 2;
                let half_ms = half.as_millis() as u64;
                if half_ms == 0 {
                    half
                } else {
                    let rand_ms = rand::random_range(0..half_ms);
                    half + Duration::from_millis(rand_ms)
                }
            }
        }
    }

    /// Decide whether the request may be attempted again after `outcome`.
    ///
    /// Returns `false` (fail-fast) when any of these hold:
    /// - the attempt budget is exhausted (`attempt >= max_attempts`),
    /// - the request is not retryable: a non-idempotent method without an
    ///   `idempotency-key` header (RFC 007 §12.1 — duplicate side effects
    ///   are considered worse than a failed call),
    /// - the outcome is a status not listed in `retry_on_status`, or a
    ///   transport error while `retry_on_transport_error` is `false`.
    pub fn should_retry<B>(
        &self,
        request: &Request<B>,
        attempt: u8,
        outcome: RetryOutcome,
    ) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }

        if !is_request_retryable(request) {
            return false;
        }

        match outcome {
            RetryOutcome::Status(status) => self.retry_on_status.contains(&status),
            RetryOutcome::TransportError => self.retry_on_transport_error,
        }
    }
}

/// Whether a request is safe to retry at all: either its method is
/// idempotent per RFC 9110, or it is a `POST` carrying an `idempotency-key`
/// header that lets the producer deduplicate replays (RFC 007 §12.1).
/// `PATCH` and key-less `POST` requests are never retryable.
pub fn is_request_retryable<B>(request: &Request<B>) -> bool {
    is_method_idempotent(request.method())
        || (request.method() == Method::POST
            && request
                .headers()
                .contains_key(http::header::HeaderName::from_static(
                    HEADER_IDEMPOTENCY_KEY,
                )))
}

/// Whether the HTTP method is idempotent per RFC 9110 §9.2.2:
/// `GET`/`HEAD`/`PUT`/`DELETE`/`OPTIONS`/`TRACE`. `POST` and `PATCH` are
/// not, and custom methods are conservatively treated as non-idempotent.
pub fn is_method_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

impl FromStr for RetryPolicy {
    type Err = RetryPolicyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut max_attempts = None;
        let mut base_delay = None;
        let mut max_delay = None;
        let mut jitter = None;
        let mut retry_on_status = None;
        let mut retry_on_transport_error = None;

        for segment in value
            .split(';')
            .filter(|segment| !segment.trim().is_empty())
        {
            let (key, raw_value) = segment
                .split_once('=')
                .ok_or_else(|| RetryPolicyParseError::InvalidSegment(segment.to_owned()))?;
            let key = key.trim();
            let raw_value = raw_value.trim();

            match key {
                "max_attempts" => {
                    max_attempts = Some(raw_value.parse::<u8>().map_err(|_| {
                        RetryPolicyParseError::InvalidU8 {
                            field: "max_attempts",
                            value: raw_value.to_owned(),
                        }
                    })?);
                }
                "base_delay_ms" => {
                    base_delay = Some(parse_duration_millis("base_delay_ms", raw_value)?);
                }
                "max_delay_ms" => {
                    max_delay = Some(parse_duration_millis("max_delay_ms", raw_value)?);
                }
                "jitter" => {
                    jitter = Some(raw_value.parse::<Jitter>()?);
                }
                "retry_on_status" => {
                    let statuses = if raw_value.is_empty() {
                        Vec::new()
                    } else {
                        raw_value
                            .split(',')
                            .map(|status| parse_status_code(status.trim()))
                            .collect::<Result<Vec<_>, _>>()?
                    };
                    retry_on_status = Some(statuses);
                }
                "retry_on_transport_error" => {
                    retry_on_transport_error =
                        Some(parse_bool_strict("retry_on_transport_error", raw_value)?);
                }
                _ => return Err(RetryPolicyParseError::UnknownField(key.to_owned())),
            }
        }

        let policy = Self {
            max_attempts: max_attempts
                .ok_or(RetryPolicyParseError::MissingField("max_attempts"))?,
            base_delay: base_delay.ok_or(RetryPolicyParseError::MissingField("base_delay_ms"))?,
            max_delay: max_delay.ok_or(RetryPolicyParseError::MissingField("max_delay_ms"))?,
            jitter: jitter.ok_or(RetryPolicyParseError::MissingField("jitter"))?,
            retry_on_status: retry_on_status
                .ok_or(RetryPolicyParseError::MissingField("retry_on_status"))?,
            retry_on_transport_error: retry_on_transport_error.ok_or(
                RetryPolicyParseError::MissingField("retry_on_transport_error"),
            )?,
        };

        if policy.base_delay > policy.max_delay {
            return Err(RetryPolicyParseError::InvalidDurationOrder {
                base_delay_ms: policy.base_delay.as_millis().to_string(),
                max_delay_ms: policy.max_delay.as_millis().to_string(),
            });
        }

        Ok(policy)
    }
}

fn parse_duration_millis(
    field: &'static str,
    value: &str,
) -> Result<Duration, RetryPolicyParseError> {
    let millis = value
        .parse::<u64>()
        .map_err(|_| RetryPolicyParseError::InvalidU64 {
            field,
            value: value.to_owned(),
        })?;
    Ok(Duration::from_millis(millis))
}

fn parse_status_code(value: &str) -> Result<StatusCode, RetryPolicyParseError> {
    let raw = value
        .parse::<u16>()
        .map_err(|_| RetryPolicyParseError::InvalidStatusCode {
            value: value.to_owned(),
        })?;
    StatusCode::from_u16(raw).map_err(|_| RetryPolicyParseError::InvalidStatusCode {
        value: value.to_owned(),
    })
}

fn parse_bool_strict(field: &'static str, value: &str) -> Result<bool, RetryPolicyParseError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(RetryPolicyParseError::InvalidBoolean {
            field,
            value: value.to_owned(),
        }),
    }
}

/// Rejection produced when parsing the `key=value;...` retry-policy string
/// form (fields: `max_attempts`, `base_delay_ms`, `max_delay_ms`, `jitter`,
/// `retry_on_status`, `retry_on_transport_error`).
///
/// Parsing is strict: every field is mandatory, unknown keys are errors, and
/// no defaults are silently substituted, so a config typo cannot weaken the
/// retry policy unnoticed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RetryPolicyParseError {
    /// A `;`-separated segment did not have the `key=value` shape.
    #[error("retry policy segment must be key=value: {0}")]
    InvalidSegment(String),
    /// A mandatory field was absent; all six fields must be spelled out.
    #[error("retry policy is missing required field '{0}'")]
    MissingField(&'static str),
    /// `max_attempts` was not a valid `u8` (0–255).
    #[error("retry policy field '{field}' must be a u8, got '{value}'")]
    InvalidU8 {
        /// Name of the offending field.
        field: &'static str,
        /// The rejected raw value.
        value: String,
    },
    /// A delay field was not a valid `u64` **millisecond** count.
    #[error("retry policy field '{field}' must be a u64 millisecond value, got '{value}'")]
    InvalidU64 {
        /// Name of the offending field.
        field: &'static str,
        /// The rejected raw value.
        value: String,
    },
    /// `jitter` was not one of `none`, `full`, or `equal`.
    #[error("retry policy field 'jitter' is invalid: {0}")]
    InvalidJitter(String),
    /// A boolean field was not exactly `true` or `false` (no `1`/`yes`
    /// aliases are accepted).
    #[error("retry policy field '{field}' must be 'true' or 'false', got '{value}'")]
    InvalidBoolean {
        /// Name of the offending field.
        field: &'static str,
        /// The rejected raw value.
        value: String,
    },
    /// An entry in the comma-separated `retry_on_status` list was not a
    /// valid HTTP status code (100–999).
    #[error("retry policy status code is invalid: '{value}'")]
    InvalidStatusCode {
        /// The rejected raw status value.
        value: String,
    },
    /// The string contained a key outside the six recognized fields.
    #[error("retry policy contains unknown field '{0}'")]
    UnknownField(String),
    /// `base_delay_ms` exceeded `max_delay_ms`, which would make the backoff
    /// cap meaningless.
    #[error("base_delay_ms ({base_delay_ms}) must be less than or equal to max_delay_ms ({max_delay_ms})")]
    InvalidDurationOrder {
        /// Configured base delay, in milliseconds.
        base_delay_ms: String,
        /// Configured maximum delay, in milliseconds.
        max_delay_ms: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with_jitter(jitter: Jitter) -> RetryPolicy {
        RetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(100),
            jitter,
        )
    }

    #[test]
    fn no_jitter_is_deterministic() {
        let policy = policy_with_jitter(Jitter::None);
        assert_eq!(policy.backoff_delay(1), Duration::from_millis(10));
        assert_eq!(policy.backoff_delay(2), Duration::from_millis(20));
        assert_eq!(policy.backoff_delay(5), Duration::from_millis(100));
    }

    #[test]
    fn full_jitter_is_bounded_below_calculated_cap() {
        let policy = policy_with_jitter(Jitter::Full);
        let caps = [(1, 10), (2, 20), (5, 100)];
        for (attempt, cap_ms) in caps {
            for _ in 0..50 {
                let delay = policy.backoff_delay(attempt);
                assert!(
                    delay < Duration::from_millis(cap_ms),
                    "attempt {attempt} produced delay {delay:?} not below {cap_ms}ms cap"
                );
            }
        }
    }

    #[test]
    fn equal_jitter_is_bounded_above_half_and_below_cap() {
        let policy = policy_with_jitter(Jitter::Equal);
        let caps = [(1, 10), (2, 20), (5, 100)];
        for (attempt, cap_ms) in caps {
            let half = Duration::from_millis(cap_ms / 2);
            let cap = Duration::from_millis(cap_ms);
            for _ in 0..50 {
                let delay = policy.backoff_delay(attempt);
                assert!(
                    delay >= half,
                    "attempt {attempt} produced delay {delay:?} below half {half:?}"
                );
                assert!(
                    delay < cap,
                    "attempt {attempt} produced delay {delay:?} not below cap {cap:?}"
                );
            }
        }
    }

    #[test]
    fn zero_attempt_yields_zero_delay() {
        let policy = policy_with_jitter(Jitter::Full);
        assert_eq!(policy.backoff_delay(0), Duration::ZERO);
    }
}
