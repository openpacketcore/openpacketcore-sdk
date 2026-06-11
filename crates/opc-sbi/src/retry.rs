use crate::headers::HEADER_IDEMPOTENCY_KEY;
use http::{Method, Request, StatusCode};
use std::{str::FromStr, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jitter {
    None,
    Full,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    Status(StatusCode),
    TransportError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: Jitter,
    pub retry_on_status: Vec<StatusCode>,
    pub retry_on_transport_error: bool,
}

impl RetryPolicy {
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
                    let rand_ms = rand::random::<u64>() % ms;
                    Duration::from_millis(rand_ms)
                }
            }
            Jitter::Equal => {
                let half = calculated / 2;
                let half_ms = half.as_millis() as u64;
                if half_ms == 0 {
                    half
                } else {
                    let rand_ms = rand::random::<u64>() % half_ms;
                    half + Duration::from_millis(rand_ms)
                }
            }
        }
    }

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

pub fn is_request_retryable<B>(request: &Request<B>) -> bool {
    is_method_idempotent(request.method())
        || (request.method() == Method::POST
            && request
                .headers()
                .contains_key(http::header::HeaderName::from_static(
                    HEADER_IDEMPOTENCY_KEY,
                )))
}

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RetryPolicyParseError {
    #[error("retry policy segment must be key=value: {0}")]
    InvalidSegment(String),
    #[error("retry policy is missing required field '{0}'")]
    MissingField(&'static str),
    #[error("retry policy field '{field}' must be a u8, got '{value}'")]
    InvalidU8 { field: &'static str, value: String },
    #[error("retry policy field '{field}' must be a u64 millisecond value, got '{value}'")]
    InvalidU64 { field: &'static str, value: String },
    #[error("retry policy field 'jitter' is invalid: {0}")]
    InvalidJitter(String),
    #[error("retry policy field '{field}' must be 'true' or 'false', got '{value}'")]
    InvalidBoolean { field: &'static str, value: String },
    #[error("retry policy status code is invalid: '{value}'")]
    InvalidStatusCode { value: String },
    #[error("retry policy contains unknown field '{0}'")]
    UnknownField(String),
    #[error("base_delay_ms ({base_delay_ms}) must be less than or equal to max_delay_ms ({max_delay_ms})")]
    InvalidDurationOrder {
        base_delay_ms: String,
        max_delay_ms: String,
    },
}
