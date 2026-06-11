use crate::{
    headers::{BearerToken, HEADER_AUTHORIZATION, HEADER_DEADLINE_HINT_MS},
    retry::{RetryOutcome, RetryPolicy},
};
use http::{
    header::{HeaderName, HeaderValue, InvalidHeaderValue},
    Request,
};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Absolute completion deadline for one outbound SBI request (RFC 007
/// §6.3: every outbound request must carry a caller-supplied deadline).
///
/// Stored as a monotonic `Instant`, so it is immune to wall-clock jumps;
/// it travels in request extensions and is rendered to peers as a relative
/// millisecond hint via the `x-opc-deadline-ms` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestDeadline {
    expires_at: Instant,
}

impl RequestDeadline {
    /// Deadline at an absolute monotonic instant.
    pub fn at(expires_at: Instant) -> Self {
        Self { expires_at }
    }

    /// Deadline `timeout` from `now` — the usual way to derive a deadline
    /// from a per-request budget.
    pub fn after(now: Instant, timeout: Duration) -> Self {
        Self {
            expires_at: now + timeout,
        }
    }

    /// The absolute instant after which the request should be abandoned.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Budget left at `now`, or `None` if the deadline has already passed
    /// (callers should fail fast instead of sending).
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.expires_at.checked_duration_since(now)
    }

    /// Remaining budget as the integer **millisecond** value carried in the
    /// `x-opc-deadline-ms` header.
    ///
    /// Returns `None` once expired; otherwise clamps to at least 1 ms so a
    /// nearly expired deadline is never rendered as `0` (which a callee
    /// could misread as "no budget given").
    pub fn timeout_hint_ms(&self, now: Instant) -> Option<u64> {
        let remaining = self.remaining(now)?;
        let millis = remaining.as_millis().max(1);
        Some(millis.min(u128::from(u64::MAX)) as u64)
    }
}

/// Failure applying a `RequestDeadline` to an outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeadlineError {
    /// The deadline passed before the request was sent; the caller should
    /// abort instead of dialing a peer it can no longer wait for.
    #[error("request deadline has already expired")]
    Expired,
    /// The rendered millisecond hint was not a valid HTTP header value
    /// (practically unreachable for decimal integers, kept for
    /// completeness).
    #[error("request deadline hint cannot be encoded as an HTTP header")]
    InvalidHeaderValue,
}

/// Outbound-request decorator that stamps deadline hints and bearer tokens
/// onto requests before they reach the wire.
///
/// "Shell" because it carries no I/O of its own — `SbiClient` (or any other
/// transport) performs the send; this type only mutates request headers and
/// extensions.
#[derive(Debug, Clone)]
pub struct ClientMiddlewareShell {
    deadline_header: HeaderName,
}

impl Default for ClientMiddlewareShell {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientMiddlewareShell {
    /// Shell writing deadline hints to the default `x-opc-deadline-ms`
    /// header.
    pub fn new() -> Self {
        Self {
            deadline_header: HeaderName::from_static(HEADER_DEADLINE_HINT_MS),
        }
    }

    /// Shell writing deadline hints to a custom header name, for peers that
    /// expect a different deadline-propagation convention.
    pub fn with_deadline_header(deadline_header: HeaderName) -> Self {
        Self { deadline_header }
    }

    /// Stamp `deadline` onto the request: writes the remaining budget (in
    /// milliseconds, evaluated at `now`) into the deadline header and
    /// stores the `RequestDeadline` in the request extensions so local
    /// timeout enforcement can read it back.
    ///
    /// Fails with `DeadlineError::Expired` when no budget remains, leaving
    /// the request unmodified.
    pub fn apply_deadline<B>(
        &self,
        request: &mut Request<B>,
        deadline: RequestDeadline,
        now: Instant,
    ) -> Result<(), DeadlineError> {
        let timeout_hint_ms = deadline
            .timeout_hint_ms(now)
            .ok_or(DeadlineError::Expired)?;
        let header_value = HeaderValue::from_str(&timeout_hint_ms.to_string())
            .map_err(|_| DeadlineError::InvalidHeaderValue)?;
        request
            .headers_mut()
            .insert(self.deadline_header.clone(), header_value);
        request.extensions_mut().insert(deadline);
        Ok(())
    }

    /// Set the request's `Authorization` header to `Bearer <token>`,
    /// replacing any existing value. The token is exposed only into the
    /// header itself; do not log the resulting request headers.
    pub fn apply_bearer_token<B>(
        &self,
        request: &mut Request<B>,
        token: &BearerToken,
    ) -> Result<(), InvalidHeaderValue> {
        let value = HeaderValue::from_str(&format!("Bearer {}", token.expose()))?;
        request
            .headers_mut()
            .insert(HeaderName::from_static(HEADER_AUTHORIZATION), value);
        Ok(())
    }

    /// Convenience pass-through to `RetryPolicy::should_retry`, so retry
    /// decisions can be made at the middleware layer with the same
    /// idempotency rules as the policy itself.
    pub fn should_retry<B>(
        &self,
        request: &Request<B>,
        attempt: u8,
        outcome: RetryOutcome,
        policy: &RetryPolicy,
    ) -> bool {
        policy.should_retry(request, attempt, outcome)
    }
}
