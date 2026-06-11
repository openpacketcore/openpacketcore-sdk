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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestDeadline {
    expires_at: Instant,
}

impl RequestDeadline {
    pub fn at(expires_at: Instant) -> Self {
        Self { expires_at }
    }

    pub fn after(now: Instant, timeout: Duration) -> Self {
        Self {
            expires_at: now + timeout,
        }
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.expires_at.checked_duration_since(now)
    }

    pub fn timeout_hint_ms(&self, now: Instant) -> Option<u64> {
        let remaining = self.remaining(now)?;
        let millis = remaining.as_millis().max(1);
        Some(millis.min(u128::from(u64::MAX)) as u64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeadlineError {
    #[error("request deadline has already expired")]
    Expired,
    #[error("request deadline hint cannot be encoded as an HTTP header")]
    InvalidHeaderValue,
}

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
    pub fn new() -> Self {
        Self {
            deadline_header: HeaderName::from_static(HEADER_DEADLINE_HINT_MS),
        }
    }

    pub fn with_deadline_header(deadline_header: HeaderName) -> Self {
        Self { deadline_header }
    }

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
