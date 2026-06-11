use crate::{
    auth::ErasedAuthContext,
    client::RequestDeadline,
    headers::{
        extract_bearer_token_from_headers, HeaderParseError, SbiHeaders, HEADER_DEADLINE_HINT_MS,
    },
    redact::SensitivePresence,
};
use http::{header::HeaderName, HeaderMap, Request};
use std::{fmt, time::Duration};

/// Everything the framework can extract from one inbound SBI request,
/// gathered in a single fail-closed parse for handlers to consume.
///
/// `Debug` prints presence flags instead of values for the sensitive
/// fields, so the whole struct is log-safe.
#[derive(Clone, PartialEq, Eq)]
pub struct SbiExtractorData {
    /// Parsed TS 29.500 common headers.
    pub headers: SbiHeaders,
    /// Bearer token from the `Authorization` header; `None` when absent or
    /// when a non-Bearer scheme was used.
    pub bearer_token: Option<crate::headers::BearerToken>,
    /// Credential-free authorization result placed in request extensions by
    /// the auth middleware; `None` if the request has not passed (or was
    /// extracted without) authorization.
    pub auth_context: Option<ErasedAuthContext>,
    /// Locally established absolute deadline from request extensions
    /// (monotonic clock); only populated by `extract_from_request`, since a
    /// bare header map cannot carry extensions.
    pub deadline: Option<RequestDeadline>,
    /// Relative budget parsed from the peer's `x-opc-deadline-ms` header,
    /// in milliseconds. Advisory: unlike `deadline` it is the remote
    /// caller's claim, not a locally enforced deadline.
    pub timeout_hint: Option<Duration>,
}

impl fmt::Debug for SbiExtractorData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiExtractorData")
            .field("headers", &self.headers)
            .field(
                "bearer_token",
                &SensitivePresence(self.bearer_token.is_some()),
            )
            .field(
                "auth_context",
                &SensitivePresence(self.auth_context.is_some()),
            )
            .field("deadline", &self.deadline)
            .field("timeout_hint", &self.timeout_hint)
            .finish()
    }
}

/// Stateless extractor turning raw requests into `SbiExtractorData`.
///
/// Extraction is fail-closed: the first malformed or duplicated SBI header
/// aborts with a `HeaderParseError` so handlers never observe partially
/// parsed metadata.
#[derive(Debug, Default, Clone)]
pub struct SbiExtractor;

impl SbiExtractor {
    /// Extract from headers alone: parses the TS 29.500 common headers, the
    /// bearer token, and the `x-opc-deadline-ms` hint. `auth_context` and
    /// `deadline` stay `None` because they live in request extensions, not
    /// headers.
    pub fn extract_from_header_map(
        headers: &HeaderMap,
    ) -> Result<SbiExtractorData, HeaderParseError> {
        let parsed_headers = SbiHeaders::parse(headers)?;
        let bearer_token = extract_bearer_token_from_headers(headers)?;
        let timeout_hint = parse_timeout_hint(headers)?;

        Ok(SbiExtractorData {
            headers: parsed_headers,
            bearer_token,
            auth_context: None,
            deadline: None,
            timeout_hint,
        })
    }

    /// Extract from a full request: everything `extract_from_header_map`
    /// yields, plus the `RequestDeadline` and `ErasedAuthContext` (if the
    /// middleware stack stored them in the request extensions).
    pub fn extract_from_request<B>(
        request: &Request<B>,
    ) -> Result<SbiExtractorData, HeaderParseError> {
        let mut extracted = Self::extract_from_header_map(request.headers())?;
        extracted.deadline = request.extensions().get::<RequestDeadline>().copied();
        extracted.auth_context = request.extensions().get::<ErasedAuthContext>().cloned();
        Ok(extracted)
    }
}

fn parse_timeout_hint(headers: &HeaderMap) -> Result<Option<Duration>, HeaderParseError> {
    let mut values = headers
        .get_all(HeaderName::from_static(HEADER_DEADLINE_HINT_MS))
        .iter();
    let first = match values.next() {
        Some(value) => value,
        None => return Ok(None),
    };
    if values.next().is_some() {
        return Err(HeaderParseError::Duplicate {
            header: HEADER_DEADLINE_HINT_MS,
        });
    }
    let value = first.to_str().map_err(|_| HeaderParseError::NonUtf8 {
        header: HEADER_DEADLINE_HINT_MS,
    })?;

    let millis = value
        .parse::<u64>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_DEADLINE_HINT_MS,
            reason: "deadline hint must be an integer millisecond value".into(),
        })?;
    Ok(Some(Duration::from_millis(millis)))
}
