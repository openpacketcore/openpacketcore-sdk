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

#[derive(Clone, PartialEq, Eq)]
pub struct SbiExtractorData {
    pub headers: SbiHeaders,
    pub bearer_token: Option<crate::headers::BearerToken>,
    pub auth_context: Option<ErasedAuthContext>,
    pub deadline: Option<RequestDeadline>,
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

#[derive(Debug, Default, Clone)]
pub struct SbiExtractor;

impl SbiExtractor {
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
