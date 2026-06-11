//! TS 29.500 common SBI header parsing, rendering, and safe redaction.
//!
//! Every parser in this module is fail-closed: malformed, empty, duplicated,
//! or non-UTF-8 header values produce a structured `HeaderParseError` instead
//! of being silently dropped or passed through. Credential-bearing values
//! (`Authorization`) are wrapped in redacting types so `Debug`/`Display`
//! output never leaks token material (RFC 007 §8).

use http::{
    header::{HeaderName, HeaderValue, ToStrError},
    HeaderMap, Uri,
};
use opc_types::{IntoRedacted, Redacted};
use std::{fmt, str::FromStr, time::Duration};
use thiserror::Error;
use time::{Date, Month, Time, Weekday};

use crate::redact::SensitivePresence;

/// `3gpp-Sbi-Message-Priority` (TS 29.500): relative SBI message priority.
/// This crate restricts the value to the 0–7 range; values outside it are
/// rejected at parse time.
pub const HEADER_MESSAGE_PRIORITY: &str = "3gpp-sbi-message-priority";
/// `3gpp-Sbi-Correlation-Info` (TS 29.500): opaque correlation data used to
/// associate related SBI messages across NFs. Treated as sensitive and
/// redacted from `Debug` output because it can carry subscriber correlation.
pub const HEADER_CORRELATION_INFO: &str = "3gpp-sbi-correlation-info";
/// `3gpp-Sbi-Binding` (TS 29.500): binding indication a producer returns so
/// consumers can target the same NF (service) instance on later requests.
pub const HEADER_BINDING: &str = "3gpp-sbi-binding";
/// `3gpp-Sbi-Routing-Binding` (TS 29.500): binding indication a consumer
/// sends to steer SCP-mediated routing toward a previously bound producer.
pub const HEADER_ROUTING_BINDING: &str = "3gpp-sbi-routing-binding";
/// `3gpp-Sbi-Target-apiRoot` (TS 29.500): absolute API root of the intended
/// producer when requests are sent indirectly through an SCP.
pub const HEADER_TARGET_API_ROOT: &str = "3gpp-sbi-target-apiroot";
/// Standard HTTP `Retry-After` (RFC 9110): carried on 429/503 overload
/// responses; value is either delay-seconds or an IMF-fixdate HTTP-date.
pub const HEADER_RETRY_AFTER: &str = "retry-after";
/// Standard HTTP `Location` (RFC 9110): URI of a created resource or
/// redirect target; redacted from `Debug` output because resource paths can
/// embed subscriber identifiers.
pub const HEADER_LOCATION: &str = "location";
/// Standard HTTP `Authorization` (RFC 6750): OAuth2 bearer credentials.
/// Values parsed from this header are always stored redacted.
pub const HEADER_AUTHORIZATION: &str = "authorization";
/// OPC idempotency-key header: its presence on a `POST` marks the request as
/// safely retryable (see `retry::is_request_retryable`); the framework never
/// retries non-idempotent requests without it (RFC 007 §12.1).
pub const HEADER_IDEMPOTENCY_KEY: &str = "idempotency-key";
/// OPC-specific deadline hint header: remaining request budget as an integer
/// number of **milliseconds** (not seconds), propagated hop-by-hop so callees
/// can shed work that cannot finish before the caller's deadline.
pub const HEADER_DEADLINE_HINT_MS: &str = "x-opc-deadline-ms";

/// Structured rejection produced when an SBI header fails validation.
///
/// Each variant names the offending header so producers can return a precise
/// TS 29.500 ProblemDetails body. The error text never includes the raw
/// header value, only a static reason, so it is safe to surface to clients
/// and logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderParseError {
    /// The header bytes are not valid UTF-8 / visible-ASCII text.
    #[error("header '{header}' is not valid UTF-8")]
    NonUtf8 {
        /// Lower-cased name of the offending header.
        header: &'static str,
    },
    /// The header is present but its value is empty (or whitespace-only where
    /// trimming applies).
    #[error("header '{header}' must not be empty")]
    Empty {
        /// Lower-cased name of the offending header.
        header: &'static str,
    },
    /// The header appears more than once; SBI common headers must be single
    /// valued, so duplicates are rejected rather than merged (fail-closed).
    #[error("header '{header}' must not be repeated")]
    Duplicate {
        /// Lower-cased name of the offending header.
        header: &'static str,
    },
    /// The value is present and well-formed text but violates the grammar
    /// for that header (e.g. priority out of 0–7, non-IMF-fixdate date,
    /// non-b64token bearer credentials).
    #[error("header '{header}' is invalid: {reason}")]
    InvalidValue {
        /// Lower-cased name of the offending header.
        header: &'static str,
        /// Static, value-free description of the grammar violation.
        reason: String,
    },
}

/// OAuth2 bearer credentials validated against the RFC 6750 `b64token`
/// grammar and stored redacted.
///
/// `Debug` and `Display` print a redaction placeholder, never the raw token;
/// the token can only be read deliberately via `expose` or `into_inner`.
/// Construction rejects empty values, whitespace/control characters, and
/// characters outside the `b64token` alphabet, so a `BearerToken` is always
/// safe to write into an `Authorization` header verbatim.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BearerToken(Redacted<String>);

impl BearerToken {
    /// Validate `value` as an RFC 6750 `b64token` and wrap it redacted.
    ///
    /// Fails with `HeaderParseError::Empty` for an empty string and
    /// `HeaderParseError::InvalidValue` for whitespace, control characters,
    /// out-of-alphabet bytes, interior `=` padding, or padding-only input.
    pub fn new(value: impl Into<String>) -> Result<Self, HeaderParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HeaderParseError::Empty {
                header: HEADER_AUTHORIZATION,
            });
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(HeaderParseError::InvalidValue {
                header: HEADER_AUTHORIZATION,
                reason: "bearer token must not contain whitespace or control characters".into(),
            });
        }
        validate_b64token(&value)?;
        Ok(Self(value.redacted()))
    }

    /// Deliberately read the raw token, bypassing redaction.
    ///
    /// Callers must not log or otherwise persist the returned value; use it
    /// only to build outbound `Authorization` headers or verify signatures.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Consume the wrapper and return the raw token string, leaving the
    /// redaction boundary. Same handling rules as `expose` apply.
    pub fn into_inner(self) -> String {
        self.0.into_inner()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Parsed `Authorization` header with credentials kept redacted.
///
/// Bearer credentials get full RFC 6750 grammar validation; any other scheme
/// is preserved as `Opaque` (control characters rejected) so middleware can
/// pass it through without understanding it. `Debug` prints `<redacted>` in
/// place of credentials for both variants.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationHeader {
    /// `Bearer` scheme (matched case-insensitively) with validated token.
    Bearer(BearerToken),
    /// Any non-Bearer scheme; credentials are stored redacted and are only
    /// checked for control characters, not scheme-specific grammar.
    Opaque {
        /// Authentication scheme exactly as received (case preserved).
        scheme: String,
        /// Raw credentials, redacted from `Debug`/`Display` output.
        credentials: Redacted<String>,
    },
}

impl AuthorizationHeader {
    /// Parse an `Authorization` header value of the exact form
    /// `<scheme> <credentials>`.
    ///
    /// Rejects values with missing credentials or more than two
    /// whitespace-separated parts. `Bearer` (case-insensitive) routes through
    /// `BearerToken::new` validation; everything else becomes `Opaque`.
    pub fn parse(value: &str) -> Result<Self, HeaderParseError> {
        let mut parts = value.split_ascii_whitespace();
        let scheme = parts.next().ok_or(HeaderParseError::Empty {
            header: HEADER_AUTHORIZATION,
        })?;
        let credentials = parts.next().ok_or_else(|| HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "authorization header must contain credentials".into(),
        })?;

        if parts.next().is_some() {
            return Err(HeaderParseError::InvalidValue {
                header: HEADER_AUTHORIZATION,
                reason: "authorization header must contain exactly scheme and credentials".into(),
            });
        }

        if scheme.eq_ignore_ascii_case("Bearer") {
            Ok(Self::Bearer(BearerToken::new(credentials.to_owned())?))
        } else {
            if credentials.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(HeaderParseError::InvalidValue {
                    header: HEADER_AUTHORIZATION,
                    reason: "credentials must not contain control characters".into(),
                });
            }
            Ok(Self::Opaque {
                scheme: scheme.to_owned(),
                credentials: credentials.to_owned().redacted(),
            })
        }
    }

    /// Return the bearer token if this header used the `Bearer` scheme;
    /// `None` for any opaque/unknown scheme.
    pub fn bearer_token(&self) -> Option<&BearerToken> {
        match self {
            Self::Bearer(token) => Some(token),
            Self::Opaque { .. } => None,
        }
    }

    /// Re-render the header value, **exposing** the redacted credentials.
    ///
    /// Intended only for writing outbound `Authorization` headers; the result
    /// must never be logged.
    pub fn render(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {}", token.expose()),
            Self::Opaque {
                scheme,
                credentials,
            } => format!("{scheme} {}", credentials.expose()),
        }
    }
}

impl fmt::Debug for AuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
            Self::Opaque { scheme, .. } => f
                .debug_struct("Opaque")
                .field("scheme", scheme)
                .field("credentials", &"<redacted>")
                .finish(),
        }
    }
}

/// Parsed `Retry-After` header (RFC 9110 §10.2.3), carried on 429/503 SBI
/// overload responses to tell consumers when a retry is appropriate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAfter {
    /// Relative delay in whole **seconds** (the `delay-seconds` form).
    DelaySeconds(u32),
    /// Absolute retry time as a validated IMF-fixdate HTTP-date string,
    /// kept verbatim so it can be re-rendered byte-for-byte.
    HttpDate(String),
}

impl RetryAfter {
    /// Parse a `Retry-After` value.
    ///
    /// All-digit input parses as `DelaySeconds` (must fit in `u32`); anything
    /// else must be a strict 29-character IMF-fixdate (`Sun, 06 Nov 1994
    /// 08:49:37 GMT`) whose weekday matches the calendar date, otherwise
    /// `HeaderParseError::InvalidValue` is returned. Obsolete RFC 850 and
    /// asctime date formats are deliberately rejected.
    pub fn parse(value: &str) -> Result<Self, HeaderParseError> {
        let raw = trim_non_empty(HEADER_RETRY_AFTER, value)?;
        if raw.bytes().all(|byte| byte.is_ascii_digit()) {
            let seconds = raw
                .parse::<u32>()
                .map_err(|_| HeaderParseError::InvalidValue {
                    header: HEADER_RETRY_AFTER,
                    reason: "retry-after delay must fit within u32 seconds".into(),
                })?;
            Ok(Self::DelaySeconds(seconds))
        } else {
            parse_http_date(raw)?;
            Ok(Self::HttpDate(raw.to_owned()))
        }
    }

    /// Convert to a relative wait duration.
    ///
    /// Returns `Some` only for the `DelaySeconds` form; `HttpDate` yields
    /// `None` because turning an absolute date into a delay requires a
    /// wall-clock reading the caller must supply.
    pub fn as_duration(&self) -> Option<Duration> {
        match self {
            Self::DelaySeconds(value) => Some(Duration::from_secs(u64::from(*value))),
            Self::HttpDate(_) => None,
        }
    }

    /// Render the value back to its on-the-wire header form (bare seconds or
    /// the original IMF-fixdate string).
    pub fn render(&self) -> String {
        match self {
            Self::DelaySeconds(seconds) => seconds.to_string(),
            Self::HttpDate(date) => date.clone(),
        }
    }
}

/// Typed view of the TS 29.500 common SBI headers on one request/response.
///
/// Every field is optional: absence means the header was not present.
/// `parse` is fail-closed (any malformed or duplicated header aborts the
/// whole parse) and the `Debug` impl prints only presence/absence for
/// sensitive fields, never their values.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SbiHeaders {
    /// Message priority (0–7), mapped from the 3GPP QosIdentifier field.
    /// TS 29.500 defines QosIdentifier as 0–255, but this implementation
    /// restricts the field to 0–7 per the SBI message priority semantics.
    pub message_priority: Option<u8>,
    /// `3gpp-Sbi-Correlation-Info` value: opaque visible-ASCII correlation
    /// data; treated as sensitive because it can carry subscriber
    /// correlation identifiers.
    pub correlation_info: Option<String>,
    /// `3gpp-Sbi-Binding` value: producer binding indication returned so the
    /// consumer can re-target the same NF (service) instance.
    pub binding: Option<String>,
    /// `3gpp-Sbi-Routing-Binding` value: consumer-supplied binding used by
    /// an SCP to route to a previously bound producer.
    pub routing_binding: Option<String>,
    /// `3gpp-Sbi-Target-apiRoot` value: producer API root URI for indirect
    /// (SCP-mediated) routing; validated as a URI at parse time.
    pub target_api_root: Option<Uri>,
    /// `Retry-After` value from a 429/503 overload response.
    pub retry_after: Option<RetryAfter>,
    /// `Location` value (created resource or redirect target); validated as
    /// a URI and redacted from `Debug` because paths can embed SUPI/GPSI.
    pub location: Option<Uri>,
    /// Parsed `Authorization` header; credentials stay redacted.
    pub authorization: Option<AuthorizationHeader>,
}

impl SbiHeaders {
    /// Parse the recognized TS 29.500 common headers out of `headers`.
    ///
    /// Unrecognized headers are ignored. Each recognized header must appear
    /// at most once; a repeated header fails with
    /// `HeaderParseError::Duplicate` rather than picking one value
    /// (fail-closed). The first invalid header aborts the whole parse.
    pub fn parse(headers: &HeaderMap) -> Result<Self, HeaderParseError> {
        Ok(Self {
            message_priority: optional_header_value(headers, HEADER_MESSAGE_PRIORITY)?
                .map(parse_message_priority)
                .transpose()?,
            correlation_info: optional_header_value(headers, HEADER_CORRELATION_INFO)?
                .map(|value| parse_non_sensitive_string(HEADER_CORRELATION_INFO, value))
                .transpose()?,
            binding: optional_header_value(headers, HEADER_BINDING)?
                .map(|value| parse_non_sensitive_string(HEADER_BINDING, value))
                .transpose()?,
            routing_binding: optional_header_value(headers, HEADER_ROUTING_BINDING)?
                .map(|value| parse_non_sensitive_string(HEADER_ROUTING_BINDING, value))
                .transpose()?,
            target_api_root: optional_header_value(headers, HEADER_TARGET_API_ROOT)?
                .map(|value| parse_uri_header(HEADER_TARGET_API_ROOT, value))
                .transpose()?,
            retry_after: optional_header_value(headers, HEADER_RETRY_AFTER)?
                .map(RetryAfter::parse)
                .transpose()?,
            location: optional_header_value(headers, HEADER_LOCATION)?
                .map(|value| parse_uri_header(HEADER_LOCATION, value))
                .transpose()?,
            authorization: optional_header_value(headers, HEADER_AUTHORIZATION)?
                .map(AuthorizationHeader::parse)
                .transpose()?,
        })
    }

    /// Render the populated fields back into a `HeaderMap` for an outbound
    /// message, skipping `None` fields.
    ///
    /// Fails with `HeaderParseError::InvalidValue` if a value cannot be
    /// encoded as an HTTP header (e.g. a URI rendering to non-ASCII). The
    /// rendered `Authorization` header exposes the redacted credentials, so
    /// the resulting map must be treated as sensitive.
    pub fn render(&self) -> Result<HeaderMap, HeaderParseError> {
        let mut headers = HeaderMap::new();

        if let Some(priority) = self.message_priority {
            insert_header(&mut headers, HEADER_MESSAGE_PRIORITY, &priority.to_string())?;
        }
        if let Some(correlation_info) = &self.correlation_info {
            insert_header(&mut headers, HEADER_CORRELATION_INFO, correlation_info)?;
        }
        if let Some(binding) = &self.binding {
            insert_header(&mut headers, HEADER_BINDING, binding)?;
        }
        if let Some(routing_binding) = &self.routing_binding {
            insert_header(&mut headers, HEADER_ROUTING_BINDING, routing_binding)?;
        }
        if let Some(target_api_root) = &self.target_api_root {
            insert_header(
                &mut headers,
                HEADER_TARGET_API_ROOT,
                &target_api_root.to_string(),
            )?;
        }
        if let Some(retry_after) = &self.retry_after {
            insert_header(&mut headers, HEADER_RETRY_AFTER, &retry_after.render())?;
        }
        if let Some(location) = &self.location {
            insert_header(&mut headers, HEADER_LOCATION, &location.to_string())?;
        }
        if let Some(authorization) = &self.authorization {
            insert_header(&mut headers, HEADER_AUTHORIZATION, &authorization.render())?;
        }

        Ok(headers)
    }
}

impl fmt::Debug for SbiHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiHeaders")
            .field("message_priority", &self.message_priority)
            .field(
                "correlation_info",
                &SensitivePresence(self.correlation_info.is_some()),
            )
            .field("binding", &SensitivePresence(self.binding.is_some()))
            .field(
                "routing_binding",
                &SensitivePresence(self.routing_binding.is_some()),
            )
            .field(
                "target_api_root",
                &SensitivePresence(self.target_api_root.is_some()),
            )
            .field("retry_after", &self.retry_after)
            .field("location", &SensitivePresence(self.location.is_some()))
            .field(
                "authorization",
                &SensitivePresence(self.authorization.is_some()),
            )
            .finish()
    }
}

/// Parse an `Authorization` header value and return the bearer token, if any.
///
/// Returns `Ok(None)` for well-formed non-Bearer schemes (the caller decides
/// whether opaque schemes are acceptable) and `Err` for malformed values.
pub fn extract_bearer_token(value: &str) -> Result<Option<BearerToken>, HeaderParseError> {
    let parsed = AuthorizationHeader::parse(value)?;
    Ok(parsed.bearer_token().cloned())
}

/// Extract the bearer token from a request's `Authorization` header.
///
/// Returns `Ok(None)` when the header is absent or uses a non-Bearer scheme;
/// fails with `HeaderParseError::Duplicate` if the header is repeated and
/// with parse errors for malformed credentials (fail-closed: a request with
/// a broken `Authorization` header is rejected, not treated as anonymous).
pub fn extract_bearer_token_from_headers(
    headers: &HeaderMap,
) -> Result<Option<BearerToken>, HeaderParseError> {
    match optional_header_value(headers, HEADER_AUTHORIZATION)? {
        Some(value) => extract_bearer_token(value),
        None => Ok(None),
    }
}

fn optional_header_value<'a>(
    headers: &'a HeaderMap,
    header: &'static str,
) -> Result<Option<&'a str>, HeaderParseError> {
    let mut values = headers.get_all(HeaderName::from_static(header)).iter();
    let first = match values.next() {
        Some(value) => value,
        None => return Ok(None),
    };

    if values.next().is_some() {
        return Err(HeaderParseError::Duplicate { header });
    }

    Ok(Some(to_str(header, first)?))
}

fn to_str<'a>(header: &'static str, value: &'a HeaderValue) -> Result<&'a str, HeaderParseError> {
    value
        .to_str()
        .map_err(|_: ToStrError| HeaderParseError::NonUtf8 { header })
}

fn parse_message_priority(value: &str) -> Result<u8, HeaderParseError> {
    let raw = trim_non_empty(HEADER_MESSAGE_PRIORITY, value)?;
    let priority = raw
        .parse::<u8>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_MESSAGE_PRIORITY,
            reason: "priority must be an integer between 0 and 7".into(),
        })?;
    if priority > 7 {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_MESSAGE_PRIORITY,
            reason: "priority must be between 0 and 7".into(),
        });
    }
    Ok(priority)
}

fn parse_non_sensitive_string(
    header: &'static str,
    value: &str,
) -> Result<String, HeaderParseError> {
    let raw = trim_non_empty(header, value)?;
    validate_visible_ascii(header, raw)?;
    Ok(raw.to_owned())
}

fn parse_uri_header(header: &'static str, value: &str) -> Result<Uri, HeaderParseError> {
    let raw = trim_non_empty(header, value)?;
    raw.parse::<Uri>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header,
            reason: "header must contain a valid URI".into(),
        })
}

fn trim_non_empty<'a>(header: &'static str, value: &'a str) -> Result<&'a str, HeaderParseError> {
    if value.trim() != value {
        return Err(HeaderParseError::InvalidValue {
            header,
            reason: "header value must not contain leading or trailing whitespace".into(),
        });
    }
    if value.is_empty() {
        return Err(HeaderParseError::Empty { header });
    }
    Ok(value)
}

fn validate_visible_ascii(header: &'static str, value: &str) -> Result<(), HeaderParseError> {
    if value
        .bytes()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(HeaderParseError::InvalidValue {
            header,
            reason: "header value must contain only visible ASCII characters".into(),
        });
    }
    Ok(())
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), HeaderParseError> {
    let header_name = HeaderName::from_static(name);
    let value = HeaderValue::from_str(value).map_err(|_| HeaderParseError::InvalidValue {
        header: name,
        reason: "header value cannot be encoded".into(),
    })?;
    headers.insert(header_name, value);
    Ok(())
}

fn validate_b64token(value: &str) -> Result<(), HeaderParseError> {
    let mut saw_padding = false;
    let mut saw_content = false;

    for byte in value.bytes() {
        if is_b64token_char(byte) {
            if saw_padding {
                return Err(HeaderParseError::InvalidValue {
                    header: HEADER_AUTHORIZATION,
                    reason: "bearer token padding must only appear at the end".into(),
                });
            }
            saw_content = true;
            continue;
        }

        if byte == b'=' {
            saw_padding = true;
            continue;
        }

        return Err(HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "bearer token contains characters outside the RFC 6750 b64token grammar".into(),
        });
    }

    if !saw_content {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "bearer token must contain at least one non-padding character".into(),
        });
    }

    Ok(())
}

fn is_b64token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

fn parse_http_date(value: &str) -> Result<(), HeaderParseError> {
    validate_visible_ascii(HEADER_RETRY_AFTER, value)?;
    if value.len() != 29 {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    let bytes = value.as_bytes();
    if bytes[3] != b','
        || bytes[4] != b' '
        || bytes[7] != b' '
        || bytes[11] != b' '
        || bytes[16] != b' '
        || bytes[19] != b':'
        || bytes[22] != b':'
        || bytes[25] != b' '
        || &value[26..] != "GMT"
    {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    let weekday = parse_weekday(&value[..3])?;
    let day = parse_u8_component(&value[5..7], "day")?;
    let month = parse_month(&value[8..11])?;
    let year = parse_i32_component(&value[12..16], "year")?;
    let hour = parse_u8_component(&value[17..19], "hour")?;
    let minute = parse_u8_component(&value[20..22], "minute")?;
    let second = parse_u8_component(&value[23..25], "second")?;

    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })?;
    Time::from_hms(hour, minute, second).map_err(|_| HeaderParseError::InvalidValue {
        header: HEADER_RETRY_AFTER,
        reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
    })?;

    if date.weekday() != weekday {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    Ok(())
}

fn parse_weekday(value: &str) -> Result<Weekday, HeaderParseError> {
    match value {
        "Mon" => Ok(Weekday::Monday),
        "Tue" => Ok(Weekday::Tuesday),
        "Wed" => Ok(Weekday::Wednesday),
        "Thu" => Ok(Weekday::Thursday),
        "Fri" => Ok(Weekday::Friday),
        "Sat" => Ok(Weekday::Saturday),
        "Sun" => Ok(Weekday::Sunday),
        _ => Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        }),
    }
}

fn parse_month(value: &str) -> Result<Month, HeaderParseError> {
    match value {
        "Jan" => Ok(Month::January),
        "Feb" => Ok(Month::February),
        "Mar" => Ok(Month::March),
        "Apr" => Ok(Month::April),
        "May" => Ok(Month::May),
        "Jun" => Ok(Month::June),
        "Jul" => Ok(Month::July),
        "Aug" => Ok(Month::August),
        "Sep" => Ok(Month::September),
        "Oct" => Ok(Month::October),
        "Nov" => Ok(Month::November),
        "Dec" => Ok(Month::December),
        _ => Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        }),
    }
}

fn parse_u8_component(value: &str, component: &'static str) -> Result<u8, HeaderParseError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: format!("retry-after {component} must be numeric"),
        });
    }

    value
        .parse::<u8>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })
}

fn parse_i32_component(value: &str, component: &'static str) -> Result<i32, HeaderParseError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: format!("retry-after {component} must be numeric"),
        });
    }

    value
        .parse::<i32>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })
}

impl FromStr for RetryAfter {
    type Err = HeaderParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_visible_ascii_rejects_control_and_high_bytes() {
        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "hello\x00world").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "control bytes should be rejected"
        );

        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "hello\x7fworld").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "DEL should be rejected"
        );

        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "café").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "non-ASCII bytes should be rejected"
        );
        assert!(err.to_string().contains("visible ASCII"));

        assert!(validate_visible_ascii(HEADER_CORRELATION_INFO, "plain-ascii-123").is_ok());
    }

    #[test]
    fn validate_b64token_rejects_padding_only_and_malformed() {
        // Padding-only tokens must be rejected.
        for token in ["=", "==", "==="] {
            let err = validate_b64token(token).unwrap_err();
            assert!(
                matches!(err, HeaderParseError::InvalidValue { .. }),
                "padding-only token '{token}' should be rejected"
            );
        }

        // Padding after content is allowed.
        assert!(validate_b64token("abc=").is_ok());
        assert!(validate_b64token("ab==").is_ok());

        // Padding in the middle is not allowed.
        let err = validate_b64token("a=b").unwrap_err();
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));

        // Non-b64token characters are rejected.
        let err = validate_b64token("abc,def").unwrap_err();
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));
    }
}
