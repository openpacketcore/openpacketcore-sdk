use crate::{
    auth::{ErasedAuthContext, SbiAuthContext},
    headers::HeaderParseError,
    server::{SbiExtractor, SbiExtractorData},
};
use http::Request;

/// Framework-agnostic server-side middleware operations, for embedding the
/// SBI auth/extraction steps into a custom (non-`SbiServerBuilder`) stack.
///
/// "Shell" because it is stateless and performs no I/O — it only reads and
/// writes request extensions and headers.
#[derive(Debug, Default, Clone)]
pub struct ServerMiddlewareShell;

impl ServerMiddlewareShell {
    /// Store the authorization result in the request extensions in its
    /// **erased** (credential-free) form, so downstream handlers can read
    /// peer identity and scopes without ever touching the access token.
    pub fn install_auth_context<B>(&self, request: &mut Request<B>, context: &SbiAuthContext) {
        request
            .extensions_mut()
            .insert(ErasedAuthContext::from(context));
    }

    /// Run the standard fail-closed extraction (`SbiExtractor::
    /// extract_from_request`): TS 29.500 headers, bearer token, deadline
    /// hint, plus any deadline/auth context already in the extensions.
    pub fn extract<B>(&self, request: &Request<B>) -> Result<SbiExtractorData, HeaderParseError> {
        SbiExtractor::extract_from_request(request)
    }
}
