use crate::{
    auth::{ErasedAuthContext, SbiAuthContext},
    headers::HeaderParseError,
    server::{SbiExtractor, SbiExtractorData},
};
use http::Request;

#[derive(Debug, Default, Clone)]
pub struct ServerMiddlewareShell;

impl ServerMiddlewareShell {
    pub fn install_auth_context<B>(&self, request: &mut Request<B>, context: &SbiAuthContext) {
        request
            .extensions_mut()
            .insert(ErasedAuthContext::from(context));
    }

    pub fn extract<B>(&self, request: &Request<B>) -> Result<SbiExtractorData, HeaderParseError> {
        SbiExtractor::extract_from_request(request)
    }
}
