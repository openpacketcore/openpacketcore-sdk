//! Inbound SBI HTTP/2 server: builder with TLS/mTLS peer identity, auth and
//! admission middleware, panic containment, and typed request extractors
//! (RFC 007 §9, §13).

pub mod builder;
mod extractors;
mod middleware;

pub use builder::SbiServerBuilder;
pub use extractors::{SbiExtractor, SbiExtractorData};
pub use middleware::ServerMiddlewareShell;
