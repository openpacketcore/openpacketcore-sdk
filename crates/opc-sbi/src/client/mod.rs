//! Outbound SBI HTTP/2 client: connection pooling, retries, per-peer
//! circuit breaking, and deadline/bearer-token middleware (RFC 007 §6,
//! §12, §13.4).

pub mod builder;
pub mod circuit_breaker;
mod middleware;

pub use builder::{SbiClient, SbiClientBuilder};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakers, CircuitState};
pub use middleware::{ClientMiddlewareShell, DeadlineError, RequestDeadline};
