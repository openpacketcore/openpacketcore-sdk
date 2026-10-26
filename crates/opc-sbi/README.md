# opc-sbi

## Purpose

`opc-sbi` provides shared Service Based Interface primitives for
OpenPacketCore network functions: TS 29.500 ProblemDetails, common SBI header
parsing/redaction, JWT-SVID authorization, outbound HTTP/2 client middleware,
server middleware, retries, circuit breakers, NRF helpers, and test fixtures.

It is a framework crate, not a generated client for every 3GPP service API and
not a complete product SBI stack by itself.

## API Shape

- Headers and errors: `SbiHeaders`, `AuthorizationHeader`, `BearerToken`,
  `RetryAfter`, `HeaderParseError`, header constants, `extract_bearer_token`,
  and `extract_bearer_token_from_headers`.
- ProblemDetails: `ProblemDetails`, `CauseCode`, `CauseCodeError`, and
  `InvalidParam`.
- Auth: `SbiAuth`, `SbiAuthRequest`, `SbiAuthContext`, `ErasedAuthContext`,
  `SbiPeer`, `SbiAuthError`, `SbiJwtValidator`, `Jwk`, `Jwks`, `JwksResolver`,
  `JwksCache`, `ClientTokenCache`, and `TokenProvider`.
- Client: `SbiClientBuilder`, `SbiClient`, `ClientMiddlewareShell`,
  `RequestDeadline`, `DeadlineError`, `CircuitBreaker`, `CircuitBreakers`, and
  `CircuitState`.
- Server: `SbiServerBuilder`, `SbiExtractor`, `SbiExtractorData`, and
  `ServerMiddlewareShell`.
- Retry: `RetryPolicy`, `RetryOutcome`, `Jitter`, and
  `RetryPolicyParseError`.
- NRF: `NfProfile`, `DiscoveryQuery`, `DiscoveryResult`, `DiscoveryCache`,
  `CachedDiscoveryClient`, `HeartbeatDriver`, `NrfClient`, `NrfOperations`,
  and service-name constants under `nrf::services`.
- Testkit: with `features = ["testkit"]`, exports `MockNrf`, `MockProducer`,
  `MockConsumer`, `RecordedRequest`, token fixtures, JWKS fixtures, and failure
  fixtures.
- Runtime hooks: with `features = ["runtime-hooks"]`, exports `NrfDrainHook`
  and `NrfRuntimeBuilderExt`.

## Usage

```rust,no_run
use std::time::Duration;

use opc_sbi::{Jitter, RetryPolicy, SbiClientBuilder};

let retry = RetryPolicy::new(
    3,
    Duration::from_millis(50),
    Duration::from_secs(1),
    Jitter::Equal,
);
let client = SbiClientBuilder::new()
    .with_retry_policy(retry)
    .with_body_limit(1024 * 1024)
    .build()
    .unwrap();
```

## Relationships

- Uses `opc-tls`, `opc-identity`, `opc-types`, `opc-redaction`, and optionally
  `opc-runtime`.
- `opc-api-nnrf` and per-service API crates own generated or service-specific
  request/response shapes.
- Downstream CNF crates provide handlers, product-specific auth policy, service
  clients, and graceful shutdown orchestration.

## Status And Limits

- Header parsers fail closed on malformed, empty, duplicate, or non-UTF-8
  common header values.
- Bearer tokens and authorization credentials are redacted by default.
- `SbiClient` retries only idempotent requests or POST requests with an
  `idempotency-key`.
- `SbiServerBuilder` production mode requires TLS, an auth policy, trust
  bundles, and a nonzero concurrency cap.
- The server builder accepts connections forever once started; graceful
  shutdown wiring belongs in the runtime/product layer.

## Roadmap

- Keep generic framework behavior here and service-specific OpenAPI bindings in
  service crates.
- Expand NRF production HTTP behavior alongside contract tests.
- Keep redaction and fail-closed parsing as compatibility requirements for new
  headers and auth modes.

## Verification

```sh
cargo test -p opc-sbi
cargo test -p opc-sbi --features testkit
cargo test -p opc-sbi --features runtime-hooks
```

## NRF wire compatibility

Registration uses TS 29.510 NF type/status tokens, object-form PLMN/S-NSSAI
identifiers, and typed service instances. Supply `NfService` metadata (instance
ID, versions, scheme and status), not a vector of service-name strings. The
`NnrfPlmnId`/`NnrfSnssai` wrappers accept existing SDK identifiers via `Into`.
The timer field on registration/heartbeat responses is `heartBeatTimer`.

`DiscoveryQuery::requester_nf_type` is mandatory and part of the cache key.
The client sends both NF types, requester instance, `target-plmn-list`,
`snssais`, and the comma-separated service-name filter. A malformed SearchResult
is an error, not a negative discovery result.

`DiscoveryResult::Found` and `NotFound` carry `valid_for`. HTTP discovery caps
this by `validityPeriod`, Cache-Control max-age/no-cache/no-store, Age and Date.
The local cache TTL remains an additional limit; server lifetime also caps
stale-if-error. Fresh authoritative absence evicts a stale positive. A 404
without explicit freshness is not stored. These are bounded discovery helpers,
not a complete HTTP caching proxy or full NRF data model.

## NRF access tokens

The validator defaults to the SDK JWT-SVID profile. To accept TS 29.510
6.3.5.2.4 access tokens, select
`SbiTokenProfile::NrfAccessToken` with `with_token_profile`. Configure the NRF
UUID as expected issuer and the local producer NF type or instance ID as
expected audience. RS256 signatures, issuer, audience, expiry and service
scope are enforced. `nbf` is optional but enforced when present. NRF scope
claims must use the standard space-delimited grammar.

NRF consumer UUID subjects must match the authenticated transport peer's NF
instance. Tenant and NF type are retained from that peer, never invented from
token or unsigned HTTP fields. This profile requires peer binding even outside
production and does not allow the mock-token bypass. Resource/operation-level
authorization remains the consuming service's policy; the generic validator
requires the invoked service scope.
