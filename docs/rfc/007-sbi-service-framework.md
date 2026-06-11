# OPC-SDK-RFC-007: SBI Service Framework

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: SBI NF implementers, security engineers, operator authors, test authors

## 1. Abstract

This RFC defines the OpenPacketCore Service Based Interface (SBI) framework for
5G control-plane CNFs. It standardizes HTTP/2 transport behavior, 3GPP
ProblemDetails, OAuth2/JWT-SVID authentication, NRF discovery, service
registration, retry/backoff, overload control, circuit breaking, idempotency,
callback delivery, OpenAPI/model generation, observability, and conformance
tests.

Without this RFC, every SBI-producing NF would independently implement common
TS 29.500/29.501 behavior. That would create incompatible error semantics,
token validation, discovery caching, and overload behavior across AMF, SMF,
PCF, NRF, UDM, AUSF, NSSF, NEF, NWDAF, BSF, CHF, SCP, and SEPP.

## 2. Scope

### 2.1 In Scope

- SBI HTTP/2 server and client substrate.
- TS 29.500 common headers and ProblemDetails behavior.
- TS 29.510 NRF registration, heartbeat, discovery, and access token client
  helpers.
- OAuth2 bearer token validation and client-credentials acquisition.
- SPIFFE JWT-SVID client authentication to NRF where configured.
- Retry, timeout, backoff, idempotency, and callback delivery.
- Per-peer, per-slice, and per-service overload controls.
- Circuit breakers and outlier detection.
- OpenAPI-driven model generation and compatibility.
- Metrics, tracing, audit, and evidence hooks.

### 2.2 Out of Scope

- NF-specific SBI resource semantics. Those live in per-NF crates.
- Management-plane gNMI/NETCONF. See RFC 001 and RFC 003.
- Protocol codecs below HTTP/2. See RFC 005.
- Session persistence. See RFC 004.

## 3. Design Goals

### 3.1 Security

- Authenticate every SBI peer with mTLS and, where applicable, OAuth2 access
  tokens.
- Bind peer identity, NF type, NF instance ID, PLMN, tenant, slice, and token
  scopes into authorization decisions.
- Prevent topology scraping, token replay, confused-deputy calls, callback
  spoofing, and cross-slice data exposure.
- Avoid logging raw SUPI/GPSI, bearer tokens, assertion JWTs, or subscriber
  payloads.

### 3.2 Performance

- Use HTTP/2 connection pooling and bounded concurrency per peer.
- Avoid per-request DNS/NRF discovery.
- Make token verification hot-path cacheable.
- Provide low-latency fast paths for common ProblemDetails and header parsing.
- Enforce backpressure before request queues grow unbounded.

### 3.3 Maintainability

- Keep TS 29.500 common behavior in `opc-sbi`, not in every NF.
- Generate typed models from version-pinned OpenAPI definitions where possible.
- Keep retry and overload policy declarative through YANG.
- Provide one shared testkit for SBI peers and NRF behavior.

### 3.4 Functionality

- Support SBI producer and consumer roles.
- Support NRF registration, heartbeat, discovery, subscriptions, and token
  acquisition.
- Support service-version negotiation.
- Support callbacks with retry and dead-letter behavior.
- Support direct NF-to-NF routing and SCP-mediated routing.

## 4. Standards Baseline

The initial target is 3GPP Release 17 with explicit support for selected Release
18 behavior when per-NF specs require it.

Required references:

- TS 29.500: Common API framework, HTTP behavior, headers, ProblemDetails.
- TS 29.501: Principles and guidelines for services definition.
- TS 29.510: NRF NFManagement, NFDiscovery, AccessToken.
- TS 33.501: SBI security and OAuth2 usage.
- RFC 6749: OAuth2.
- RFC 6750: Bearer token usage.
- RFC 7515/7517/7519: JWS, JWK, JWT.
- RFC 7662: Token introspection, if enabled by profile.
- RFC 9110/RFC 9113: HTTP semantics and HTTP/2.

The exact release and supported service APIs are captured in RFC 006 evidence.

## 5. Crate Model

The shared crate is `opc-sbi`.

```text
crates/opc-sbi/
  src/
    lib.rs
    error.rs
    problem.rs
    headers.rs
    identity.rs
    oauth.rs
    nrf/
      mod.rs
      registration.rs
      discovery.rs
      heartbeat.rs
      access_token.rs
      cache.rs
    client/
      mod.rs
      pool.rs
      retry.rs
      circuit_breaker.rs
      overload.rs
    server/
      mod.rs
      auth.rs
      extractors.rs
      middleware.rs
    callback/
      mod.rs
      dispatcher.rs
      dead_letter.rs
    models/
      generated/
    observability.rs
    testkit/
```

NF crates MUST use `opc-sbi` for common SBI behavior. They MUST NOT duplicate
ProblemDetails encoding, bearer-token parsing, NRF discovery caching, or retry
policy.

## 6. Transport Contract

### 6.1 HTTP/2

SBI uses HTTP/2 by default. The framework MUST:

- Use TLS 1.3 by default.
- Verify peer certificate identity through RFC 003.
- Support direct NF endpoints and SCP endpoints.
- Enforce max header list size, max frame size, max body size, stream
  concurrency, and idle timeouts.
- Reject HTTP/1.1 in production profiles unless a per-NF compatibility profile
  explicitly permits it.

### 6.2 Connection Pooling

The client pool key MUST include:

- target NF instance or service set,
- transport mode: direct or SCP,
- trust domain,
- tenant,
- service name,
- API version,
- TLS profile,
- OAuth2 audience/scope set.

Pools MUST enforce:

- maximum connections per peer,
- maximum concurrent streams per connection,
- idle connection eviction,
- connection max age,
- backpressure when all streams are saturated.

### 6.3 Deadlines

Every outbound SBI request MUST carry a deadline from the caller. The framework
MUST enforce request timeout locally and SHOULD propagate timeout hints through
headers where 3GPP permits.

## 7. ProblemDetails

### 7.1 Error Type

`opc-sbi` owns the canonical ProblemDetails type:

```rust
pub struct ProblemDetails {
    pub status: http::StatusCode,
    pub cause: Option<CauseCode>,
    pub title: Option<String>,
    pub detail: Option<String>,
    pub instance: Option<String>,
    pub invalid_params: Vec<InvalidParam>,
    pub supported_features: Option<String>,
}
```

NF code returns domain errors; the framework maps them to ProblemDetails.

### 7.2 Mapping Rules

ProblemDetails mapping MUST be:

- deterministic,
- spec-cited,
- test-covered,
- safe for logs and clients,
- evidence-linked through RFC 006.

No domain handler may return ad hoc JSON error bodies on SBI routes.

## 8. Common Headers

The framework MUST parse and render configured TS 29.500 headers, including:

- `3gpp-Sbi-Message-Priority`
- `3gpp-Sbi-Correlation-Info`
- `3gpp-Sbi-Binding`
- `3gpp-Sbi-Routing-Binding`
- `3gpp-Sbi-Target-apiRoot`
- `Retry-After`
- `Location`
- `Authorization`

Header parsing MUST reject malformed values with structured errors. Sensitive
headers MUST be redacted.

## 9. Identity and Authorization

### 9.1 Peer Identity

The server middleware extracts:

```rust
pub struct SbiPeer {
    pub spiffe: Option<SpiffeId>,
    pub nf_instance_id: Option<NfInstanceId>,
    pub nf_type: Option<NfType>,
    pub tenant: TenantId,
    pub plmn: Option<PlmnId>,
    pub snssai: Option<Snssai>,
}
```

Identity MAY come from mTLS SPIFFE, NRF-issued token claims, or a legacy
certificate mapping profile. Unsigned metadata headers MUST NOT establish
identity.

### 9.2 OAuth2 Validation

SBI producers that require OAuth2 MUST validate:

- issuer,
- audience,
- expiry and not-before,
- signature and key ID,
- scope,
- NF type and instance binding,
- tenant and slice binding where configured,
- replay-sensitive claims when configured.

Token validation results MAY be cached until the earlier of token expiry or
policy version change.

### 9.3 OAuth2 Client Credentials

SBI consumers MUST acquire tokens through NRF or configured authorization
server. Client authentication methods:

- SPIFFE JWT-SVID, preferred.
- mTLS-bound client authentication.
- Private key JWT.
- Kubernetes Secret client secret only in explicit compatibility profile.

Long-lived shared client secrets are forbidden in production carrier profiles
unless an RFC 006 waiver exists.

## 10. NRF Integration

### 10.1 Registration

`opc-sbi` MUST provide helpers for NF registration, update, deregistration, and
heartbeat.

NF profiles MUST be generated from typed NF metadata and canonical YANG. Raw
free-form JSON construction is forbidden outside test fixtures.

### 10.2 Heartbeats

The heartbeat driver MUST:

- derive interval from NRF response where present,
- jitter heartbeat timing,
- mark the NF degraded on repeated heartbeat failure,
- keep serving existing local traffic according to per-NF policy,
- deregister gracefully on shutdown when possible.

### 10.3 Discovery

The discovery client MUST provide:

- query construction with typed filters,
- response validation,
- cache with TTL and stale-if-error policy,
- negative caching,
- per-service-set load balancing,
- SCP preference where configured,
- tenant and slice filter enforcement.

Discovery cache entries MUST be invalidated on canonical config changes that
affect peers, PLMN, slice, trust anchors, or routing mode.

### 10.4 Subscriptions

NRF subscription handling MUST support retry, backoff, and dead-letter behavior
for failed notifications. Subscription callbacks MUST be authenticated and
authorized like any other SBI request.

## 11. Routing Modes

Supported modes:

| Mode | Behavior |
| :--- | :--- |
| `direct` | Consumer dials producer discovered from NRF or static peer config |
| `scp` | Consumer sends through SCP with routing headers |
| `sepp` | Inter-PLMN traffic goes through SEPP policy |
| `static` | Explicit peer list from YANG, for lab or interop |

The mode is selected per service, tenant, PLMN, and slice. Inter-PLMN traffic
MUST NOT bypass SEPP when policy requires SEPP.

## 12. Retry, Idempotency, and Callback Delivery

### 12.1 Retry Policy

Retry policy MUST be declarative:

```rust
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: Jitter,
    pub retry_on_status: Vec<StatusCode>,
    pub retry_on_transport_error: bool,
}
```

The framework MUST NOT retry non-idempotent requests unless the request carries
an idempotency key or the operation is explicitly marked idempotent by the
service definition.

### 12.2 Idempotency

For operations that can be retried, the framework SHOULD provide:

- idempotency key generation,
- inbound idempotency cache,
- replay-safe response caching,
- expiry and memory bounds.

### 12.3 Callback Delivery

Callback dispatchers MUST support:

- bounded queues,
- retry budget,
- backoff,
- callback authentication,
- dead-letter sink,
- observability,
- cancellation on subscription deletion.

Callback storms MUST be rate-limited per callback target.

## 13. Overload Control

### 13.1 Admission

The framework MUST provide admission control before request bodies are fully
read when possible.

Admission keys:

- peer identity,
- NF type,
- tenant,
- slice,
- service,
- operation,
- priority.

### 13.2 Response Semantics

Overload responses MUST use:

- HTTP `429` for rate limiting,
- HTTP `503` for temporary service overload,
- `Retry-After` where retry is appropriate,
- ProblemDetails with a stable cause code.

### 13.3 Priority

Requests with emergency, lawful, registration, paging, or charging criticality
MAY receive higher priority only when the per-NF spec and 3GPP behavior justify
it. Priority policy MUST be explicit, audited, and tested.

### 13.4 Circuit Breakers

Outbound circuit breakers MUST track:

- consecutive failures,
- error-rate window,
- latency outliers,
- half-open probes,
- per-peer and per-service state.

Circuit breaker state MUST be visible in metrics and debug endpoints without
exposing secrets or topology beyond authorized users.

## 14. Generated Models and OpenAPI

`opc-sbi` SHOULD generate models from version-pinned OpenAPI sources where
available. Generated code MUST:

- be reproducible,
- preserve unknown extension fields only when configured,
- avoid ad hoc stringly typed JSON in NF handlers,
- include spec tags for RFC 006,
- pass serialization round trips.

OpenAPI mismatches with normative 3GPP text MUST create RFC 006 known gaps or
generator overrides with citations.

## 15. Configuration Model

Each SBI NF YANG SHOULD expose:

- `sbi/listeners`
- `sbi/clients`
- `sbi/nrf`
- `sbi/oauth2`
- `sbi/retry-policy`
- `sbi/overload`
- `sbi/circuit-breakers`
- `sbi/callbacks`

These may be embedded under the shared `listeners`, `peers`, `rate-limits`,
and `policy` containers defined by the cloud-native pattern.

## 16. Observability

Required metrics:

- `opc_sbi_requests_total{nf,service,operation,outcome}`
- `opc_sbi_request_duration_seconds{service,operation}`
- `opc_sbi_problem_details_total{service,cause,status}`
- `opc_sbi_oauth_validation_total{outcome,reason}`
- `opc_sbi_nrf_discovery_total{outcome}`
- `opc_sbi_nrf_cache_entries{service}`
- `opc_sbi_nrf_heartbeat_total{outcome}`
- `opc_sbi_circuit_state{peer,service,state}`
- `opc_sbi_overload_rejections_total{service,reason}`
- `opc_sbi_callback_delivery_total{target,outcome}`

Tracing MUST propagate W3C `traceparent` and 3GPP correlation headers when
present.

## 17. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-sbi-problem` | ProblemDetails model and mappings |
| `opc-sbi-headers` | 3GPP header parse/render/redaction |
| `opc-sbi-auth` | OAuth2/JWT-SVID validation and token acquisition |
| `opc-sbi-nrf` | NRF registration, heartbeat, discovery, cache |
| `opc-sbi-client` | HTTP/2 pool, deadlines, retries, circuit breakers |
| `opc-sbi-server` | Axum/tower middleware, extractors, admission |
| `opc-sbi-callback` | Callback queues, retry, dead-letter |
| `opc-sbi-codegen` | OpenAPI/model generation |
| `opc-sbi-testkit` | Mock NRF, mock producer, token fixtures |

Agents must not implement NF-specific business logic in `opc-sbi`.

## 18. Testing Requirements

### 18.1 Unit Tests

- ProblemDetails mappings.
- Header parsing and redaction.
- Token validation matrix.
- Retry idempotency policy.
- Circuit breaker transitions.
- NRF cache expiry and invalidation.

### 18.2 Integration Tests

- Mock NRF registration, heartbeat, discovery, and token issuance.
- Producer validates mTLS and OAuth2 together.
- Consumer refreshes token before expiry.
- SCP routing header generation.
- Callback retry and dead-letter.
- Overload rejection with `Retry-After`.

### 18.3 Fault Injection

- NRF unavailable.
- Expired token.
- Bad JWK key ID.
- Peer certificate rotation.
- DNS failure.
- HTTP/2 stream reset.
- Slow callback target.
- Discovery cache stale while NRF down.

### 18.4 Performance Gates

- Hot token validation cache p99 under 25 microseconds.
- ProblemDetails mapping allocation-free for common static errors.
- Discovery cache lookup p99 under 10 microseconds.
- Client pool does not allocate per request beyond body/model needs.
- Overload admission rejects before full body read for oversized bodies.

## 19. Acceptance Criteria

This RFC is implemented when:

1. All SBI NFs use shared ProblemDetails, header, auth, retry, and NRF code.
2. OAuth2 validation and client-credential acquisition are test-covered.
3. NRF registration, heartbeat, discovery, and cache behavior are shared.
4. Retry behavior is idempotency-aware.
5. Overload control returns consistent 429/503/Retry-After semantics.
6. Circuit breaker state is observable and bounded.
7. Generated models are reproducible and evidence-tagged.
8. A shared SBI testkit can exercise producer and consumer behavior for every
   SBI NF.
