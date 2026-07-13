# OPC-SDK-RFC-003: Security Substrate

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
**Audience**: SDK implementers, security engineers, operator authors, NF teams

## 1. Abstract

This RFC defines the OpenPacketCore security substrate: workload identity,
transport security, authorization, key management, secret handling, audit
integrity, and runtime security administration. It integrates SPIFFE/SPIRE,
gNSI, NACM, AEAD envelope encryption, and tenant-aware policy into a coherent
boundary suitable for carrier-grade cloud-native network functions.

The initial draft correctly selected SPIFFE and gNSI, but it did not define a
strong enough multi-tenant carrier boundary, key lifecycle, replay controls, or
break-glass governance. This version makes those contracts explicit.

## 2. Security Objectives

### 2.1 Security

- Authenticate every workload and operator action with cryptographic identity.
- Authorize every operation by tenant, role, transport, method, and YANG path.
- Encrypt all sensitive persistent configuration and session state.
- Keep secret material out of logs, telemetry, panic messages, and ordinary
  gNMI reads.
- Provide tamper-evident audit and durable security event trails.
- Fail closed on invalid identity, unknown issuer, expired certificate, failed
  authorization, key lookup failure, or audit integrity failure.

### 2.2 Performance

- TLS rotation must not drop established data-plane sessions unless policy
  requires it.
- Authorization decisions must be cacheable and bounded.
- Crypto operations must use the RFC 001 crypto pool or equivalent offload so
  they do not starve async or data-plane workers.
- Security checks on high-rate paths must avoid heap allocation in the common
  case.

### 2.3 Maintainability

- Identity parsing, authorization, key lookup, and redaction must be separate
  modules with narrow APIs.
- Policy documents must be versioned, validated, and testable offline.
- Security defaults must live in one profile file, not scattered constants.
- The same security metadata must drive NACM, audit, and evidence generation.

### 2.4 Functionality

- Support SPIFFE X.509-SVID identity.
- Support trust domain federation.
- Support gNSI certificate and authorization services.
- Support break-glass with strict governance.
- Support tenant-aware policy.
- Support key rotation and historical decryption.

## 3. Threat Model

The SDK assumes attackers may:

- Control an unprivileged pod in the same Kubernetes cluster.
- Control another tenant namespace.
- Replay old management-plane requests.
- Attempt confused-deputy attacks through the operator.
- Read persistent volumes or backend snapshots offline.
- Corrupt local database files.
- Delay, drop, or reorder network packets.
- Trigger malformed gNMI, NETCONF, gNSI, or protocol inputs.
- Observe timing, status codes, and logs.
- Compromise a single NF replica.

The SDK does not claim to survive:

- Total compromise of the root trust domain signing keys.
- Compromise of the active KMS/HSM root keys without detection.
- Kernel-level compromise of the node running the NF.
- Malicious code compiled into the NF binary.

These residual risks MUST be documented in RFC 006 known gaps.

## 4. Identity Model

### 4.1 SPIFFE Workload Identity

Every NF replica MUST obtain an X.509-SVID from the local SPIRE Workload API.

Default SPIFFE ID format:

```text
spiffe://<trust-domain>/tenant/<tenant-id>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance-id>
```

The original namespace/service-account pattern is insufficient for
multi-tenant carrier isolation because namespaces are often operational
boundaries, not contractual tenant boundaries. `tenant-id` MUST be explicit
unless the deployment uses one trust domain per tenant.

### 4.2 Identity Claims

The SDK MUST parse the SVID into:

```rust
pub struct WorkloadIdentity {
    pub trust_domain: TrustDomain,
    pub tenant: TenantId,
    pub namespace: Namespace,
    pub service_account: ServiceAccount,
    pub nf_kind: NetworkFunctionKind,
    pub instance: InstanceId,
    pub spiffe_id: SpiffeId,
    pub expires_at: Timestamp,
}
```

Identity parsing MUST reject:

- Unknown path formats.
- Missing tenant.
- Invalid NF kind.
- Expired SVID.
- SVIDs with trust domains not present in the active bundle set.

### 4.3 Workload Attestation

SPIRE registration entries MUST bind identity to Kubernetes selectors such as:

- namespace
- service account
- pod label set
- node attestation policy
- image digest, when available through the attestor

The SDK MUST document the required SPIRE registration pattern. Relying only on
service account name is not sufficient for production carrier profiles.

### 4.4 Trust Domain Federation

Federation MUST be explicit. The SDK MUST load and validate trust bundles for:

- local workload trust domain
- management/operator trust domain
- optional peer-region trust domains

Federation policy MUST define which remote trust domains may perform which
actions. Accepting a federated bundle MUST NOT automatically grant management
privileges.

Example:

```toml
[[federation]]
trust_domain = "operator.openpacketcore.example"
allowed_tenants = ["tenant-a"]
allowed_roles = ["config-admin", "security-admin"]
allowed_transports = ["gnmi", "gnsi"]
```

### 4.5 Rotation

The SDK MUST watch SVID and bundle updates and hot-reload TLS acceptors and
clients without process restart.

Rotation requirements:

- New connections use the latest identity immediately after reload.
- Existing connections are reauthenticated on stream boundaries or at a
  configurable maximum connection age.
- Expired identities are not accepted.
- Bundle removal revokes future handshakes.
- Rotation failures emit critical telemetry.

For Kubernetes projected Secrets, production consumers MUST resolve one
relative `..data` target and read the leaf chain, key, intermediates, and trust
bundles directly from that immutable generation directory. Independently
following each user-facing file symlink is forbidden because an atomic
`..data` replacement can otherwise produce mixed material. A source MUST check
the generation after every read, discard a candidate if it changes, and stop
after a fixed retry and work budget.

`ProjectedSvidSource` implements this boundary with public exact limits: 1 MiB
for the chain file, 64 KiB for the key, 1 MiB per trust-bundle file, 4 MiB
total, 16 bundle files, 16 chain certificates, 128 trust anchors, and three
retries after the initial attempt. Each attempt has a five-second deadline.
Polling cannot be configured below 100 milliseconds. Paths must be normalized
relative paths below the projected generation. The source rejects non-regular
material files and never places paths, PEM, SPIFFE IDs, keys, or parser text in
status or events.

A validated candidate is published with a process-local monotonic generation.
Rollback is another publication and therefore advances that generation. An
invalid candidate retains the exact last-known-good identity, but never beyond
the leaf's expiry; expiry clears the identity and reports a typed unavailable
state. This source-level publication contract precedes #162's coherent
per-handshake TLS epoch and #163's bounded connection reauthentication.

`opc-tls::TlsMaterialController` MUST revalidate each identity state under fixed
certificate, trust-anchor, private-key, and aggregate byte bounds before it can
become handshake authority. It MUST pin the explicit local SPIFFE identity or
the first accepted identity, retain an invalid candidate's predecessor only
until leaf expiry, and assign every accepted update or rollback a new opaque
process-local epoch. Status and errors MUST contain only closed reason codes,
epoch, availability, and leaf expiry; identity text, paths, PEM, keys, and
parser/application error text are forbidden.

Every production handshake MUST freeze one controller snapshot before rustls
construction so certificate resolution and peer verification use the same
leaf/key/chain/trust material. After mutual TLS and application negotiation,
the caller MUST verify that epoch is still current before admitting the
connection. A changed epoch MUST discard the connection and retry within the
fixed SDK retry/concurrency limits. Tickets, resumption, early data, half-RTT
data, and 0-RTT MUST remain disabled. This admission record carries the exact
epoch and local leaf expiry; #163 separately owns retirement of connections
after admission.

## 5. Transport Security

### 5.1 gRPC Transports

gNMI, gNSI, and internal gRPC APIs MUST use mTLS with SPIFFE identity
verification.

Requirements:

- TLS 1.3 required by default.
- TLS 1.2 disabled by default and only allowed by explicit compatibility
  profile.
- Peer certificate SAN MUST contain a valid SPIFFE URI.
- Common Name MUST NOT be used for authorization.
- ALPN and service/method authorization MUST be enforced.
- Certificates MUST be validated against active SPIFFE bundles, not system web
  PKI.

### 5.2 Cipher Suites

Default modern profile:

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

FIPS profile:

- MUST use a FIPS 140-3 validated module and only approved algorithms.
- MUST document any difference from the modern profile.
- MUST disable algorithms not available through the validated boundary.

The SDK MUST expose the selected security profile in metrics and evidence.

### 5.3 NETCONF over SSH

If NETCONF/SSH is enabled:

- SSH host keys MUST be generated or provisioned through the security substrate.
- Client identity MUST map to a `TrustedPrincipal`.
- Password authentication MUST be disabled by default.
- SSH certificate authorities SHOULD be used when SPIFFE-native SSH identity is
  unavailable.
- SSH authorization MUST flow through the same NACM engine as gNMI.

## 6. Authorization

### 6.1 Principal Model

```rust
pub struct TrustedPrincipal {
    pub identity: WorkloadIdentity,
    pub tenant: TenantId,
    pub roles: Vec<Role>,
    pub groups: Vec<Group>,
    pub auth_strength: AuthStrength,
}
```

Roles and groups MUST come from signed policy or trusted identity attributes.
They MUST NOT be accepted from unsigned client metadata.

### 6.2 Policy Layers

Authorization is evaluated in this order:

1. Transport and peer authentication.
2. Trust domain allowlist.
3. Tenant boundary check.
4. gRPC service/method authorization.
5. NACM/YANG path authorization.
6. Operation-specific guardrails, such as break-glass or key export denial.

Any deny at any layer is final unless a governed break-glass flow applies.

### 6.3 NACM Requirements

NACM MUST authorize:

- `read`
- `create`
- `update`
- `replace`
- `delete`
- `exec`
- `subscribe`
- `security-admin`

The engine MUST evaluate all changed paths after patch expansion. It is not
enough to authorize the request's root path.

Authorization decisions SHOULD be cached by:

- principal digest
- tenant
- policy version
- normalized path
- action

Cache entries MUST be invalidated on policy updates and SVID rotation.

### 6.4 Multi-Tenant Boundary

Cross-tenant access is denied by default. A principal from tenant `A` MUST NOT
read or mutate tenant `B` config, session state, keys, or audit records unless a
federated policy explicitly grants a scoped operation.

The tenant boundary MUST be enforced in:

- identity parsing
- authorization
- persistence key namespace
- session key namespace
- audit query filters
- telemetry labels, with cardinality controls
- operator reconciliation

## 7. gNSI Services

The SDK MUST provide server-side support for:

| Service | Purpose | SDK Component |
| :--- | :--- | :--- |
| `gnsi.certz.v1` | Certificate and trust material distribution | `opc-gnsi-server` |
| `gnsi.pathz.v1` | Path authorization policy | `opc-nacm` |
| `gnsi.authz.v1` | gRPC service/method authorization | `opc-nacm` |

gNSI endpoints are security-critical. Access MUST require `security-admin` or a
more specific role. gNSI mutations MUST be audited and persisted through the
shadow-security store from RFC 001.

### 7.1 Shadow Security Store

Security material pushed through gNSI is stored in `shadow-security`.

Rules:

- Not visible through ordinary gNMI `Get`.
- Exportable only through explicitly authorized security APIs.
- Encrypted at rest with a distinct key purpose from normal config.
- Included in backup only when backup policy allows secret material.
- Redacted in audit and telemetry.

### 7.2 Policy Staging

Authorization policy updates MUST support validate-only and staged apply. A
policy that would lock out all security administrators MUST be rejected unless a
break-glass recovery policy exists.

## 8. Break-Glass

Break-glass is dangerous and MUST be treated as an exceptional workflow, not a
convenience override.

Requirements:

- Disabled by default in production profiles unless explicitly enabled.
- Requires a high-assurance principal.
- Requires reason, ticket/reference, requested scope, and duration.
- Maximum default duration: 15 minutes.
- Requires dual authorization or an externally signed emergency token in
  carrier profiles.
- Cannot bypass cryptographic verification, tenant boundary, or audit logging.
- Cannot export raw key material unless a separate key recovery policy allows it.
- Emits critical audit events at start, use, and expiry.
- Emits high-priority telemetry.

Break-glass must grant the narrowest possible action set and path set.

## 9. Key Management

### 9.1 Key Hierarchy

The SDK uses purpose-separated keys:

| Purpose | Example Use |
| :--- | :--- |
| `config` | RFC 001 encrypted config blobs |
| `shadow-security` | gNSI security material |
| `session` | RFC 004 session store data |
| `audit` | HMAC hash chains |
| `backup` | encrypted export bundles |

Keys MUST be separated by KMS key ID or HKDF `info` labels. Reusing one raw key
for multiple purposes is forbidden.

### 9.2 Key Sources

Production profiles MUST obtain root or wrapping keys from one of:

- KMS plugin.
- HSM plugin.
- Kubernetes Secret encrypted by a cluster KMS provider, only for lower
  assurance profiles.
- SPIRE/SVID-authenticated key service.

Environment variables are forbidden for production key material.

### 9.3 Key Lookup API

```rust
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    async fn get_active_key(&self, purpose: KeyPurpose, tenant: &TenantId)
        -> Result<KeyHandle, KeyError>;
    async fn get_key_by_id(&self, key_id: &KeyId)
        -> Result<KeyHandle, KeyError>;
    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId)
        -> Result<KeyId, KeyError>;
}

#[async_trait::async_trait]
pub trait RemoteSealProvider: Send + Sync {
    async fn seal(&self, aad: &EnvelopeAad, plaintext: &[u8])
        -> Result<EncryptedPayload, KeyError>;
    async fn unseal(&self, key_id: &KeyId, aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}
```

`KeyHandle` MUST avoid exposing raw bytes unless required by the crypto module.
If raw bytes are materialized, they MUST be zeroized after use where the crypto
backend permits.

For remote sealing, `key_id` MUST come from a canonical, validated envelope.
It selects the exact historical remote key and MUST NOT be replaced by the
provider's current active key. `KmsRemoteSealProvider` snapshots one coherent
`RemoteSealMaterialController` epoch before each encrypt request. Active-key
publication affects only future seals; in-flight requests keep their snapshot.
The controller retains only the current ID and opaque process-local epoch. It
does not cache historical key material or authorization decisions, persist its
epoch, watch a source, coordinate pods, or produce a fleet-comparable epoch.
Each unseal calls the remote provider for the exact envelope key ID.

### 9.4 Rotation

Key rotation MUST support:

- New writes using the active key.
- Old reads using key ID from the envelope.
- Optional background re-encryption.
- Retention windows.
- Emergency key revocation.

If a key is unavailable, the SDK MUST fail closed for writes and for reads that
require the missing key.

For remote-seal rotation, KMS/HKMS is the authority for historical retention,
revocation, and physical retirement. The SDK supplies exact historical-key
selection and bounded live-state scan inputs, but it has no rewrap campaign,
dependency-proof object, retirement API, or enforcement gate and cannot block
an external KMS retirement. Operators MUST provision the new key before
publishing it active, retain every old key while any artifact can reference it,
and enforce retirement externally only after a composite proof:

- a separately implemented rewrap has completed and a bounded,
  snapshot-bound, write-fenced scan verifies the resulting live state;
- retained Raft logs and snapshots have been compacted, expired, or inspected
  and verified independently; and
- backups, restore inputs, rollback checkpoints, and other offline sources have
  been inspected and then rewrapped, deleted, or retained with the old key.

A deployment-specific finite retention/TTL proof MAY replace rewrap only when
it covers every live and replayable source and no record is unbounded. A restore
scan alone does not prove logs, snapshots, backups, restore sources, or rollback
artifacts. A partial or stale scan, concurrent writes, an unavailable source,
or an ambiguous result blocks the operator's retirement decision. Emergency
KMS revocation remains fail closed and may intentionally make dependent records
unreadable.

`RemoteSealProvider::unseal`'s historical `KeyId` argument is a breaking source
API change. Provider implementations and callers MUST be upgraded together.
It does not change the durable envelope or consensus/session wire format; the
KMS request framing/schema is unchanged, but decrypt request contents now use
the historical envelope ID. A code rollout MUST keep the old ID active until
every reader, writer, and custom provider has stopped or upgraded, passed
readiness, and can unseal by exact ID. Only then may the fleet publish a new
active ID; upgraded pods may temporarily seal under different IDs because all
upgraded reads select the envelope key.

Material rollback MUST first verify that KMS can encrypt/decrypt with the old ID
and decrypt with the new ID, then republish the old ID on every upgraded process
and verify new writes use it while both epochs remain readable. The new ID MUST
remain retained while any artifact depends on it. Rolling back to a pre-change
binary is safe only before a new ID is published, or after a complete
rewrap/artifact proof has returned all dependencies to one key; otherwise use a
coherent pre-publication checkpoint restore.

## 10. AEAD Envelope Encryption

### 10.1 Default Profile

Default persistent encryption uses `AES-256-GCM-SIV` for misuse resistance.
Nonce reuse is still a bug and MUST be monitored.

### 10.2 FIPS Profile

Some FIPS validated modules may not expose AES-GCM-SIV. A FIPS profile MAY use
`AES-256-GCM` only when:

- Nonces are generated by a validated DRBG or deterministic counter scheme.
- Nonce uniqueness is guaranteed per key.
- The uniqueness state is crash-safe.
- Tests prove duplicate nonce detection.

The active AEAD algorithm MUST be recorded in each envelope and in RFC 006
evidence.

### 10.3 Associated Data

AAD MUST bind ciphertext to:

- tenant
- purpose
- tx/session identifier
- schema digest or state type
- key ID
- version
- principal, for config commits

AAD mismatch MUST produce a generic integrity error without exposing which
field failed.

### 10.4 Replay and Rollback

Encryption alone does not prevent replay of an old valid blob. The management
store MUST enforce monotonic config versions as specified in RFC 001. Session
store backends MUST use generation numbers or lease fencing as specified in RFC
004.

## 11. Audit Security

### 11.1 Hash Chain

Audit records MUST include:

```text
entry_hmac = HMAC(audit_key, tenant || sequence || canonical_entry || previous_hash)
```

The hash chain MUST be tenant-scoped and purpose-separated. Startup MUST verify
the local audit chain unless the operator explicitly configures degraded
recovery mode.

### 11.2 External Audit Sink

Carrier profiles SHOULD stream audit events to an external append-only system.
Local SQLite audit is necessary for recovery and debugging but is not sufficient
against host-level compromise.

### 11.3 Time

Audit timestamps MUST use UTC. The SDK SHOULD record both wall-clock timestamp
and monotonic sequence number. Security decisions MUST NOT rely only on wall
clock when monotonic ordering is required.

## 12. Redaction

The redaction subsystem consumes metadata generated by RFC 002.

Redaction MUST apply to:

- `Debug`
- structured logs
- audit records
- metrics labels
- error messages
- traces
- panic hooks where possible
- gNMI read responses after NACM filtering

Redaction MUST preserve enough information for debugging, such as value
presence, length class, or stable digest when explicitly allowed by policy.

## 13. Observability

Required metrics:

- `opc_security_authn_total{outcome,reason,transport}`
- `opc_security_authz_total{outcome,reason,action}`
- `opc_security_svid_expires_seconds`
- `opc_security_bundle_version`
- `opc_security_rotation_total{kind,outcome}`
- `opc_security_key_lookup_total{purpose,outcome}`
- `opc_security_breakglass_active`
- `opc_security_breakglass_total{outcome}`
- `opc_security_audit_chain_verify_total{outcome}`
- `opc_security_redactions_total{source}`

Metrics MUST control label cardinality. Raw SPIFFE IDs SHOULD be exposed through
logs, not high-cardinality metrics, unless explicitly enabled.

## 14. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-identity` | SPIFFE ID parsing, SVID watch, trust bundle watch |
| `opc-tls` | TLS acceptor/client reload and peer extraction |
| `opc-authz` | Principal, roles, method policy, decision cache |
| `opc-nacm` | YANG path authorization and RFC 8341 semantics |
| `opc-gnsi-server` | gNSI service handlers and staged policy apply |
| `opc-key` | KeyProvider trait and KMS/HSM adapters |
| `opc-crypto` | AEAD envelopes and key derivation |
| `opc-redaction` | Secret metadata and safe rendering |
| `opc-audit` | HMAC chain, external sink adapter |
| `opc-security-testkit` | fake SPIRE, fake KMS, policy fixtures |

Agents must not mix transport identity parsing with NACM path logic. Each module
should have deterministic test fixtures and no hidden global state.

## 15. Testing Requirements

### 15.1 Unit Tests

- SPIFFE ID parser accepts valid pattern and rejects malformed identities.
- Federation allowlist denies unknown trust domains.
- Authorization cache invalidates on policy version change.
- NACM denies missing rules.
- Redaction covers generated secret fields.
- AEAD envelope rejects wrong AAD, wrong key, corrupted tag, and wrong tenant.
- Break-glass scope and TTL enforcement.

### 15.2 Integration Tests

- SVID rotation without process restart.
- Kubernetes `..data` replacement during every projected-material read phase,
  proving that no mixed generation is published.
- Projected-material exact-limit/one-over, last-good retention, expiry,
  rollback-generation, and redaction tests.
- TLS material rotation during every handshake/application phase, exact
  epoch/expiry admission, identity continuity, rollback, repeated-rotation
  retry exhaustion, concurrent-operation bounds, cancellation, and redaction.
- Trust bundle rotation revokes removed trust domain.
- gNSI policy staging and rollback.
- Management commit rejected after NACM policy update removes permission.
- Shadow-security store not visible through ordinary gNMI `Get`.
- Key rotation reads old commits and writes new commits.
- External audit sink outage does not drop local audit.

### 15.3 Fault Injection

- SPIRE socket unavailable.
- Expired SVID.
- Corrupt trust bundle.
- KMS timeout.
- Missing historical key.
- Duplicate AEAD nonce detector trigger, when applicable.
- Audit HMAC mismatch.
- Break-glass token replay.

### 15.4 Performance Gates

- Authorization decision cache p99 under 50 microseconds for hot entries.
- TLS reload completes without blocking new accepts longer than 100
  milliseconds on reference hardware.
- Key lookup cache hit p99 under 25 microseconds.
- Redaction of a 10 MiB config audit diff completes within configured commit
  budget.

## 16. Acceptance Criteria

This RFC is implemented when:

1. Every management connection is authenticated with SPIFFE-aware mTLS or an
   explicitly configured SSH identity profile.
2. Tenant identity is explicit and enforced across authz, persistence, audit,
   and telemetry.
3. gNSI services can stage, validate, apply, audit, and roll back security
   policy.
4. Config, shadow-security, session, and audit keys are purpose-separated and
   rotatable.
5. AEAD envelopes bind ciphertext to tenant, purpose, version, and schema/state
   metadata.
6. Break-glass is scoped, time-limited, audited, and disabled by default in
   production unless carrier policy enables it.
7. Security failure modes fail closed and are covered by fault injection tests.
