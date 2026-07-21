# Changelog

All notable changes to the OpenPacketCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking: urgent SWm mobility/feature/local-address context — `opc-proto-diameter`:**
  `SwmDiameterEapRequest` adds optional typed MIP6 mobility capabilities,
  ordered Supported-Features offers, and a presence-redacted UE local IP;
  `SwmDiameterEapAnswer` adds typed mobility authorization and ordered
  Supported-Features responses. The codec enforces the Release 19 M-bit,
  result-conditioning, collective PMIP6/GTPv2, grouped-child provenance, and
  unknown-child preservation contracts. Existing struct literals add `None`,
  `Vec::new()`, and `None` respectively; absent fields retain prior wire bytes
  (#352). Consumers must carry the request context into every multi-round DER;
  this focused slice does not complete the broader #352 authorization-context
  checklist, which remains open.
- **Mandatory SWm Diameter-EAP State encoding — `opc-proto-diameter`:** typed
  DER and DEA builders now set the RFC 4005 mandatory bit on every ordered,
  opaque State AVP. The dictionary accepts the RFC-permitted protected bit on
  receive, while originated messages use the canonical unprotected profile
  and diagnostics expose only State counts (#442).
- **Breaking generated key API; fail-closed YANG list keys — `opc-yanggen`:**
  generated RFC 7951
  deserialization now rejects incomplete single or composite keys and exact
  duplicate keys with stable value-free errors instead of defaulting missing
  leaves or replacing earlier rows. Generated diagnostics redact non-public
  single and composite map keys by construction while preserving serde,
  ordering, borrowed lookup, gNMI, NETCONF, and synchronized explicit
  redaction behavior. Non-public single-key maps now use `SensitiveKey<T>`;
  callers inserting an owned key wrap it with `.into()` or
  `SensitiveKey::new`, and both `Debug` and `Display` remain redacted (#434,
  #435).
- **Breaking: `opc-ipsec-lb` Host-XDP backend rework (#308):** the Host-XDP
  tier now executes keyless classification and destination-scoped owner
  steering in the kernel instead of SPI-tag steering. `HostXdpTarget`,
  `HostXdpTagTarget`, and `HostXdpClusterChannelSecurity` were removed, and
  `HostXdpSteeringBackend` no longer implements the `SteeringBackend` port:
  SPI-keyed `SteeringRule`s cannot express the destination-scoped
  ownership keys and fenced generations the datapath now executes.
  The backend gained an owner-record API (`install_owner`/`remove_owner`/
  `owner_record`), monotonic `advance_fence`, per-verdict `counters`,
  explicit cross-process prepare/adopt handoff, and typed Linux 5.18
  kernel-floor enforcement
  (`IpsecLbError::XdpKernelFloorNotMet`). The pinned map ABI changed
  (owner map keyed by the canonical ownership key, separate fence map,
  versioned config ABI v4). The runtime recognizes strict v1-v4 namespaces,
  preserves the maximum durable fence, stages fresh bounded A/B namespaces,
  and atomically updates the exact retained BPF link with expected-old
  compare-and-replace. Owner pins are emptied and verified before handoff;
  interrupted evidence-last cleanup remains recoverable without regressing
  the fence. A permanent per-interface `control` inode serializes cooperating
  processes for the full ready lifetime. The loader requires effective
  `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, admits only XDP `bpf_link` attachments,
  and rejects legacy netlink fallback. Readiness validates the configured
  bpffs pin root and target/redirect interfaces; redirect hand-off is disabled
  by default; and `Native` truthfully means Aya's kernel-selected zero-flag
  mode. XDP sends every current IANA-registered IPv6 extension kind except
  direct native ESP to the userspace slow path, and public diagnostics redact
  packet and topology identities.
- **Interrupted Host-XDP link-state queries — `opc-ipsec-lb`:** graceful XDP
  handoff now makes up to three bounded retries of the complete `RTM_GETLINK`
  snapshot when the kernel reports an interrupted or overrun dump. Every retry
  starts from an empty observation; malformed, contradictory, oversized, or
  repeatedly interrupted replies remain fail-closed (#436).

### Added
- **Sealed monotonic outbound ESP counter authority — `opc-ipsec-xfrm`:** a
  namespace-bound Linux actor now binds one durable operation/fence to an
  opaque exact OUT policy plus SA, performs transient constant-time key
  validation, advances only through `XFRM_MSG_NEWAE`, and requires exact final
  readback before issuing a bounded, redaction-safe receipt. Equal retries are
  idempotent, already-advanced state never rolls backward, and admitted work
  survives observer cancellation. Proof validation is bound to the exact live
  namespace actor even when another namespace has identical durable SA state.
  A separate read-only process-loss recovery path issues
  committed-recovery-only evidence that cannot authorize a fresh ownership
  fence and requires an independently proven committed fence before resumed
  publication. Privileged namespace proof covers cross-namespace receipt
  rejection, a restored ESN counter, and the first real ESP packet (#333).
- **Counter-authorized Host-XDP re-pin composition — `opc-ipsec-lb`,
  `opc-ipsec-xfrm`:** durable ESP requests now retain only the exact outbound
  SA binding identity, while live actor-derived target and receipt sets remain
  process-local. The coordinator revalidates the counter before ownership and
  again under a single-use actor publication guard at the Host fence-last cut;
  cancellation, expiry, ignored backend errors, counter regression, and
  first-publication counter advancement all fail closed. Host-XDP ABI v5 adds
  destination-scoped keyed fences, owner-first/fence-last activation,
  fence-first retirement, crash-safe namespace migration, and bounded
  quarantine for indeterminate cleanup. The generic re-pin coordinator now
  composes directly with Host-XDP without reverting to the unsafe SPI-only
  adapter (#333, #444).
- **Epoch-bound live session-consensus membership — `opc-session-store`,
  `opc-session-net`:** adds restart-safe, idempotent 3→5→3 topology transitions
  with exact descriptor binding, learner catch-up markers, joint-consensus
  sequencing, terminal-first pre-joint abort with candidate tombstones,
  forward-only post-joint recovery, replicated application-authority fencing,
  and redaction-safe durable evidence. Successor transport admits replication
  before joint commit but keeps Vote and application traffic closed until their
  distinct committed authority proofs; abort cleanup is restart-safe after
  response loss. The exact consensus profile advances to wire revision 3/error
  revision 5, and the legacy compatibility error set advances to revision 9,
  so older peers fail during profile admission rather than decoding the new
  topology barrier or authority-revoked result (#353).
- **Redaction-safe SWm ASR/RAR replay comparison — `opc-proto-diameter`:**
  `SwmAbortSessionRequestEnvelope` and `SwmReAuthRequestEnvelope` now compare
  complete immutable request payloads while excluding only Hop-by-Hop, T-bit,
  and authenticated expected-peer changes permitted across failover (#418).
- **Admitted IKEv2 CERTREQ authority hashing — `opc-proto-ikev2`:** adds a
  bounded exact-DER `SubjectPublicKeyInfo` input and redaction-safe 20-octet
  RFC 7296 section 3.7 Certification Authority hash. The SHA-1 operation runs
  only through the installed `IkeCryptoModule`, has its own explicit
  `Ikev2CryptoRequirements` authorization independent of NAT-D, and rechecks
  module evidence, readiness, capability, operation support, provider success,
  and output width on every call with no implicit fallback (#412).
- **Typed TS 24.302 P-CSCF restoration exchange — `opc-proto-ikev2`:** adds
  a bounded, order-preserving, redaction-safe IPv4/IPv6 address-list
  `CFG_REQUEST` builder plus a strict decoder for an already-authenticated and
  opened `INFORMATIONAL` `CFG_REPLY`. The request forwards every PGW-provided
  P-CSCF address in exact order, including repeats, as an exact RFC 7651 value;
  replies must contain exactly one empty acknowledgement for every requested
  family. Unsupported Configuration attributes and RFC 7296 non-critical
  extensions are retained, while error Notify and critical or semantically
  invalid payloads fail closed. Exact IKE SPI, exchange, direction, and Message
  ID correlation is available before product state changes (#426).
- **SWm DER access authorization context — `opc-proto-diameter`:**
  `SwmDiameterEapRequest` can now encode and decode typed `RAT-Type` and
  redacted `Service-Selection` fields with their exact 3GPP/IETF vendor, flag,
  type, and singleton rules. The request boundary rejects malformed APN label
  syntax, duplicates, malformed values, and Service-Selection on emergency requests;
  raw-wire tests cover the WLAN/VIRTUAL enum mapping and conditional APN
  profile (#352).
- **Cancellation-safe staged XFRM composite install — `opc-ipsec-xfrm`:**
  `XfrmStagedInstall::run` consumes the staged value, establishing one runner
  at compile time (#402). On first poll it moves the operation and an `Arc`
  backend into an owned Tokio worker, so dropping the observing future cannot
  race recovery against an adapter's still-running `spawn_blocking` mutation.
  A caller-cloned `XfrmInstallJournal` records every unobserved install or
  rollback operation and transfers a successful install to product ownership
  through the shared `Committed` state. Recovery uses an exact, generation-bound
  `XfrmInstallRecoveryPlan`, requires an explicit `Owned`, `Absent`, `Foreign`,
  or `Indeterminate` classification for every candidate, runs policy-first,
  treats `NotFound` as idempotent absence, and serializes recovery across all
  clones. Recovery itself runs in an owned worker, so dropping its observer
  cannot let a same-identity replacement overtake an issued removal; actual
  worker termination records a permanent, typed supervision-loss state and
  disables in-process recovery because detached blocking work may still
  complete. A fresh process must re-establish writer exclusion and
  authoritative readback before acting. Multiple simultaneous uncertainties are retained,
  composite outcomes report possible residue consistently, and all journal,
  plan, classification, ownership, and error `Debug` surfaces omit keys,
  addresses, selectors, and SPIs.
- **Identity-safe drained eBPF v2 teardown — `opc-gtpu-dataplane`:** adds the
  maintenance-only `GtpuDataplaneBackend::teardown_drained_v2` boundary with an
  explicit caller drain attestation, exact interface identity, typed refusal
  and partial-progress evidence, and a durable retry proof. The eBPF backend
  acquires its normal exclusive reconciler lease, proves the complete frozen
  endpoint-unbound v2 program/map/hook identity, requires both exact hooks before
  the first proof, independently requires empty forwarding/session state, and
  revalidates every surviving pin and map before each unlink. Hook absence is
  accepted only on proof-backed retry; foreign, non-directory, symlink, or
  indeterminate objects are preserved. State appearing after proof commit stops
  cleanup with a distinct partial outcome and requires a renewed drain. The
  proof is removed only after an exact proof-only inventory, so interrupted
  hook/pin cleanup is idempotently retryable; its presence also fences normal
  create/adopt until teardown returns removed or already absent. Once both
  hooks, every recorded map, and the proof are authoritatively absent, cosmetic
  directory-removal failure remains terminal success rather than creating an
  unfenced retry state. A parse-only child module exposes only derived tags from
  the frozen historical v2 artifact to production. Unit failure-injection and an
  isolated, no-traffic privileged load of the hash-pinned v2 object prove
  refusal, real program-to-map binding, every partial phase, durable retry,
  exact hook/pin cleanup, and subsequent fresh source-port-v4 provisioning.
  The proof is bound to its own kernel map ID and full ABI, and every retry
  revalidates recorded program tags against the frozen artifact and scans both
  hook directions for same-name extras or cross-direction legacy programs
  before mutation. Missing pin
  state is accepted only when target-bound dumps find no legacy SDK program at
  any priority or handle, so a historical non-default tc priority cannot be
  misreported as absent.
  Hook ownership is accepted only after an uninterrupted, zero-status multipart
  dump whose sequence, local netlink port ID, interface, clsact parent, and
  protocol match; overrun, malformed completion, or duplicate owner evidence
  remains indeterminate.
- **Typed GTP-U control-procedure codec foundation — `opc-proto-gtpu`:** adds
  strict typed Echo Request/Response, canonical receiver-ignored `Recovery=0`,
  Error Indication with IPv4/IPv6 peer address and optional UDP Port extension,
  Supported Extension Headers Notification, End Marker, Recovery Time Stamp,
  repeatable Private Extension, and bounded unknown-TLV handling. Extension
  types now expose TS 29.281 endpoint/intermediate comprehension semantics;
  unsupported comprehension-required headers fail with stable value-free
  diagnostics while optional unknown headers remain skippable/raw-preserved.
  Standardized but procedure-inapplicable extension types are rejected
  separately, the supported-header list permits the specification-defined zero
  count, and the PDU Session Container QFI/PPI/RQI subset rejects reserved
  types and unmodelled conditional-field flags instead of partially decoding.
  Its validated DL/UL constructors and now-fallible `encode` reject reserved
  types, oversized QFI/PPI, and direction-incompatible fields rather than
  masking or discarding them. Control diagnostics retain typed PDU reasons and
  the offending extension offset; decoded optional unknown extensions survive
  UDP Port/PDU Session Container mutation. Typed End Marker canonical encoding
  rebuilds the container from its semantic value, clears receiver-ignored spare
  bits, and puts it first while preserving every unrelated optional unknown
  header in relative order; generic raw-preserving encoding remains byte-exact.
  Control encoding preflights bounded IE count and exact final wire capacity
  before serializing payload bytes; canonical Recovery Time Stamp builders can
  no longer emit arbitrary extension data.
  TEID, address, private value, and raw packet data remain absent from typed
  `Debug` and errors. This is the codec-only first slice of #341: backend-
  neutral datagram ports, Linux/eBPF integration, responder/rate policy, and
  live parity evidence remain open and no production qualification is claimed.
  Migration: inactive `GtpuHeader::next_ext_type` is now `None`; use
  `raw_next_ext_type` for the receiver-ignored octet. Callers must handle the
  `Result` from `PduSessionContainer::encode` and
  `GtpuErrorIndication::with_triggering_udp_source_port`. Exhaustive public
  error matches must include the new reason-bearing PDU/extension-chain and
  duplicate-container variants. Typed End Marker callers that previously
  expected accepted non-canonical PDU Session Container bytes or extension
  placement to survive `to_bytes` must use the generic raw-preserving boundary
  for byte-exact forwarding.
- **Bounded outer-fragment and uplink PMTU handling — `opc-gtpu-dataplane`
  (#345):** the eBPF GTP-U dataplane now has a complete contract for
  fragmented outer packets and uplink MTU growth.
  `CreateGtpDeviceRequest::uplink_mtu_policy` carries an explicit
  `GtpuUplinkMtuPolicy` (effective link MTU plus the outer-fragmentation
  choice) whose `inner_mtu()` accounts the fixed 36-byte encapsulation
  headroom; `None` preserves any persisted policy, and
  `EbpfGtpuDataplaneBackend::set_uplink_mtu_policy` mutates a live device
  atomically. `decide_uplink_encap` in `opc-gtpu-ebpf-common` returns a
  typed outcome — `Emit` with headroom (DF stamped and checksum refreshed
  under the strict policy), `RequiresOuterFragmentation` (a host action that
  does not claim the oversized packet was emitted), or
  fail-closed `RejectTooBig` carrying RFC 1191 ICMPv4 / RFC 8200-8201 ICMPv6
  Packet-Too-Big guidance. The eBPF backend rejects the host-only
  `RequireOuterFragmentation` policy because tc redirect cannot execute it;
  every configured over-MTU eBPF packet is a silent, counted drop (no ICMP
  from the kernel path — operators size the inner MTU out of band). Host
  callers can generate the wire signal with the new
  `build_icmpv4_packet_too_big`/`build_icmpv6_packet_too_big` helpers. The
  tc uplink program enforces the decision from the additive single-slot
  `GTPU_PMTU_CFG` map (committed under the `OPC-PMTU-v5` schema marker; the
  all-zero slot is the legacy behavior, so v3/v4 pin sets upgrade in place
  and a committed v5 set that loses an MTU map fails closed; adoption and
  read-back are indeterminate on corrupt policy bytes). Over-MTU rejects
  and the corrupt-policy canary are separate `GTPU_PMTU_DROP` slots,
  surfaced as `uplink_mtu_rejected` and `uplink_mtu_policy_corrupt` in the
  identity-bound snapshot; `effective_uplink_mtu_policy` reads the
  effective policy back. The inner packet is never leaked unencapsulated,
  and under the strict policy the encapsulation never exceeds the
  effective MTU. Downlink outer fragments follow the reported
  `GtpuDownlinkFragmentContract::KernelReassemblyHandoff` — handoff-capable
  only, requiring an operator-run consumer on the concrete S2b-U address —
  where tc passes fragments to the stack, the kernel reassembles under
  bounded `ipfrag` limits (reported from live sysctls, absent when
  unreadable), and the new `GtpuReassemblyConsumer` mirrors the tc PDR
  resolution (dual-map/zero-mark corruption fails closed), binding, and
  marked-owner authorization on the reassembled datagram exactly once,
  with fixed-cardinality typed counters and a sealed `GtpuReassemblySocket`
  that applies `SO_BINDTODEVICE` before its concrete IPv4 UDP/2152 bind,
  verifies kernel device/address identity around every receive, and accepts a
  zero reassembled `IP_PKTINFO` ifindex only through that kernel-enforced
  identity. The socket also exposes safe `SO_RCVBUF` sizing/readback and has no
  unbound wrapping path; creation normally requires Linux `CAP_NET_RAW`.
  Linux also exposes bounded typed `/proc/net/snmp` reassembly stats readback,
  including timeouts and aggregate overlap/resource failures. `GtpuProbe`
  reports `uplink_pmtu_enforcement` and `downlink_outer_fragment_handling`
  per backend: only the eBPF backend reports its live-proven reassembly
  handoff; Linux `gtp`, mock, and unsupported backends report the contract
  missing, and reject configured policies fail closed.
- **Configurable stable uplink GTP-U UDP source ports — `opc-gtpu-dataplane`
  (#346):** `GtpPdpContext::uplink_source_port_policy` selects, per PDP
  context, the UDP source port stamped by the eBPF uplink encapsulator while
  the destination remains the TS 29.281 section 4.4.2 service port 2152.
  `GtpuUplinkSourcePortPolicy::LegacyServicePort` is the explicit pre-feature
  fixed-2152 behavior with byte-for-byte identical wire bytes;
  `GtpuUplinkSourcePortPolicy::selected(port)` persists one stable
  per-context port in the new additive `GTPU_UL_SPORT`/`GTPU_ULM_SPORT` maps.
  Each map value is a fixed 68-byte commit record containing the complete FAR,
  DSCP, local TEID, endpoint binding, publication phase, and explicit
  big-endian source port. Userspace writes `Pending` before component maps,
  publishes `Active` last, writes `Removing` before deletion, and deletes the
  commit record last. Both tc directions accept only an `Active` record whose
  complete live graph matches exactly, so a crash-mixed or transitional graph
  cannot carry traffic. Restart recovery removes a `Pending` or `Removing`
  graph to proven absence, with the commit record removed last, and can resume
  after interruption at every mutation boundary. Legacy is also stored
  explicitly as 2152: pre-feature active contexts are materialized as complete
  commit records before the v4 program or `OPC-SPORT-v4` marker becomes
  authoritative. A missing, zero, malformed, unowned, or mixed committed-v4
  record fails adoption/read-back and drops in both tc directions rather than
  silently falling back. The reserved port zero and the redundant
  `Selected(2152)` representation fail closed at policy construction or the
  userspace map boundary; the effective port is carried through reconciliation,
  restart adoption, and PDP read-back, appears in conflict evidence only as the
  `UplinkSourcePortPolicy` field name, and is redacted from `Debug`. The new
  `GtpuProbe::uplink_source_port_selection`
  capability gates eBPF policy state fail-closed; the Linux `gtp`, mock, and
  unsupported backends report `Missing` and reject non-legacy policies.
  Downlink peer source-port validation (`downlink_source_port_policy`) remains
  independently configurable.
- **Typed external routing-stack prefix intent — `opc-ipsec-lb`:** adds a
  bounded, declarative exact-host-prefix reconcile boundary grouped by opaque
  routing domain, with per-prefix typed outcomes, injected-clock lease and
  monotonic-generation gating, ordered session/prefix/BFD observations,
  redacted snapshots, and a deterministic conformance fake. The concrete BIRD
  2 adapter atomically owns one exact-set fragment per domain, verifies applied
  routes and each established peer's exact local export view through the
  documented control protocol, validates and durably clears stale fragments
  before child launch, proves configured protocols absent before admitting
  traffic, and keeps withdrawal intent absent while boundedly confirming a
  queued reconfiguration or fail-stopping the owned process. It fails
  closed on refusal, ambiguity, malformed replies, drift, cancellation, or
  bounded-resource exhaustion. A non-forgeable local-process admission supervises
  foreground BIRD through the SDK helper's versioned nonce handshake and Linux
  parent-death signal, so loss of the service/helper boundary terminates the
  owned local process instead of leaving it detached; the supervisor retains
  child ownership until kernel wait status is available. Launch artifacts and
  socket/fragment namespaces are descriptor-pinned. No configured reap deadline
  or local export view is represented as remote installation evidence. BGP/BFD policy,
  peer selection, and application-health admission remain product
  responsibilities. Gated real-BIRD and
  deterministic adversarial tests cover advertisement, exact withdrawal,
  session relay, lease expiry, cancellation, durable drift, and process death.
- **Validated-provider capability seam — `opc-crypto-provider`:** a new
  standalone crate defining the capability-reporting and key-custody boundary
  requested by #334 (slice 1 of 5). `CryptoCapability` enumerates the
  security-critical operation families (TLS, IKE hash, IKE PRF, IKE integrity, IKE
  encryption, IKE signature, IKE Diffie-Hellman, approved entropy,
  zeroization, sealed key storage) and `CapabilitySet` is fail-closed: an
  unreported or unknown capability never reads as available and the default
  set is empty. `ProviderIdentity` binds a bounded, printable-ASCII module
  name and version to every report; `ValidationState` defaults to
  non-validated and records only a module's self-declared validation claim —
  the SDK does not verify, certify, or imply external certification of any
  module or deployment. `SelfTestOutcome`, `SelfTestEvidence`, and
  `ModuleReadiness` withdraw a capability when its self-test fails, when the
  self-test cannot run, or when readiness is lost, and the withdrawal is
  visible in the bounded, redaction-safe `CapabilityReport` evidence, which
  can carry no key material by construction. `ProviderPolicy::admit` fails
  closed with typed missing-capability and validation errors and is the only
  constructor of `PolicyAdmission`, so no operation can be admitted past a
  rejected policy and no implicit software fallback exists. The async
  `CryptoModule` trait exposes identity, capabilities, self-test, and
  readiness; slice 3 now composes it with IKEv2 operations through
  `IkeCryptoModule`, while TLS and `opc-key` custody remain later work. This
  provider crate implements no cryptographic algorithm. A configurable
  `FakeCryptoModule` behind the `testkit` feature lets tests satisfy an
  advertised capability set and then drop a capability, fail the self-test,
  or lose readiness to prove the fail-closed behavior end to end.
- **Fail-closed `SecurityInit` startup hook — `opc-runtime`:** the previously
  placeholder `SecurityInit` phase now runs an optional fallible
  `StartupPhases::init_security` callback (type alias `SecurityInitFn`,
  mirroring `init_telemetry`), the enforcement point requested by #334
  (slice 2 of 5). An `Err` — wrapped in the new
  `BootstrapError::SecurityInit` variant — makes `Builder::build` fail
  before `ConfigBootstrap`, `ResourcePreflight`, `ServiceBind`, and
  `PeerWarmup`, so the runtime binds no service listener when, for example, a
  policy-required cryptographic capability is not effective on the selected
  module. That guarantee covers runtime-mediated listeners: `init_logging` and
  `init_telemetry` run in earlier phases, so anything they bind — a metrics
  scrape endpoint, for instance — already exists and is not torn down. The
  failure is fatal in every runtime mode; mode-conditional
  leniency belongs inside the callback, which receives the
  `RuntimeProfile`. `opc-runtime` takes no dependency on
  `opc-crypto-provider`: consumers wire `probe_capability_report` and
  `ProviderPolicy::admit` into the hook themselves (proven end to end in
  tests with the `FakeCryptoModule` testkit). A new
  `known_gates::CRYPTO_PROVIDER` health-gate name carries the admission
  evidence (a bounded `CapabilityReport` fits in `HealthGate::details`) for
  observability only — the startup hook, not the gate, is what prevents
  traffic. Absent hook, startup behavior is unchanged. `StartupPhases` gains a
  public field, so construct it with `..Default::default()` rather than an
  exhaustive struct literal.
- **Process-wide admitted IKEv2 cryptographic module —
  `opc-crypto-provider`, `opc-proto-ikev2`:** completes #334 slice 3 by
  composing evidence and the synchronous hash, entropy, PRF, integrity,
  encryption, Diffie-Hellman, and signature operation traits into one
  `IkeCryptoModule` object. `install_ikev2_crypto_module` probes and applies
  `ProviderPolicy`, preflights every configured typed algorithm, then sets an
  immutable process slot; failed preflight leaves it unset and there is no
  production or `testkit` fallback. Every operation rechecks the exact module
  identity/validation declaration and the full policy-granted capability set
  against live advertisement/readiness before dispatch. Opaque DH and signing
  handles are gated again when used. Successful hash, PRF/PRF+, integrity,
  AEAD/CBC, and DH results must match their algorithm-derived widths; AEAD
  results must retain the requested explicit IV, ECDSA signatures must be
  valid curve-specific DER scalars, and RSA signatures must match the opaque
  key handle's public modulus width. DH public values are semantically
  validated and snapshotted, and DH/signing handles must retain their admitted
  identity at use time. Child-SA PFS groups
  can be named separately from their ESP KEYMAT profile during preflight.
  Provider contract violations are rejected as stable `InvalidOutput` failures.
  Signature generation and verification requirements are distinct, preserving
  default-build RSA peer verification while RSA private signing remains
  feature-gated. `CryptoOperationError`
  exposes stable codes without provider-native source text, secret outputs use
  zeroizing buffers, and production CBC IVs come from the same admitted
  module's `ApprovedEntropy` operation. The explicit
  `Ikev2SoftwareCryptoModule` delegates to the existing RustCrypto paths and
  declares `NotValidated`; it makes no certification claim. Existing AES-GCM,
  AES-CBC/HMAC, PRF/KDF, NAT-D, DH, IKE_AUTH signature, rekey, restore, and
  dedicated-bearer crypto call sites now route through admission with their
  stable protocol errors preserved. Consumers install the module from the
  async `StartupPhases::init_security` hook and propagate the newly fallible
  NAT-D helpers. This is source-breaking for exhaustive downstream matches:
  add `CryptoModuleFailure { error }` to `Ikev2SaInitCryptoError`,
  `Ikev2ProtectedPayloadCryptoError`, `Ikev2IkeAuthVerificationError`, and
  `Ikev2SignatureKeyError` matches, and add `CryptoModuleFailure` to
  `Ikev2SaInitCryptoErrorCode` and `Ikev2ProtectedPayloadCryptoErrorCode`
  matches. Existing semantic variants and codes are unchanged. TLS and
  `opc-key` custody remain later #334 slices.

### Fixed
- **Linux 6.8 GTP-U eBPF verifier compatibility — `opc-gtpu-dataplane`:**
  reduces the bounded checksum callback frame so the complete downlink call
  chain remains below Linux 6.8's cumulative 512-byte BPF stack limit without
  changing checksum coverage, endpoint binding, PDR, commit-record, or owner
  validation. The committed object is regenerated, both classifiers are
  load-gated on exact Linux 6.8.0-134 in CI, and `BPF_PROG_LOAD` rejection now
  maps to the redaction-safe typed `GtpuError::ProgramLoadRejected` rather than
  an undifferentiated I/O failure (#427).
- **Table-scoped Linux route readback — `opc-route-steering`:** route
  convergence now classifies only candidates in the requested address family,
  destination prefix, and routing table. An unrelated table's non-unicast or
  otherwise unrepresentable route can no longer make an exact route
  indeterminate merely because both use the same prefix, including
  `0.0.0.0/0`; unrepresentable candidates in the requested table remain
  fail-closed. Unit and privileged network-namespace regressions cover the
  public-VRF unreachable-default plus uplink-default shape (#420).
- **Exact IKEv2 signature trust-material DER parsing:**
  `Ikev2SignaturePublicKey` now rejects bytes following an otherwise valid
  SubjectPublicKeyInfo or X.509 certificate instead of silently ignoring them.
  The new `SpkiTrailingData` and `CertificateTrailingData` errors provide
  stable, redaction-safe classification at configuration trust boundaries;
  exhaustive matches on `Ikev2SignatureKeyError` must add those variants.
- **Zeroizing retained SWm lifecycle identities — `opc-proto-diameter`:** adds
  the reusable redaction-safe `Sensitive<T>` owner, whose current allocation
  is zeroized on drop and independently protected across clones. Typed STR/STA
  facts, request/answer envelopes, and correlated exchanges now retain
  `Session-Id` and permanent `User-Name` in that owner without changing wire
  bytes, request/answer correlation, or diagnostic output. `Redacted<T>`
  remains the diagnostics-only wrapper for values without a memory-lifetime
  contract. Migration: direct STR construction must provide
  `Sensitive<String>` for `session_id` and `user_name`; string literals and
  owned strings continue to work through `.into()`.
- **Complete public SWm lifecycle acceptance — `opc-proto-diameter`:** adds one
  compiler-external, deterministic public-API fixture covering a successful
  DER/DEA establishment followed by RAR/RAA, AAR/AAA, and ePDG STR/STA, plus a
  separate successful DER/DEA session followed by inbound maintained-state
  ASR/ASA and the derived administrative STR/STA. Every exchange crosses the
  exported builder/parser envelope boundary and correlates exact Diameter
  transaction, application, command, direction, P/T/E flags, session, user,
  connection generation, and logical Origin as applicable. Canonical rebuilds
  and committed retries are byte-identical, diagnostics remain redacted, and
  the fixture leaves session lookup, authorization, transport, retries,
  teardown ordering, and side effects downstream. This completes the generic
  typed SWm lifecycle scope requested by #351 without changing the crate's
  broader experimental Diameter status.
- **Typed SWm Abort-Session boundary — `opc-proto-diameter`:** adds TS 29.273
  ASR/ASA command definitions, typed redaction-safe request/answer models,
  bounded parsers, request-bound deterministic builders, and exact transaction,
  P-bit, ordinary-answer Session-Id, permanent-identity, Proxy-Info, and
  overload-control correlation. Outbound envelopes require an opaque
  authenticated connection-generation token and optionally constrain a direct
  host or routed realm using ASCII case-insensitive DiameterIdentity matching;
  Destination AVPs are never peer-authentication evidence. Generic E-bit errors
  skip only logical-Origin policy and remain connection-bound. The request
  parser retains Diameter's T bit while every ASA clears it. Same-Hop T/non-T
  duplicates rebuild byte-identical committed responses; failover atomically
  replaces the connection binding and Hop-by-Hop Identifier while preserving
  End-to-End duplicate identity and response AVPs. Required ASR omissions retain
  sealed provenance for checked 5005 construction, including the
  procedure-mandated User-Name. Command metadata is the single additional-AVP
  occurrence authority for typed and conservative dictionary decoding: ASR
  permits repeated `Class` and `Reply-Message` while keeping `State` singleton;
  ASA permits repeated `Failed-AVP` and dictionary-level `Redirect-Host` while
  keeping `Class`, `State`, redirect usage, and cache time singleton. Canonical
  RFC 6733 redirect definitions validate flags, widths, and bounded DiameterURI
  grammar, but typed ASA rejects redirect context until result 3006 semantics
  are modeled. ASR explicitly rejects answer-only error and redirect fields,
  and an undeclared extension wildcard remains singleton.
  At the ePDG, a successfully built and committed maintained-state ASA derives
  an administrative STR fact set from the inbound ASR envelope;
  `NO_STATE_MAINTAINED` and unsuccessful ASAs produce explicit no-STR
  dispositions. The AAA-side correlated exchange does not claim ownership of
  this ePDG-originated transition. Independent wire fixtures, hostile-input cases, corpus seeds,
  and fuzz dispatch cover the modeled boundary. Session lookup, exactly-once
  teardown, duplicate-cache lifetime, exact encoded-byte replay, fresh STR
  transaction allocation, transport, retry, and compensation remain product
  responsibilities.
- **Typed SWm authorization-information update boundary — `opc-proto-diameter`:**
  adds TS 29.273 RAR/RAA command 258 and AAR/AAA command 265 definitions,
  redaction-safe typed models, bounded builders/parsers, sealed missing-AVP
  provenance, exact identifier/session/user/proxy/overload correlation, typed
  AAR flags and UE address state, base or experimental AAA results, and typed
  successful APN projection. Outbound envelopes require an authenticated
  connection-generation token plus an explicit direct, realm-routed, or routed
  logical-Origin policy instead of treating Destination AVPs as authentication
  evidence. Generic RFC 6733 E-bit agent errors retain their actual grammar,
  accept permitted missing application fields, skip only logical-Origin policy,
  and remain connection- and transaction-bound. A public type-state sequence
  commits the RAA, enforces the immediate matching AAR, caches byte-identical
  T-clear ordinary retries, exposes an explicit failover-only transition that
  atomically replaces the Hop-by-Hop Identifier and peer binding, and correlates
  the terminal AAA without owning product session policy. Independent wire
  fixtures cover all roles, the published AAA ABNF R-bit editorial error,
  proxy drift, result families,
  canonical Table 7.2.3.1/2 flag handling, hostile input, bounds, replay, and
  redaction. Decode ignores understood M-bit mismatches as required by the
  table note while encode remains canonical, including M-clear
  UE-Local-IP-Address. Command-derived additional-AVP rules preserve repeated
  RAA/AAA Failed-AVP and Reply-Message, declare RAR Reply-Message singleton,
  and expose the optional answer-side Re-Auth-Request-Type as a typed value.
  Canonical RFC 6733 Session-Timeout, Authorization-Lifetime, and
  Auth-Grace-Period definitions add typed SWm request/answer timer fields with
  exact command roles: RAA/AAR admit lifetime and grace, AAA additionally
  admits TS 29.273 Session-Timeout, and RAR admits none. Singleton/type/flag
  checks, positive-lifetime re-auth requirements, timeout/lifetime ordering,
  success-class AAA enforcement of the AAR lifetime ceiling,
  zero/absent/maximum semantics, value-free diagnostics, independent fixtures,
  and corpus coverage fail closed before product policy,
  while rejecting wrong-role lifecycle/diagnostic state and AAR Class. Request
  roles forbid redirect-only state; answer metadata retains
  RFC 6733 Redirect-Host repeatability, while typed parsing and emission reject
  every redirect context until the complete result surface is modeled.
  Experimental-Result-only 3xxx AAA emission fails closed because it cannot
  satisfy the generic E-bit grammar. Session lookup, duplicate-cache
  lifetime, retry timers, authorization policy, and side effects remain
  downstream. Migration: downstream exhaustive matches on `AuthRequestType`
  must add `AuthorizeOnly`; wire value 2 now projects to that named variant
  instead of `Other(2)`.
- **Typed SWm Session-Termination boundary — `opc-proto-diameter`:** adds
  TS 29.273 STR/STA command definitions, typed redaction-safe request/answer
  models, bounded parsers, and request-bound builders. Envelopes preserve both
  Diameter identifiers, P, exact `Session-Id`, and ordered Proxy-Info. Outbound
  envelopes require an opaque authenticated connection-generation token and
  optionally constrain a direct host or routed realm using ASCII
  case-insensitive DiameterIdentity matching; answer correlation rejects
  connection, identifier, present Session-Id, logical-Origin-policy, or
  Proxy-Info drift without inferring identity from Destination AVPs.
  RFC 6733 generic E-bit answers, including permanent-failure fallback, may
  omit Session-Id and then correlate by transaction, P, and the exact
  Proxy-Info chain; intermediary-origin errors skip only optional logical-Origin
  matching and remain connection-bound. The request-bound builder
  emits only the fully modeled `DIAMETER_SUCCESS` (2001),
  `DIAMETER_UNKNOWN_SESSION_ID` (5002), and `DIAMETER_UNABLE_TO_COMPLY` (5012)
  contexts with RFC-correct E-bit handling; received non-redirect base results
  remain forward-compatible projections, while unmodeled redirect 3006 fails
  closed. Repeated RFC 6733 `Class` state is preserved through the redacted
  extension surface. Dictionary-known additional AVPs are value-validated on
  decode and encode, and RFC 7683 OC plus RFC 8583 Load groups receive bounded
  child, flag, type, duplicate, unknown-M, and offer/answer validation.
  Originated DRMP and Load clear M while recognized inbound M mismatches follow
  the TS 29.273 table-note tolerance without weakening other flag checks. A loss
  overload selection requires an offer, while an answer without the capability
  is correctly treated as a non-reporting node; originating a loss report
  additionally requires its reduction percentage. Missing required
  STR AVPs, including the procedure-table-mandatory permanent User-Name, use
  the existing sealed parser-provenance path to checked 5005 responses despite
  the reused command CCF marking User-Name optional. Initial outbound requests
  clear T, while a one-way envelope transition marks queued, unacknowledged
  state resent after link failover/recovery, atomically installs the replacement
  connection plus a caller-reserved Hop-by-Hop Identifier, and preserves the
  End-to-End Identifier and AVPs; ordinary timer retries do not set T.
  Independent wire fixtures
  and hostile-input tests cover
  cardinality, wrong role/vendor/type/application, grouped AVPs, limits,
  extension preservation, non-ASCII DiameterIdentity rejection,
  retransmission shape, same-hop byte-identical success/error replay,
  failover-hop replay equivalence, direct/routed peer binding, and diagnostics.
  Active session lookup, identifier allocation, response caching, teardown
  ordering, retry, and compensation remain downstream.
- **Request-bound Diameter missing-AVP provenance — `opc-proto-diameter`:**
  additive provenance-aware CER, DWR, DPR, and SWm DER parsers now retain the
  original `DecodeError` plus sealed exact-Diameter-message and numeric command/
  application/vendor-aware AVP identity. The checked parser-error mapper
  verifies the exact SDK AVP schema, derives the dictionary's minimum
  `Failed-AVP`, proves root or received-parent-relative absence, and binds
  result code 5005 without consumer-owned grammar or reason-string matching.
  RFC 6733 `Vendor-Specific-Application-Id` missing-one-of failures report both
  Auth/Acct child examples; mutually exclusive received children bind 5009
  with only those exact children in wire order. SWm `Terminal-Information`
  missing IMEI is covered by the same received-parent proof.
  `DiameterRequestFailure` gains `MutuallyExclusiveAvps`; downstream exhaustive
  matches on this newly introduced, unreleased enum must add an arm. Its result
  and stable diagnostic code remain in the existing 5009 family.
  Legacy parser signatures and non-missing decode-error mapping are unchanged;
  cross-request reuse, mismatched or untrusted provenance, and missing,
  conflicting, or ambiguous dictionary definitions fail closed.
- **Conflict-safe PDP-context reconciliation — `opc-gtpu-dataplane`:** the
  additive backend trait now supports redaction-safe readback by local TEID or
  uplink identity, dual-selector classified install, validated mismatch-only
  conflict evidence, separate reconciliation capabilities, and authority-safe
  exact removal. Existing third-party backends retain source compatibility
  through typed unsupported defaults. The eBPF adapter reconstructs complete
  default/marked v3 graphs under its reconciler lease and exact program/map
  identities, including a rebuilt host-only default UE-to-TEID index, without
  changing the datapath schema. The Linux adapter performs strict stable
  generic-netlink GETPDP readback and classified NEWPDP reconciliation,
  including independently typed inner MS/PAA and outer peer families; exact
  removal remains unavailable because mainline Linux has neither compare-delete
  nor a cross-process writer lease. The mock provides stateful parity and
  redaction-safe corrupt/transitional/changing fault injection through a
  separate reconciliation log that preserves its established operation enum.
- **Durable session-level multi-SA re-pin — `opc-ipsec-lb`:** new
  `SessionRePinPlan`, `SessionRePinCoordinator`, and
  `SessionStoreRePinJournal` APIs bind one privacy-preserving session identity
  and operation identity to a canonical bounded IKE/default-ESP/dedicated-ESP
  order and every exact `RePinRequest` fingerprint. The session-store-backed v1
  journal retains completed per-SA fences and any current post-commit fence,
  resumes exact requests after process restart, rejects a competing active
  plan, and exposes success only after every SA durably completes fencing,
  steering, and final audit. Later operations require
  `SessionRePinPlan::new_successor` with the exact previous terminal
  fingerprint, preventing a stale completed retry from replacing newer restart
  authority. Successors must also use fresh operation and per-SA transition
  identities, while resume/status use an exact redaction-safe
  operation-plus-plan token. Before a later mutation or terminal success, every
  completed prefix first has all steering reconciled, then crosses a separate
  global mutation-free exact-proof sweep whose monotonic fences provide the
  linearization point. Pre-commit first-SA failure is quarantined; any known partial
  commit requires forward convergence and can never fall through to ownership
  birth/upsert. Public saga diagnostics contain counts and stages only.
  Every production journal read/write fails closed after a backend authority
  capability downgrade. Production wiring reuses the existing quorum, payload
  encryption, and HKMS/KMS lifecycle without a parallel authority; the mock
  journal is test only. Consumers migrating from sequential per-SA loops must
  prepare the full ordered plan before mutation, call `start` once, call
  `resume` with the same privacy-safe session ID and `SessionRePinIdentity`
  after interruption, retain the
  terminal fingerprint for the next failover, and claim continuity only from a
  terminal `SessionRePinOutcome`. This does not claim the adapter-issued
  applied-counter evidence tracked by #333.
- **Fenced terminal session re-pin retirement — `opc-ipsec-lb`:** the typed
  journal and coordinator retirement boundary now accepts only the exact
  terminal session/operation/plan identity, replaces its byte-compatible v1
  checkpoint with an encrypted, fenced-CAS v2 tombstone, and makes ambiguous
  retries idempotent across restart. Prepared or forward-converging plans,
  stale predecessor/successor identities, and losing concurrent generations
  fail closed without discarding known ownership progress. Tombstones bind
  their retirement and record-expiry timestamps to one fixed seven-day
  interval; retries never extend it, the existing per-key TTL bounds cleanup,
  and callers must use non-reused privacy-safe session IDs with shorter retry
  horizons after cleanup. Exact version dispatch makes older v1-only SDKs fail
  closed on tombstones. The private tenant/NF/session key,
  `EncryptingSessionBackend`, quorum authority, and HKMS/KMS rotation path are
  unchanged.
- **BREAKING — fail-closed eBPF GTP-U downlink endpoint binding —
  `opc-gtpu-dataplane`:** every tc downlink PDR now carries a canonical binding
  to its outer peer, concrete local destination, address family, ingress
  ifindex, and explicit bounded UDP source-port policy. Missing, corrupt, or
  mismatched state drops before inner delivery and advances one of six fixed
  redaction-safe aggregate counters. Fresh install, exact peer relocation,
  rollback, marked-owner journaling, removal, restart adoption, snapshot
  identity, and probe readiness all include the binding and counter maps.
  Populated endpoint-unbound graphs are never interpreted as permissive state:
  committed v2 pins require drain/reprovision, and older populated graphs fail
  closed. `GtpPdpContext` literals must add
  `downlink_source_port_policy: GtpuSourcePortPolicy::{Any, Exact, ...}`;
  consumers must gate eBPF traffic readiness on
  `GtpuProbe::downlink_endpoint_binding == Available`. The backend-neutral
  `GtpuDownlinkEndpoint` API models canonical IPv4/IPv6 identity while the
  current tc adapter remains explicitly IPv4-only. The Linux `gtp` backend
  preserves prior behavior for explicit `Any`, rejects narrower policies, and
  reports the exact-binding capability as missing.
- **BREAKING — typed conditional S2b session context — `opc-proto-gtpv2c`:**
  Create Session now uses `S2bCreateSessionIdentity` for subscriber versus
  UICC-less emergency identity and a new `S2bCreateSessionContext` for
  AAA/HSS-provenanced MSISDN, PCO/APCO, Recovery, Charging Characteristics,
  Trace Information, WLAN location/timestamp, UE local/NAT endpoint data, and
  the separately typed optional Fixed Broadband ePDG IKEv2 endpoint. Delete
  Session now requires `S2bDeleteSessionContext` with its mandatory S2b UE
  Local IP, optional procedure-specific UDP/TCP ports, WLAN context, and an
  explicitly Diameter- or IKEv2-discriminated release cause. Canonical builders
  enforce the different Create/Delete instances and block profile-owned fields
  from `additional_ies`; ProcedureAware receive discards wrong known instances,
  preserves unknown optionals, validates endpoint/emergency dependencies, and
  exposes redaction-safe context projections. New typed
  `ChargingCharacteristics`, exact-length `TraceInformation` with typed
  `SessionTraceDepth`, and `RanNasCause` IE codecs are public. IKEv2 release
  causes use the validated `Ikev2ErrorNotifyType`; `RanNasCause::ikev2` is
  fallible and rejects higher-range Notify types above 16383. Existing
  Create callers must replace `imsi` with `identity` and add `context`; Delete
  callers must add the required endpoint context. No feature flag is required.
- **BREAKING — RFC 7296 receiver-ignored fields — `opc-proto-ikev2`:** network
  decode now accepts higher IKEv2 minor versions, ignored Version/Critical bits,
  and receiver-ignored reserved fields in fixed/generic headers, SA
  Proposal/Transform structures, ID, AUTH, KE, TS, CP, and CP attributes while
  retaining every structural, major-version, unknown-critical, integrity, and
  authentication check. `Ikev2ValidationProfile::SenderCanonical` preserves
  opt-in outbound-fixture diagnostics, and typed builders continue to emit
  zero. Decoded `Ikev2IdentificationPayload` gains the exact three-octet
  `reserved` field, and `to_payload_body()` now preserves it so AUTH verifies
  the received ID body byte-for-byte instead of silently canonicalizing it.
  Downstream struct literals must initialize `reserved`; decoded values should
  pass `to_payload_body()` directly into AUTH transcript construction.
  Exhaustive downstream error matches must also handle
  `Ikev2SaPayloadError::ReservedNonZero` and
  `Ikev2IkeAuthBuildError::ConfigurationAttributeTypeTooLarge`.
- **Complete eBPF GTP-U downlink envelope validation — `opc-gtpu-dataplane`:**
  the tc ingress datapath now binds variable-IHL IPv4 Total Length, UDP Length,
  and GTP-U Length to one exact nested boundary, validates the complete IPv4
  header and every non-zero UDP checksum unless Linux positively reports
  `CHECKSUM_UNNECESSARY`, trims only legal layer-2 padding, and drops malformed
  UDP/2152 candidates before PDR lookup with the existing bounded counter.
  `CHECKSUM_NONE`, `CHECKSUM_COMPLETE`, and metadata-helper failures require a
  reversible non-pseudoheader checksum probe followed by exact byte
  verification. The probe distinguishes complete bytes and legal zero IPv4
  UDP omission from any pending `CHECKSUM_PARTIAL` operation, restores the
  exact original bytes, and fails closed on every helper or restoration error.
  Pending checksums are never trusted or repaired, even when their current
  bytes happen to satisfy the final checksum equation. Full-range software
  checksumming uses the bounded `bpf_loop` helper so maximum-length IPv4 UDP
  packets remain within the kernel verifier's finite state budget.
- **BREAKING — S2b UE-initiated IPsec tunnel update — `opc-proto-gtpv2c`:**
  Modify Bearer Request no longer requires or emits the S5/S8 Bearer Context
  shape on S2b. New `S2bUeIpsecTunnelUpdateRequest` and
  `s2b_ue_ipsec_tunnel_update_request` APIs model independently optional WLAN
  Location/Timestamp values and a typed Fixed Broadband endpoint whose UDP
  port cannot exist without its local IP address. Typed IP Address, Port
  Number, complete bounded TWAN Identifier, and TWAN Identifier Timestamp
  codecs use their exact TS 29.274 instances and redact subscriber endpoint
  and location values from `Debug`. Extendable tunnel-update IEs accept their
  known Release 18 prefix while raw-preserving message encode retains later
  suffixes; TWAN receive ignores spare flags and canonical encode zeroes them.
  The relay FQDN bound accounts for RFC 1035's terminating root label.
  Procedure-aware receive retains the first applicable singleton and optional
  ePDG Overload Control Information instance 2, discards known unexpected
  Bearer Context/wrong-instance fields under clause 7.7.9, and exposes
  request/response correlation summaries including response Cause. The old
  bearer-context-shaped `s2b_modify_bearer_request` is deprecated and fails
  closed; callers must migrate to `s2b_ue_ipsec_tunnel_update_request` and
  select either `S2bUeIpsecTunnelUpdateEndpoint::General` or `FixedBroadband`.
- **BREAKING — S2b Create Session PAA profile — `opc-proto-gtpv2c`:**
  `S2bCreateSessionRequest` no longer accepts or emits the top-level PDN Type
  IE prohibited by TS 29.274 Table 7.2.1-1 Note 1. The required PAA now owns
  the requested IPv4, IPv6, IPv4v6, Non-IP, or Ethernet family. Explicit
  dynamic and AAA-static constructors validate family/address shape; the S2b
  sender rejects IE 99 even through `additional_ies`, while ProcedureAware
  receive discards an unexpected IE 99 under clause 7.7.9 and continues.
  Callers must remove `pdn_type` and construct `paa` with
  `PdnAddressAllocation::{dynamic_*,static_*,non_ip,ethernet}`.
- **S2b Create Session Response control endpoint — `opc-proto-gtpv2c`:**
  accepted responses now encode, require, and project the PGW S2b GTP-C
  F-TEID at instance 1/interface type 32 instead of treating instance-0 Sender
  F-TEID as the response endpoint. The profile rejects a wrong interface,
  zero TEID, or missing address and preserves first-occurrence receive
  semantics. The public accepted-response input/summary field is renamed from
  `sender_f_teid` to `pgw_control_f_teid`; the corresponding stable projection
  errors now name the PGW control role.
- **TS 29.274 singleton repetition — `opc-proto-gtpv2c`:** ProcedureAware S2b
  receive now retains the first occurrence of each non-repeatable IE key per
  exact top-level or Bearer-Context-instance scope, ignores later occurrences,
  discards message-grammar-known unexpected type/instance keys before
  interpreting their values, preserves unknown optional keys, and ignores
  declared-list excess at its table bound. The grammar applies explicit S2b
  applicability for exact endpoint roles; typed projections enforce endpoint
  value semantics and correlation.
  `decode_with_diagnostics` exposes bounded redaction-safe duplicate metadata;
  canonical builders remain strict and reject duplicate singleton input.
- **BREAKING — fail-closed Diameter SCTP protection contract — `opc-sctp`:**
  the deprecated `DiameterSctpSecurity::Dtls` compatibility selector no longer
  maps ordinary SCTP payloads to PPID 47. It returns the typed
  `diameter_sctp_protected_transport_unavailable` error before configuration
  validation, socket setup, or payload framing. New
  `DiameterSctpPeer::new_unprotected` and
  `DiameterSctpAssociation::connect_unprotected_with_config*` APIs make the
  remaining PPID-46 path explicit, while every peer carries the sole typed
  `DiameterSctpProtection::Unprotected` value; PPID-0 compatibility stays
  bounded, direction-specific, and default-off. PPID metadata, SCTP readiness,
  health, and metrics make no DTLS or protected-transport claim. The named
  `DIAMETER_DTLS_SCTP_PPID` constant is removed so ordinary
  `SctpAssociation` callers cannot mistake raw PPID-47 metadata for a protected
  Diameter path. Existing callers must replace `new` with `new_unprotected`,
  replace `connect_with_config*` with the corresponding
  `connect_unprotected_with_config*` method, and use a real protected transport
  rather than the rejected legacy `Dtls` option.
- **Typed IKEv2 protected-payload open failures — `opc-proto-ikev2`:** `SK`
  and `SKF` provider errors now pass through `open_protected_payloads` as their
  original type instead of being reduced to `Display` text. The concrete
  SA_INIT-key provider exposes exact authentication, structural-length, and
  authenticated-padding codes for local diagnostics while retaining one
  uniform outer provider-rejection classification for peer-visible policy.
- **Consensus cold-establishment liveness — `opc-session-net`:** one bounded
  per-peer singleflight now carries DNS/TCP/mTLS/identity/bootstrap work across
  a short Openraft caller deadline without carrying request bytes across that
  cancellation boundary. Later callers can claim the staged authenticated
  connection; configuration identity, TLS material, explicit reauthentication,
  lifecycle expiry, and pool shutdown invalidate it before dispatch.

### Changed
- **Certificate-generation test dependency:** upgraded `rcgen` from 0.13.2 to
  0.14.8 and migrated every certificate fixture, including generated gNMI
  scratch source, to its typed `CertifiedIssuer`/`Issuer` signing API. Existing
  root, intermediate, workload, validity, and trust-rotation test semantics are
  preserved; production TLS, key storage, HKMS, and encrypted-at-rest paths are
  unchanged.

### Added
- **Initiator-side IKE-SA rekey exchange boundary — `opc-proto-ikev2`:** the
  typed IKE-SA rekey boundary now covers the initiating side of the RFC 7296
  `CREATE_CHILD_SA` exchange. A request builder emits the exact immutable
  `SA, Ni, KEi` cleartext chain from one product-selected executable profile,
  a caller-allocated non-zero eight-octet new initiator SPI, and exact
  Ni/KEi, offering a single proposal numbered one with IKE Protocol ID and
  the profile's exact transform set; a zero SPI or a KEi group/length that
  does not match the offered profile fails closed before anything is sent. A
  strict opened-`SK` response decoder validates the `CREATE_CHILD_SA`
  response header, including the caller-supplied established IKE-SA SPI
  pair, and accepts exactly one SA, Nonce, and KE payload whose single
  proposal echoes the offered profile with a non-zero eight-octet new
  responder SPI and whose KEr uses the negotiated group's exact public-value
  length. Vendor IDs, unrecognized status-range Notify payloads (`>= 16384`),
  and unknown non-critical payloads follow the same RFC 7296 mandatory-ignore
  preservation policy as the responder boundary, but any error-range Notify
  (`< 16384`) in a response fails the exchange per RFC 7296 §3.10.1 with a
  typed peer-error carrying only the Notify Message Type and Protocol ID,
  regardless of the unknown-IE policy — a responder declining the rekey with
  only `TEMPORARY_FAILURE` or `NO_PROPOSAL_CHOSEN` therefore yields that
  typed peer-error (feeding the §2.25 retry rules) instead of a
  missing-payload failure. Child-SA `REKEY_SA`, ESP/AH, TSi/TSr, other known
  payloads, missing/duplicate required payloads, unknown critical payloads
  (classified distinctly from other chain failures), proposal
  count/number/SPI/transform mismatches, and KE group/length mismatches fail
  closed with stable redaction-safe typed errors before any key derivation.
  Decoded responses expose the selected profile, responder SPI, nonce, DH
  group, and responder public value directly to the existing DH agreement
  and rekey KDF APIs. Specification-authored AEAD and AES-CBC/HMAC vectors
  audit byte-exact request encoding, initiator/responder boundary interop,
  and response decoding. Message-ID allocation and correlation,
  simultaneous-rekey collision policy, `SK` protection, retransmission,
  cutover, rollback, Child-SA inheritance, and old-SA deletion remain
  caller-owned.
- **Authoritative owned route/rule collection reconciliation —
  `opc-route-steering`:** additive `OwnedRouteRuleScope`,
  `OwnedRouteRuleSet`, and `OwnedRouteRuleSnapshot` APIs let Linux and mock
  backends enumerate and reconcile one complete, explicitly allocated
  protocol-`242` writer scope. Same-family/same-priority rules can now coexist
  when they are source-only, non-wildcard, and provably prefix-disjoint; exact
  duplicates, overlap, unrepresentable owned state, wildcard selectors, and
  ambiguous or foreign target collisions fail closed. Reconciliation takes
  bounded complete snapshots, installs and verifies all desired objects before
  garbage collection, removes orphan rules before routes, and finishes with an
  exact snapshot, allowing a restarted process to remove stale owned state
  without retained in-memory attempt history. It is serialized among clones of
  one backend, but separate instances are not serialized and the operation is
  not kernel-atomic. Partial or uncertain completion returns typed redaction-safe
  `ReconcileIncomplete` phase/count evidence, including a separate typed
  rollback-failure classification when attempted cleanup is incomplete, and
  never treats an incomplete dump as proof of absence. Mutation progress is
  counted only after exactly one matching zero-error netlink ACK; missing,
  duplicate, `DONE`, or arbitrary transaction replies fail closed. Desired and
  final sets admit at most `50,000` routes and `50,000` rules each; the
  install-before-delete old∪new intermediate admits at most `100,000` routes
  and `100,000` rules. Reconciliation's initial recovery snapshot accepts that
  transient bound so a restart can garbage-collect an interrupted old∪new
  residual; public and successful final snapshots retain the lower bound. The
  default Linux hard envelope for each complete dump is `65,535` datagrams,
  `131,072` decoded messages, and `64 MiB` of aggregate reply bytes.
  Default-limit synthetic Linux gates classify `50,000` owned routes plus
  `50,000` source-disjoint, same-priority owned rules returned by exactly one
  `AF_UNSPEC` route-dump request and one `AF_UNSPEC` rule-dump request, and
  separately pass `50,000` multipart messages through the production
  byte/datagram/message accounting parser. This proves bounded snapshot
  enumeration capacity, not `50,000` kernel mutations, atomic application, or
  end-to-end reconciliation throughput. The mock covers the same collection
  semantics without per-key reads; it does not broaden that kernel evidence.
  The new `owned_route_rule_collection` attempt capability is separate from
  singleton and legacy mutation support. On Linux it permits a fail-closed,
  self-verifying bootstrap and is not `FRA_PROTOCOL` retention attestation;
  only `LinuxRuleProtocolCapability::Confirmed` records positive tagged
  readback, while cached rejection/discard disables later attempts. Protocol
  `242` remains a namespace-local
  reservation rather than authentication, so the declared scope requires one
  exclusive orchestrated writer. Existing singleton convergence and
  static/untagged legacy APIs retain their behavior.
- **Typed IKE-SA rekey exchange boundary — `opc-proto-ikev2`:** a strict
  responder-side opened-`SK` decoder now classifies only RFC 7296
  `CREATE_CHILD_SA` requests shaped as `SA, Ni, KEi`, with IKE Protocol ID,
  consecutive proposals, non-zero eight-octet new initiator SPIs, mandatory
  non-`NONE` DH, and exact selected KE/group correlation. Vendor IDs,
  unrecognized error/status Notify payloads, and unknown non-critical payloads
  follow RFC 7296 mandatory-ignore behavior: `Drop` discards the latter two
  classes, while `Preserve` and generic `Reject` retain them. Unknown critical
  payloads still fail closed. Child-SA `REKEY_SA`, ESP/AH, TSi/TSr, other
  semantically invalid known payloads, malformed/zero SPIs, and
  missing/duplicate SA, Nonce, or KE fail closed with stable redaction-safe
  errors. Selection reuses the executable SA_INIT policy and exposes the chosen
  profile and initiator SPI directly to the existing rekey KDF. That KDF now
  requires the selected group's fixed-width shared secret (DH14 256 octets;
  DH19/20/21 32/48/66 octets) and reports a mismatch through the pre-existing
  redaction-safe invalid-key-length error contract. The response builder
  requires a caller-allocated non-zero responder SPI plus exact Nr/KEr and
  emits immutable `SA, Nr, KEr` bytes.
  Specification-authored AEAD and AES-CBC/HMAC vectors independently audit
  decode and byte-exact response encoding. IKE-SA state, SPI/DH/nonce
  allocation, simultaneous-rekey policy, `SK` protection, retransmission
  caching, installation, and deletion remain caller-owned.
- **Conflict-safe route/rule convergence — `opc-route-steering`,
  `opc-linux-route-sys`:** backend-neutral typed readback and convergence now
  distinguish newly installed, exact resident, conflicting, and indeterminate
  route/rule state instead of treating Linux `EEXIST` as equality. Bounded
  strict `RTM_GETROUTE`/`RTM_GETRULE` multipart parsing compares every modeled
  identity field and fails closed on unsupported, incomplete, malformed,
  oversized, duplicate, or unrepresented kernel state. It recognizes the
  kernel's extended-table compatibility marker, family-specific default route
  metrics, effective IPv4/IPv6 destination networks after clearing host bits,
  and only non-semantic IPv6 cache counters. Legacy route mutation bytes and
  mock operation records retain the exact caller destination. Conflict-safe
  Linux routes and rules carry a reserved nonzero namespace ownership protocol;
  legacy or foreign protocol values, multiplicity, and wildcard-unsafe exact
  deletion fail closed. The existing mutation API retains static/untagged wire
  behavior plus mark-zero and IPv4/IPv6 `/0` request compatibility. Explicit
  `remove_converged_*` methods and typed capability flags keep that legacy
  contract distinct from owned convergence. Plain upstream pre-4.17 kernels
  fail before rule convergence; possible vendor backports remain unknown and
  every allowed rule create is verified. Before positive readback, validated
  IPv4 kernel rejection becomes typed cached capability evidence; confirmed
  support is monotonic, and later generic or non-IPv4 create failures retain
  their operational meaning. An ACK which silently drops `FRA_PROTOCOL` triggers
  immediate attempt-owned rollback and caches separate typed unsupported
  evidence without a global probe rule. The mock now uses bounded multimaps
  with the same exact-plus-conflict behavior while preserving the legacy
  `MockOperation` variants through a separate read-observation API. Public
  nonzero-count conflict constructors support external backends. A clone-shared
  worker lock covers each operation and an entire paired rollback, including
  after cancellation of its async waiter. Foreign-state preservation assumes
  one coordinated owner of the reserved protocol within a network namespace;
  separate instances and external writers still require orchestration-level
  serialization. Existing mutation APIs remain available, and third-party
  trait implementations default to indeterminate until they add readback and
  owned convergence. Pre-upgrade static routes are not silently adopted;
  known-provenance cleanup and any BGP/export policy for route protocol `242`
  remain product/operator migration responsibilities.
- **BREAKING — observed quorum topology attestation — `opc-session-store`:** a bounded,
  product-neutral `QuorumTopologyAttestor` port now authenticates opaque proofs
  over SDK-canonical replica, service, physical-node, failure-domain, durable
  backing, descriptor, collector, configuration-epoch, and freshness claims.
  Attested admission rejects duplicate observed infrastructure, stale/replayed
  or replaced backing evidence, untrusted collectors, wrong bindings, and
  expired proofs before HA readiness. Static HA profiles now return the
  fail-closed `Unknown` value because time-unaware capability methods cannot
  prove freshness; only the new time-aware production capability/readiness
  methods may return `Quorum`/`Ready`. Production readiness bounds its Openraft
  barrier by both wall and verification-anchored monotonic validity, retains a
  bounded nondecreasing per-store wall-clock high-water, and repeats both checks
  after asynchronous work. Clock rollback and older concurrent probes cannot
  revive evidence. `DurableReadinessScope` now machine-labels `EngineOnly`
  versus `ProductionTopologyAttested` reports, and
  `is_production_traffic_ready` requires the latter. Deterministic conformance
  evidence can exercise three- and five-member admission without claiming
  production provenance.
  Long-running consumers can authenticate replacement evidence for the same
  immutable configuration without restarting Openraft; cross-epoch reuse still
  fails. The verified token and monotonic anchor/high-water are process-local,
  so restart must authenticate evidence again against current time. Whether a
  still-unexpired proof may be re-presented or must be replaced remains part of
  the adapter-owned proof/replay policy. No Kubernetes, cloud, CSI, TPM, SPIFFE
  collection, or dynamic
  membership policy is embedded in the store.
- **Request-bound Diameter error answers — `opc-proto-diameter`:** bounded
  inspection now separates answerable requests from fragments and
  untrustworthy boundaries, retaining only redacted Session-Id, ordered
  canonically re-encoded Proxy-Info, and one selected Failed-AVP context. Typed
  RFC 6733 failures cover unknown command/application, header/AVP flags,
  unsupported/invalid/missing/forbidden/excess AVPs, unsupported version,
  reserved header bits (5013), and invalid AVP length. Classification binds to
  the exact request, distinguishes missing from ambiguous dictionaries, checks
  command P and AVP M/P/V rules, and maps generic decoder failures only after
  proving offset, M-bit/local-policy, and explicit command-cardinality
  provenance. 5009 requires `ZeroOrOne`, 5008 requires an explicit
  `Forbidden` rule, and missing rules remain unmapped. The command-aware decoder
  and classifier reject the first forbidden occurrence, while triple singleton
  inputs bind 5009 to the second occurrence even if later evidence is supplied;
  earlier unknown M-bit AVPs centrally map to 5001. Nested 5008/5009 evidence
  uses only its immediate Grouped parent's schema and preceding siblings.
  Missing nested AVPs use parent-relative structures without fake offsets and
  prove absence at the request root or received direct parent;
  malformed fixed-width AVPs use a unique dictionary's zero-filled minimum;
  U24 synthesis bounds are checked before allocation. Received grouped ancestry
  carries exact private request range/digest provenance and must prove unique
  Grouped definitions, direct containment, and an exact top-level root;
  ancestor-free evidence must itself be an exact top-level iterator entry, so
  AVP-shaped value bytes cannot be rebound. Synthesized ancestry requires a
  declared grouped-child schema path and bounded depth. Proxy-Info
  canonicalization enforces caller depth and child-count limits. Classification
  and decoder/application mapping return a request-digest-bound failure token,
  and the builder accepts only that token, rejecting unrelated copied evidence
  or a different envelope. The builder preserves P and both identifiers,
  removes request-only routing fields, exposes exact amplification sizing, and
  requires an explicit §7.2 fallback before a 5xxx result sets E; 3xxx plans
  report their necessarily effective §7.2 grammar.
- **Bounded GTPv2-C protocol-error responses — `opc-proto-gtpv2c`:** a
  zero-allocation fixed-header inspector now separates answerable requests
  from TS 29.274 silent-discard cases. Typed plans cover header-only Version
  Not Supported with a checked local sequence, Echo Response special handling,
  and Cause-bearing S2b responses for invalid message/IE length,
  missing/incorrect mandatory or conditional IE, and Context Not Found. The
  clause 5.5.2 no-lookup path uses TEID zero without permitting Context Not
  Found, and the unknown-TEID classification requires a received non-zero TEID
  rather than a legitimate zero-TEID initial request. Exact amplification
  sizing and redacted caller-metadata reversal are available before bounded
  encoding.
- **BREAKING — authenticated-only ESP Child SAs — `opc-proto-ikev2`,
  `opc-ipsec-xfrm`:** typed ENCR_NULL transform 11 negotiation and restore now
  require a separate supported integrity transform, prohibit Key Length, and
  derive zero encryption/salt octets while retaining normal directional
  integrity KEYMAT. ENCR_NULL remains rejected for IKE-SA protected payloads
  and is not enabled or preferred by SDK policy. The Linux adapter maps it to
  the kernel-required zero-key `ecb(cipher_null)` attribute plus HMAC auth,
  rejects fabricated NULL keys and raw ESP auth without that attribute, and
  adds a privileged bidirectional packet/tamper proof. Existing AES-CBC and
  AES-GCM mappings are unchanged. Downstream exhaustive matches on
  `Ikev2EncryptionAlgorithm` must add the Child-SA-only `Null` arm.
- **BREAKING — typed random-IV IKE same-SPI resume — `opc-ipsec-lb`:**
  `SameSpiResume` replaces its three unconditional outbound-counter fields with
  `outbound_iv: SameSpiOutboundIvResume`. Existing IKE-AEAD and ESP-ESN callers
  must move their checkpoint, restored counter, and optional forward-jump into
  `CounterBased`; validation and safety floors are unchanged. IKE
  encrypt-then-MAC callers may instead select `IkeRandomIv` with the mandatory
  `FreshIndependentCsprngIvPerMessage` attestation and no placeholder counters.
  Random-IV evidence is rejected for ESP, while `Unspecified` preserves a
  fail-closed boundary for legacy or ambiguous evidence. Existing
  counter-based requests retain their byte-identical v1 transition fingerprint
  so an in-flight transition remains recoverable across a rolling upgrade; new
  random-IV and unspecified evidence use the v2 domain and bind the outbound
  mode and attestation. The existing `opc-sa-mirror` wire path remains
  counter-based and does not infer random-IV mode from legacy counter values.
- **Atomic candidate-only v5 Kubernetes HA artifacts — `opc-session-testkit`:**
  a separate executable and reusable composition API now preflight a trusted
  Linux output parent and Python interpreter before campaign mutation, run the
  deployed v5 batch/watch/restore/readiness campaign, and publish only after
  cleanup completes and both the frozen checker and additive workload verifier
  pass. The exact v5 machine-readable profile now closes the crate, feature,
  platform, protocol, threshold, checker, workload-verifier, and remaining-gate
  inventory named by the evidence. Private descriptor-relative staging retains
  that profile, the exact v5 JSONL history, fault schedule, generated workload
  schedule, closed candidate evidence, unchanged frozen independent checker,
  separate additive workload verifier, both bounded outputs, and a v2 digest
  summary that binds the profile bytes;
  `renameat2(NOREPLACE)` prevents replacement. Reusable-API callers must supply
  both expected digests; the dedicated CLI binds the exact programs embedded in
  the invoked binary and is not an independent provenance trust root.
  Descriptor-pinned interpreter/input access, full parent-ancestry validation,
  isolated Python, bounded pre-reap process-group cleanup, and explicit
  cleanup-unknown handling fail closed. Normal success never signals a reaped
  process's old numeric group. A post-rename parent-sync failure is
  quarantine-only outcome-unknown; no authenticated acceptance verifier is
  claimed. Every
  artifact remains
  `experimental=true`, `qualification_complete=false`, and
  `counts_for_production=false`; this is no live-cluster or production
  qualification claim.
- **Exact authenticated-control-plane SA relocation — `opc-ipsec-xfrm`:** a
  typed `RelocateSaRequest` carries a query-proven old SA identity plus new
  outer addresses and ESP-in-UDP ports. Linux uses the exact single-state
  `XFRM_MSG_MIGRATE_STATE` UAPI, validates current state before mutation, and
  requires exact target GETSA readback plus old-tuple absence after an identity
  move; it never falls back to ambiguous legacy migration or packet-source
  inference. The upstream missing-SA feature
  probe maps `ESRCH` to `Available` and the documented `EINVAL`/`ENOPROTOOPT`
  cases to `Missing`; a real-operation `EINVAL` is never reclassified as
  old-kernel evidence. Relocation is explicitly documented as not
  cancellation-safe once polled, requiring exact recovery reconciliation before
  safety fences are released or a retry begins. Policies, authenticated IKE
  signalling, writer serialization, and seamless-mobility qualification remain
  consumer-owned. Typed preserve/set/remove encapsulation actions cover native
  ESP and exact NAT-T add, port replacement, and removal semantics. Default
  trait methods plus separate identity/capability queries preserve the existing
  `SaState` and `XfrmProbe` public shapes and third-party backend source
  compatibility; the mock records relocations in a separate typed log without
  extending its established exhaustive operation enum. Relocation snapshots
  preserve every raw selector field and reject unmodelled nonzero NAT-T
  original addresses. A required direction contract distinguishes incoming
  migration from outgoing migration after the upstream-mandated temporary
  block policy, preventing cleartext fallback and AES-GCM IV reuse.
- **Authenticated fenced ingress redirect — `opc-ipsec-lb`:** a versioned
  mTLS-exporter-protected cross-node IKE/ESP packet path now combines canonical
  destination ownership keys, exact committed generation checks, bounded
  replay/hop/queue/MTU policy, correlated receipts with exact retry replay,
  connected UDP and deterministic in-memory adapters, mandatory packet-too-big
  feedback, fixed-cardinality metrics, and two-phase certificate/trust rotation
  with authenticated reconciliation. Endpoint-owned cancellation-safe
  operations expose proven-not-sent/authenticated-receipt/unknown outcomes;
  one-shot peer sessions, draining shutdown, dequeue-time fence validation, and
  non-evicting dual-epoch receipt-cache commits prevent capability reuse or
  acknowledgement/effect divergence. Receipt capacity is an authenticated,
  bounded profile value; slots are reserved before cryptographic open, and
  saturation or commit failure cannot emit an uncached receipt or publish an
  effect. Admission, materialized delivery, stale capability, cache load, and
  cache occupancy are independently observable. Linux UDP enforces IPv4/IPv6
  `DO` PMTU discovery, retains its last proven ceiling across transient refresh
  failures, and reports runtime shrink through the mandatory PTB boundary.
  AES-256-GCM is the production default with shared data/receipt invocation
  caps, peer-open and failed-authentication limits, and proactive rotation
  status; integrity-only HMAC-SHA-256 is explicit. Raw authenticated frames are
  crate-private, its HMAC composition zeroizes keys, pads, digest outputs, and
  hash state, and no API accepts or transports SA key material. Rotation and
  reconciliation are serialized per session, expired staged/previous epochs
  are purged before lifecycle decisions, and final initial establishment fails
  unknown if authentication expires. Rotation evidence covers independent
  CA/leaf A-to-B replacement through overlapping trust and mixed authenticated
  epochs.
- **Aggregate admission budget — `opc-runtime`:** a product-neutral global
  token bucket and in-flight ceiling now compose after the existing per-source
  limiter. The aggregate state has no source-key table or eviction path, so
  rotating identities cannot restore burst capacity. Non-blocking admission
  returns stable typed exhaustion errors and a non-cloneable RAII permit whose
  drop, including task cancellation, releases the slot; fixed-cardinality
  saturating metrics expose admits, both rejection classes, releases, current
  in-flight work, and the observed peak without peer-controlled labels.
- **Keyless destination-aware IKE/ESP ingress classifier — `opc-ipsec-lb`:**
  a zero-copy, allocation-free IPv4/IPv6 classifier now extracts canonical
  destination-scoped ownership keys for initial/established IKE, RFC 3948
  NAT-T ESP, and native ESP without accepting SA key material. It bounds IPv6
  extension traversal, treats non-initial fragments and malformed/truncated
  headers as typed `Unclassifiable` outcomes, preserves IKEv2 SKF identity,
  and safely extracts supported ICMP/ICMPv6 quotes. Quoted outbound ESP remains
  direction-typed and cannot be mistaken for an inbound ownership key;
  address, port, and SPI diagnostics are redacted.
- **Destination-scoped IPsec ownership keys — `opc-ipsec-lb`:** canonical,
  bounded initial-IKE, established-IKE, and ESP identities now structurally
  bind the public destination address and opaque routing-domain tag. A
  generation-carrying rendezvous selector provides deterministic eligible-owner
  decisions with minimal remapping on member changes, while an explicit
  initial-to-established promotion preserves the already-selected owner.
  Versioned strict encoding, Serde support, typed SPI-collision detection, and
  address/SPI-redacted diagnostics keep the product-neutral layer suitable for
  stores and redirect/datapath adapters without accepting SA key material or
  performing I/O.
- **Generalized fenced ownership — `opc-session-store`:** bounded opaque keys
  and metadata now compose with the existing lease/CAS/Openraft authority to
  provide expiring logical ownership records, strictly monotonic
  fence-derived generations, atomic renew/transfer, retained-mutation replay,
  effect-point validation, and deterministic injected-clock expiry. A bounded
  synchronous local cache consumes only contiguous committed watch entries,
  shares hit records through `Arc`, and independently caps entries and retained
  bytes. Empty views replay from sequence 1 through a proven committed head and
  remain stale during a partial backlog; later starts require an explicitly
  caller-proven namespace-bound coherent seed. An ordered expiry index reclaims
  passive expiry without an unbounded capacity scan. Excess lag produces a
  distinct owner-free stale outcome; gaps, malformed or future evidence, clock
  regression, capacity failure, and feed shutdown additionally clear the view.
  Metrics cover lag/bytes/hits/misses/stale/failures. The facade adds no consensus,
  encryption, placement, redirect, or packet policy: at-rest payload protection
  is inherited only when composed over the existing encryption/HKMS backend.
- **IKEv2 encrypt-then-MAC suites — `opc-proto-ikev2`:** typed executable
  IKE-SA profiles now preserve the negotiated PRF, DH group, encryption/key
  size, and optional integrity algorithm. PRF-HMAC-SHA2-512 (Transform ID 7),
  AES-CBC-128/192/256 with AUTH-HMAC-SHA2-256-128/384-192/512-256, and
  AES-GCM-192 are executable across initial/rekey/Child KDFs, restore, AUTH,
  and `SK`/`SKF` protection. CBC verifies a constant-time truncated ICV before
  decryption and uses a fresh 16-byte CSPRNG IV for every new message; callers
  must replay cached sealed bytes for retransmissions. The ambiguous profile
  constructor and anonymous integrity-key length are replaced by fallible typed
  constructors and `Option<integrity Transform ID>`. RustCrypto AES/CBC, a
  zeroizing SHA-2 primitive, and an explicitly wiped HMAC composition back the
  implementation; stable errors expose unsupported suites, key/IV/body
  lengths, authentication, and authenticated padding failures without secret
  material.
- **Device-scoped destination-metadata UDP sockets — `opc-runtime`:** an
  explicit, default-off typed option can apply Linux/Android
  `SO_BINDTODEVICE` before address bind, allowing listeners such as IKE and
  NAT-T endpoints to remain inside a VRF or other L3 domain. Device names are
  validated, unsupported platforms fail closed, and exact-source reply probes
  inherit the listener's device scope. The existing constructor retains its
  device-unscoped behavior.
- **SCTP multihoming path control — `opc-sctp` / `opc-libsctp-sys`:** the
  existing RTO and heartbeat configuration now applies validated non-default
  values through exact, layout-asserted Linux `SCTP_RTOINFO` and
  `SCTP_PEER_ADDR_PARAMS` bindings while omitted values preserve kernel
  defaults. Generic and Diameter associations can select a current peer path
  through `SCTP_PRIMARY_ADDR`; unknown paths fail before mutation and the
  bounded health snapshot updates without claiming a reachability change or
  disabling kernel failover. Strict config negatives, raw ABI fixtures, and
  live single-host multihoming tests cover tuning, selection, Diameter
  delegation, and data delivery.
- **Per-slot HA qualification contract — `opc-session-testkit`:** an additive
  candidate-only v5 schema and SDK-independent bounded checker now model the
  actual per-slot CAS behavior of `SessionBackend::batch`. Successful CAS slots
  bind exact application-journal sequences, conflicts bind no fabricated
  event, and an explicit invocation sequence binds ordering. The evidence
  fixes one campaign-valid owner/fence guard per key and structurally binds
  non-expiring authoritative record type/class fields plus exact initial and
  terminal journal heads. At least one watch must cover the exact gap-free
  initial-to-terminal journal window, and at least one post-batch complete
  restore must match the terminal state; every restore is checked through a
  precomputed bounded prefix index. A separately digest-bound fault schedule
  now derives quorum expectation, bounded completion cadence, initial
  authority, and explicit loss/recovery-transition observations rather than
  trusting readiness rows. Openraft term/log indices
  remain distinct from journal heads. An Openraft production-path regression
  proves success/conflict/success yields two ordered journal entries. A pure
  bounded collector now validates the complete fault schedule and
  history-derived isolated state type, transactionally admits typed child
  observations, correlates real watch events in serialized batch/slot order,
  models terminal state, and requires conclusive lease, partial-batch, restore,
  and readiness coverage before its synthetic output passes the frozen
  checker. A bounded deployed-Kubernetes adapter now uses the existing
  shell-free kubectl/private-control boundary to preflight an isolated scope,
  execute the batch once, drive an acknowledged all-member consensus-RPC
  isolation/recovery cycle, sample exact-identity readiness, consume the real
  watch, scan terminal restore state, and feed the typed replies into that
  collector. Per-member actuation timing conservatively removes reachability
  at the earliest disable dispatch and restores it only after the latest enable
  acknowledgement. Bounded transition sampling retains transient recovery
  observations and requires an unchanged common journal head. Cancellation,
  partial/ambiguous gate actuation, non-convergence, and ambiguous mutation
  replies fail closed; cleanup
  restores the idempotent RPC gates, forgets process-local lease handles, and
  clears the external readiness condition without releasing the still-valid
  durable lease. Frozen v1-v4 contracts remain unchanged; v5 still adds no
  retained release-manifest binding, executed cluster evidence, or production
  qualification claim.
- **Leader-aware management commits — gNMI/NETCONF/config bus:** an opt-in
  `ConfigAuthorityPort` projection fence redirects followers with bounded
  leader hints and returns the exact persisted `{version, plaintext-envelope
  SHA-256}` on successful writes. Default authoritative/no-port replies remain
  byte-identical; stale or absent durable heads and legacy digest-less replays
  fail closed instead of serving a local projection or fabricating a hash.
- **Durable management audit store — `opc-mgmt-audit-store`:** a production
  `AuditSink` adapter now commits the existing value-free management event
  fields to the reference SQLite profile with a purpose-separated HMAC chain,
  authenticated retention low-water/terminal anchor, full restart verification,
  typed first-break failures, and fixed-bounded cursor pages. Appends atomically
  advance and prune the trail. Construction rejects unsafe or ephemeral storage
  and wrong keys; the worker admits at most 64 queued requests and fails closed
  after a five-second durable acknowledgement deadline without manufacturing
  success. Shutdown is likewise bounded and reports detached stalled workers.
  Local verification detects retained alteration, deletion, reordering, and
  anchor/row disagreement; a coherent whole-database rollback still requires an
  external monotonic checkpoint supplied by the deployment platform.
- **Follower-local committed config recovery — `opc-config-bus`:** bounded,
  transport-neutral committed-revision pages and exclusive `ConfigVersion`
  cursors now provide gap-free `watch_committed` streams and atomic
  snapshot-plus-tail `recover_from` recovery. SQLite, in-memory, encrypted, and
  Openraft-backed adapters implement ordered durable history; consensus reads
  only the contiguous local committed/applied and recovery-cleared state
  machine prefix without a leader/read-index round; an applied fenced tail
  remains invisible until its clear mutation applies. Notifications are wake
  hints followed by authoritative repaging. The explicit
  `CommittedRevisionSource` marker gates read-only
  Shadow construction, which rejects writes before I/O. Typed future-cursor,
  compaction, sequence, and page-bound errors fail closed. The additive
  `opc-config-bus-consensus` remote adapter carries only this read surface over
  a dedicated exact-profile mutual-TLS boundary: every bounded long-poll page
  proves the config consensus identity, product schema digest, and exact
  client/server SPIFFE IDs; construction rejects an authoritative bus,
  reconnects from the last caller-visible cursor, and never implements a
  voter, mutation, rebuild, leader-forward, or second consensus path. Fixed
  frame/count/deadline/concurrency limits, cancellation isolation, typed
  redacted errors, snapshot-plus-resume recovery, shared bounded TLS material
  rotation, clean maximum-version EOF, and real-TCP follower-switch
  qualification complete the out-of-process #256 surface without changing
  at-rest encryption or HKMS ownership.
- **Shared Raft-managed config datastore — `opc-config-bus-consensus`:** a
  source-build-only adapter now connects `opc-config-bus` to the existing
  `opc-persist::ConsensusConfigStore` without adding another election,
  replication, membership, recovery, or transport authority. The production
  newtype accepts only sealed config records; callers compose the existing
  HKMS-backed `EncryptingManagedDatastore` outside it, so Openraft continues to
  receive only authenticated ciphertext, clear lifecycle metadata, a
  digest-only replay index, and product-neutral redacted audit. Named rollback
  points are created atomically with their commit, temporary consensus loss is
  a typed unavailable outcome, and ambiguous accepted writes retain the
  distinct `OutcomeUnknown` reconciliation contract. The config command and
  config-specific RPC revisions advance to 3 and require a coordinated drained
  fleet upgrade. Multi-group config qualification remains `GAP-001-006`, and
  session-store production qualification remains #143. Frozen v2/v4 session-HA
  profiles remain byte-identical and do not represent the new adapter; the
  current 27-crate source-build closure is checked independently until an
  additive follow-up qualification change supplies candidate evidence.
- **Linearizable local-read gate — `opc-consensus`:** a product-neutral
  `LinearizableReadBarrier` now maps coalesced Openraft read-index outcomes to
  typed serve/not-leader/unavailable decisions and waits for the serving
  node's local apply before admission. An optional default-off same-term
  leader lease has a fixed profile-derived duration and falls back to a full
  quorum round on expiry or any leadership/term change. The leader-open helper
  gates advertisement on an exact consumer projection rebuild. Session-store
  now uses the shared full-round/apply gate without changing its membership,
  recovery, routing, wire, or encryption behavior.
- **Leadership-fenced VIP ownership — `opc-ipsec-lb`:** a protocol-neutral
  `VipOwnershipCoordinator` now turns caller-supplied leader, quorum, listener
  health, and deployment-unique monotonic-fence intent into idempotent
  advertise/withdraw operations. Missing, stale, and ABA-reused fences fail
  closed, and the default intent is not-owner. The new `ExternalLb` advertiser
  tier performs intentional route-mutation no-ops while the coordinator keeps
  the same ownership bookkeeping for externally delivered management or
  dataplane VIPs. Typed provider-unknown state safely recovers ambiguous or
  cancelled mutations by converging to a known withdrawal before retry, while
  signal loss revokes the pending epoch. Fresh coordinators also withdraw once
  before claiming provider state, and raw `AlreadyExists` remains unproven
  rather than being accepted without readback.
- **Generic XFRM SA output marks — `opc-ipsec-xfrm`:** callers can set an
  independent typed `SaParameters::output_mark` value/mask pair for Linux
  `XFRMA_SET_MARK`, including on inbound/decrypt SAs, and recover the exact
  kernel pair through `SaState`. The value and mask cannot both be zero because
  Linux canonicalizes that pair to absent attributes; callers use `None` for
  no output mark. The default absent path preserves legacy bytes; lookup marks
  remain a separate namespace; and configuring the fixed-DSCP companion does
  not reserve its mark window for SAs whose `egress_dscp` is absent. An SA that
  does request fixed DSCP must keep its generic output value and mask disjoint
  from the token window so composition remains deterministic. Existing
  `SaParameters` literals must initialize `output_mark`, normally to `None`.
- **Private qualification-node control socket — `opc-session-testkit`:** the
  existing JSON-line node protocol can now run over a `0700` workspace control
  directory and `0600` Unix socket, with one bounded command and reply per
  connection and a same-binary one-shot client. The Kubernetes foundation uses
  the socket from its existing ephemeral workspace volume, removes interactive
  container stdin, and retains a tokenless ServiceAccount without adding RBAC,
  ports, identities, or controller authority. Kubernetes `pods/exec` access to
  the client is node-administrator-equivalent qualification authority.
- **Bounded Kubernetes sequential-HA campaign — `opc-session-testkit`:** the
  candidate-only external runner drives the private same-binary control client
  with direct, time/output-bounded `kubectl` processes. After a fresh
  all-member readiness baseline it executes the shared frozen 15-operation
  lease/fence/CAS/read schedule once across designated Pods, sampling every
  member after each operation. Ambiguous mutations are recorded as
  indeterminate and never retried. Each operator-supplied unique history ID
  derives a domain-separated bounded namespace for the durable keys, owners,
  schedule ID, operation IDs, and lease handles, so retained PVCs and live
  node processes can run later campaigns without colliding. The long lease is
  checked from the exact 3/5-node serialized `kubectl` envelope (66 calls after
  the five-node op-8 acquisition through op-14 release), two command-deadline
  margins, and a hard phase deadline limited to that exact envelope; the short
  expiry proof remains unchanged. A typed, idempotent local cleanup command
  reclaims every invoked acquisition handle once, including ambiguous
  acquisitions, without replaying a durable lease mutation. Before each
  acquisition the node also reclaims expired crash residue and bounds released
  stale-probe retention to the newest four handles. It updates the custom Pod
  condition only from strict fresh Openraft barrier replies,
  resets all conditions before sampling, latches the first failure, and
  attempts all-false cleanup. A kubelet exec probe independently validates the
  exact local and fleet identities over the private UDS with layered deadlines,
  so readiness self-expires on quorum loss, a hung probe, or process exit even
  if the external evidence condition becomes stale. Ctrl-C and SIGTERM wake
  interval waits, terminate and reap an active local `kubectl`, and enter
  bounded all-false cleanup. Exact voter IDs are additive and optional on
  decode: legacy readiness replies remain readable but cannot authorize the
  exact-ID Kubernetes gates.
  It atomically publishes a private command/reply transcript, frozen v1
  schedule/history pair, readiness-v3 fragment, summary, and exact digests
  without adding a port, token, or RBAC to the fleet. The v1 pair is directly
  consumable by the independent sequential checker. Before publication, a
  sealed outcome is independently revalidated against the canonical scoped
  schedule, exact contiguous history prefix, transcript phase/order, readiness
  rows, cleanup results, and derived completion/status; caller-forged claims
  fail before a destination is created. The v3 fragment still omits
  batch/watch/restore and real fault/platform evidence, so the profile remains
  experimental and #143 production qualification remains open.
- **Canonical 3GPP TFT codec — `opc-proto-tft`:** one shared, bounded TS 24.008
  V18.8.0 value model now covers every operation, parameter, and Release 18
  packet-filter component for GTPv2-C Bearer TFT IEs and IKEv2 TFT Notify
  payloads. Strict structured validation rejects malformed lengths, reserved
  and conflicting components, illegal cardinality, duplicates, and invalid
  parameter sequences; permitted unknown parameters retain byte order.
  Specification-authored fixtures, property/negative/corpus tests, redacted
  diagnostics, and scheduled decode/round-trip fuzz targets define the codec
  evidence. Transport wrappers and state-dependent bearer policy remain with
  the consuming GTPv2-C and IKEv2 procedure boundaries.
- **S2b dedicated-bearer GTPv2-C — `opc-proto-gtpv2c`:** typed and
  procedure-aware Create Bearer (95/96), Update Bearer (97/98), and Delete
  Bearer (99/100) support now validates mandatory nested IEs, APN-AMBR,
  canonical shared Create-new/uplink TFT semantics, typed Bearer QoS/ARP and
  standardized QCI rate rules, S2b-U F-TEID roles, mutually exclusive Delete
  forms, partial results, Message Priority propagation, exact request/response
  bearer correlation, bounded ordered request-only Load/Overload/PGW Change
  IEs, and precise TFT syntax/semantic rejection Causes. The bounded
  transport-neutral triggered transaction registry uses generation-bound work
  tokens, fences timed-out side effects until explicit cancellation
  acknowledgement, prevents duplicate application dispatch, and replays exact
  committed response bytes across retransmissions.
- **3GPP dedicated-bearer IKEv2 primitives — `opc-proto-ikev2`:** typed TS
  24.302 R17 multiple-bearer QoS, TFT, modified-bearer, AMBR, and private-error
  Notify codecs now compose with strict opened-payload builders/views for new
  non-rekey `CREATE_CHILD_SA`, bearer-modification `INFORMATIONAL`, and
  Child-SA deletion exchanges. The boundary enforces payload cardinality,
  supported ESP algorithm, AEAD/INTEG, ESN, SPI, and KE/proposal relationships;
  response proposal/transform and traffic-selector correlation; an
  uplink-applicable create TFT; directional paired-SPI Delete responses; the
  explicit RFC 7296 crossed-delete exception; canonical shared TS 24.008 TFT
  exact error/success separation. A checked integer-kbps bridge maps typed
  GBR/non-GBR bearer QoS and APN-AMBR onto the complete TS 24.301 normal and
  extended rate grids with explicit exact/ceiling quantization and reports the
  values represented on the wire. Strict decoding applies the TS 24.301
  receiver interpretation for compact-rate and extended-unit aliases and
  stores their canonical equivalents. Every production Notify/exchange builder
  rejects those aliases when supplied manually, along with reserved network
  values, QCI/resource mismatches, invalid tier saturation, GBR ordering, and
  inconsistent external-rate sentinels. Admission, SPI allocation,
  retransmission timers, cryptographic sealing, and dataplane installation
  remain with the product.
- **Per-bearer GTP-U mark steering — `opc-gtpu-dataplane`:** an optional typed
  non-zero `GtpBearerMark` now selects additive dedicated-bearer FAR, DSCP, and
  PDR state without changing the legacy map ABI or default-bearer GTP-U wire
  bytes. A marked-only owner journal gates forwarding through explicit
  pending, active, and removing phases, binds the complete FAR/DSCP/PDR
  identity, and makes interrupted installation, update, removal, and restart
  recovery fail closed and exactly retryable. The S2b-U boundary owns the
  complete 32-bit packet mark: zero selects the default bearer, dedicated
  Child SAs use exact non-zero values, and XFRM mark operations and policies
  must use `u32::MAX` masks. Unknown marked uplink traffic fails closed,
  successful uplink encapsulation consumes the mark, and validated downlink
  traffic writes either the dedicated mark or a deliberately normalized
  default zero. A capability probe exposes support; existing public literals
  add `bearer_mark: None` and the probe field, with no new feature or
  dependency. Atomic tc replacement, exact pin/hook cleanup, and a hash-pinned
  frozen-v1 identity fixture provide retryable live migration while rejecting
  ambiguous or foreign state.
- `opc-proto-gtpv2c`: TEID-present EPC headers now expose the TS 29.274 R18
  Message Priority flag and a bounded `MessagePriority` value (`0` highest,
  `15` lowest). Strict decode accepts valid MP-bearing headers while rejecting
  spare bits and MP/value inconsistency; canonical encode emits the typed
  priority, and raw-preserving encode retains ignored/spare wire bits.
- `opc-sctp`: independent, default-off `DiameterInboundPpidPolicy` and
  `DiameterOutboundPpidPolicy` escape hatches can accept or emit PPID 0 for a
  configured legacy clear-text Diameter peer. Strict inbound validation and
  outbound PPID 46 remain the defaults; enabling one direction never enables
  the other, PPID 47, or DTLS. Both policies survive single-address and
  static-multihoming Diameter construction, while association metrics count
  accepted inbound legacy messages and a redaction-safe warning is emitted at
  most once per association.
- `opc-sctp`: Linux `SCTP_PEER_ADDR_CHANGE` notifications now decode into
  typed, address-redacted events and update a bounded per-association path
  health snapshot with reachability and primary-path state. An event-capable
  Diameter receive boundary exposes transport notifications without changing
  the existing payload-only helper's notification, truncation, or PPID
  behavior. Notification constants now use the Linux UAPI
  `SCTP_SN_TYPE_BASE` values so association and shutdown events decode on real
  kernels as well as fixtures.
- **SWm emergency identity construction — `opc-proto-diameter`:** consumers
  can now obtain the canonical TS 23.003 IMEI Emergency NAI with
  `emergency_nai` and build the byte-identical RFC 3748
  EAP-Response/Identity required by the TS 33.402 emergency verifiers with
  `build_eap_response_identity`. The EAP builder copies identity octets
  verbatim, rejects bodies that exceed its two-octet packet length before
  allocation, and reports only a stable redaction-safe error label. Existing
  parsing, authorization evidence, and ordinary SWm wire behavior are
  unchanged.
- **Bounded IKE_SA_INIT error responses — `opc-proto-ikev2`:** responders can
  now build notify-only `UNSUPPORTED_CRITICAL_PAYLOAD`, `NO_PROPOSAL_CHOSEN`,
  and `INVALID_KE_PAYLOAD` responses with a zero responder SPI, canonical
  response flags, and Message ID zero. The generic entry point accepts exactly
  one allowlisted IKE-SA-shaped error; dedicated helpers encode an unsupported
  critical payload as exactly one offending payload-type octet and an accepted
  non-zero Diffie-Hellman group as exactly two big-endian octets. Cleartext
  `INVALID_SYNTAX`, non-zero Protocol IDs, SPI bytes, ambiguous lists, and
  malformed data fail closed. Critical-bit inspection, source validation,
  response rate limiting, retransmission behavior, and other unauthenticated
  anti-amplification policy remain product responsibilities.
- **Combined HA candidate evidence contract — `opc-session-testkit`:** an
  additive frozen v4 profile preserves the v2 runtime inventory while binding
  both the v1 sequential and v3 concurrent independent-checker contracts. A
  closed, bounded typed manifest digest-binds one exact candidate campaign,
  artifact, environment, schedules, histories, checker programs and outputs,
  diagnostics, and complete eight-gate acceptance inventory. Strict negative
  and frozen-byte tests reject production claims, drift, malformed digests,
  inconsistent release artifacts, reversed timestamps, inconclusive checkers,
  and gate/digest mismatches. All v4 evidence remains experimental and counts
  for no production qualification.
- **Experimental projected-mTLS fault/expiry qualification —
  `opc-session-testkit`:** non-ignored, serialized single-host tests now run
  real three- and five-process Openraft/SQLite fleets through two bounded
  scenarios. The first applies a test-only consensus-RPC admission gate to one
  stable follower while a different member atomically publishes malformed
  trust, retains its exact last-good TLS epoch, and leaves the survivor quorum
  able to prove fresh durable readiness and advance an encrypted canary. It
  then restarts the gated member on its exact manifest address, proves catch-up,
  repairs the malformed generation, and proves retries stop. The second
  publishes a same-issuer leaf with a 75-second remaining-validity/expiry
  budget, keeps every incident directed path live below the idle timeout,
  proves no local/peer leaf-expiry retirement before the fixed
  `expiry - 30 seconds` soft boundary, then requires retirement, complete
  hard-deadline drain, source/controller `LastGoodExpired`, a zero SVID-expiry
  gauge, one expiry outcome, survivor readiness, and encrypted-canary progress.
  A valid long-lived leaf advances only the recovered process's explicit
  reauthentication generation, restores fresh bidirectional proofs for every
  path incident to that member, and restores all-voter readiness in the same
  process. Unrelated survivor explicit/material-epoch retirement counters must
  not advance. The next workload phase starts only after every connection
  drain has settled and every still-live survivor availability episode is
  resolved. A prepublication common-key pulse primes conservative 13-second
  progress checkpoints, the 86-second recovery clock and
  60-second two-stage server tail begin only after the atomic projected-data
  rename, and a final 2.5-second outbound-ledger quiet tail completes the
  settlement horizon. Each pulse requires one common active key to advance on
  every survivor observer; two adjacent half-SLO observations bound its
  worst-case actual event gap to 26 seconds. An independent 26-second checkpoint
  requires every active survivor key to advance on every observer and is not
  reset by a faster key, so neither timing nor fault-era terminal outcomes can
  be attributed to the clean scoped-reauthentication checkpoint. Each survivor
  may record at most one new
  availability episode while the expired member rejoins; it must recover
  inside the existing 26-second SLO and be fully settled before the clean
  baseline. A second or late episode fails closed. The complete expiry/rejoin
  interval has an 85/161 per-node new-attempt and reconnect bound: the ordinary
  24/40 allowance, at most fifteen five-second refresh rounds over the
  four/eight incident directed paths, and one scheduled post-hard-expiry
  survivor-to-expired network-negative attempt per involved node. The reverse
  expired-to-survivor probe fails local material preflight without dialing.
  Terminal outcomes may additionally
  contain only the exact attempts already outstanding at the interval baseline;
  the connection conservation equation remains mandatory. Schedule v6 binds
  this as `new-attempts-plus-baseline-outstanding/v1`. Cancellation-classified
  `abandoned` outcomes, protocol/backend outcomes, and drain overruns remain
  forbidden throughout the fault and clean intervals. Schedule v6 advances the
  checkpoint to `member-scoped-reauth-settled-baseline/v3` and binds its rolling
  proof as `common-key-pulse-all-active-key-coverage/v1`. Recovery continuity
  polls use a
  non-intrusive workload snapshot; authoritative watch-head settlement keeps
  the fail-closed linearizable head observation. Deterministic encrypted
  lease/renew/CAS/read/complete-
  restore/readiness mutations and applied-state watches run through admission
  loss, retained-last-good trust, exact-address restart, repair, and the
  short-lived publication. The expiring member drains its accepted mutation
  work and stops its watch before soft retirement while the survivor workload
  continues through soft retirement and hard expiry; replacement reconciles
  the stopped watch from the bounded durable journal. A mutation task may
  reconcile only typed backend-unavailable or operation-outcome-unavailable
  terminal results. Mutation or lease outcomes that can make authority
  ambiguous discard the prior guard, reacquire same-owner authority at a
  strictly higher fence, and validate the exact scheduled record. Read-only
  get, restore-scan, and readiness outcomes retain the already-proven guard and
  validate that same exact record without minting unnecessary fencing
  authority. This routing is bound into evidence as
  `stage-aware-known-authority/v1`. The
  schedule deterministically drops one successful release response to exercise
  this path, permits at most eight such outcomes per node, gives each recovery
  episode the fixed 26-second two-election-plus-operation transition envelope,
  retries only after a fixed 50 ms delay, and exposes total, recovered, and
  maximum-consecutive counters. Phase completion requires every interruption
  to be reconciled. The admission-loss exact-address restart is watcher-only
  before exit and enters the mutator set only after journal reconciliation. A
  resumed committed generation does not rearm that once-per-logical-mutator
  synthetic fault. Lease loss, unexpected state, and invariant failures still
  fail immediately. Separately, after malformed-material repair, exactly one
  stable follower is killed uncleanly while its mutation and watch tasks are
  active. The survivor majority advances both the encrypted canary and mixed
  traffic during the outage. The corrected
  `same-disk-exact-address-active-mutator/v3` profile checks six sequential
  stages independently: termination and process reaping within 5 seconds,
  outage/survivor progress within 26 seconds, replacement-child startup within
  45 seconds, Openraft recovery and readiness observation within 37 seconds
  (the existing 26-second recovery envelope plus one reserved 11-second final
  all-voter readiness round: 10 seconds for the backend operation and 1 second
  for bounded local result delivery), reconciliation of at most 262,144 exact
  journal entries within 25 seconds, and mutation resume under a strictly
  higher same-owner fence within 26 seconds. The composed crash-to-resume
  ceiling is 164 seconds, but no stage may borrow unused time from another
  stage or substitute that total for its own bound. Schedule v6 binds the scenario,
  count, recovery envelope, delivery allowance, final observation reserve, six
  bounds, and total, so older evidence cannot satisfy the new assertions. This retains the v1
  deadline-composition correction and fixes v2's free-running probe admission,
  which could strand the final six seconds without a complete readiness round.
  A stage that finishes after its fixed deadline fails
  with a closed terminal-stage plus elapsed-millisecond diagnostic rather than
  preserving an earlier ambiguous error that hides where the overrun occurred;
  Schedule v6 binds this as `terminal-stage-elapsed-millis/v1`. A child that
  exits during restart configuration now reports only the fixed `transport`,
  `sqlite`, `consensus`, or `listener` startup stage; underlying errors, paths,
  and identities remain redacted.
  These are synthetic regression scenarios, not a real or deployed network
  partition, and do not prove deployed production readiness or provide a
  broader restart/fault matrix, resource/soak,
  remote-HKMS, deployed-CNF, signed-release, evidence-schema, or
  production-profile claim. Openraft remains the sole commit authority, and
  payload encryption, AAD, key-provider/HKMS boundaries, SQLite/Openraft
  durable formats, and encryption-at-rest responsibilities are unchanged.
- **Experimental projected-mTLS traffic/resource qualification —
  `opc-session-testkit`:** the real 3/5-process rotation harness now registers
  every encrypted applied-state watch before starting deterministic
  per-member lease/renew/CAS/read/complete-restore/readiness/reacquire loops,
  then keeps those loops live through repeated same-issuer leaves and the
  complete overlap, intermediate, root, trust-removal, stale-old-chain
  rejection, pre-removal rollback, and overlap-first post-removal rollback
  campaign. Every publication proves resolver-fresh directed mTLS paths,
  durable readiness, acknowledged canary continuity, and workload progress.
  After each publication/handshake checkpoint, every observer must advance its
  gap-free committed sequence, applied-record count, and exact monotonic
  generation for every synthetic traffic key; final catch-up cannot mask a
  stalled rotation watch. Renewal preserves the exact lease fence,
  reacquisition strictly advances it, and get/restore compare every record
  field. A chained campaign ledger permits only the exact removed-root ring
  probes and rejects every other connection/reconnect/drain failure. Linux
  qualification samples each child process's `/proc` FD/thread maxima and
  kernel-reported `VmHWM`, and
  semantically settled FD/socket/thread/VmRSS state against explicit warmed
  bounds, alongside connection/drain/reconnect and qualification-owned async
  task bounds. Authenticated next-request idle expiry is a fixed lifecycle
  retirement reason rather than a false timeout failure; real timeout and all
  other connection failures retain a zero budget. The exact schedule digest
  additionally binds the shared eight-slot per-node Openraft proposal-admission
  limit, exactly one supervisor-owned fresh-linearizability check per node,
  and at most 64 total admitted callers across its active and waiting cohorts.
  Proposal slots and the linearizability
  supervisor bound task/memory pipelines, not connections;
  neither enlarges the explicit socket/FD formulas. Parent-side timeout,
  malformed-response, and EOF diagnostics retain only a closed pending-command
  kind, harness-local sequence, elapsed send time, and closed stderr category;
  command values, session/lease identities, payloads, and filesystem paths are
  omitted. Initial process-heavy `Configure`/`Started` exchanges are admitted
  one child at a time under one shared 45-second fleet deadline, while cluster
  `Initialize` remains concurrent. Cooperative task-stop replies reuse the last
  successfully proven linearizable replication head instead of launching a new
  backend operation
  after task join; subsequent recovery still requires fresh bounded journal
  reconciliation. The 90-second transition value is only a hard fail-safe;
  semantic completion ends each transition. These single-host synthetic bounds
  are regression evidence, not deployed Kubernetes/platform sizing, soak, or
  signed release evidence. Openraft remains the sole commit authority, and the
  `EncryptingSessionBackend`/key-provider/HKMS boundary and durable formats are
  unchanged.
- **Experimental HA transport hardening — `opc-session-net`:** each directed
  `RemoteSessionConsensusPeer` now retains a fixed primary/overflow pool of at
  most two authenticated connections, with one in-flight RPC per lane.
  Sequential calls prefer primary, a concurrent call may use overflow, and
  further calls wait for lane acquisition under the same family deadline. A
  socket returns to its selected lane only after a complete, correctly
  correlated, authenticated, and validated successful response or typed
  semantic `Unavailable` response. The latter preserves a known stream
  position but grants no success or authority. Cancellation, timeout, EOF,
  framing, protocol, authentication, scope mismatch, rejection, lifecycle
  retirement, admitted generation/material mismatch, or any uncertain stream
  position leaves the lane evicted.
  Healthy sequential Openraft heartbeats therefore reuse the primary
  DNS/TCP/mTLS/bootstrap path without adding multiplexing or another authority,
  while every replacement repeats the complete admission sequence.
  `opc-consensus` now owns the one fixed complete-call timing profile used by
  session and configuration consensus: AppendEntries/Openraft read-index 2 s,
  Vote 5 s, InstallSnapshot/forwarded mutation/consumer ReadBarrier 10 s,
  election `[5 s, 8 s)`, the shared operation default 10 s, and server
  idle/handler ceilings 30 s. A cold DNS/TCP/mTLS/bootstrap phase is capped at
  1.5 s inside the already-running family deadline, never added to it. `None` on the
  source-compatible remote constructors selects this profile; an explicit
  fixed override remains test/compatibility-only and cannot enlarge the cold
  cap. Real mTLS tests prove the family boundaries and same-leader/same-term
  follower-listener restart, 500 ms cold reconnect, catch-up, readiness, and
  linearizable read within 10 s without a preflight call. Qualification profile
  and evidence schemas advance to v2 while v1 artifacts remain unchanged.
  #143 remains experimental/open for out-of-process deployed-network, full
  failure/resource/soak, payload-key, and candidate-release evidence. Payload
  envelopes, AAD, Openraft authority, SQLite state, HKMS/provider placement,
  and at-rest encryption are unchanged.
- **Experimental production-mTLS session qualification checkpoint —
  `opc-session-testkit`:** the default multiprocess node consumes coherent
  projected SVID material and uses the production authenticated session
  consensus peer/server constructors with exact manifest SPIFFE binding and
  production connection-lifecycle defaults. Its control boundary now reports
  projected-source reload status separately from TLS-controller material
  status, so source publication cannot be mistaken for handshake readiness.
  Real three- and five-process, distinct-SQLite tests atomically replace
  immutable Kubernetes-style `..data` generations through trust overlap,
  per-member leaf and intermediate changes, pre-removal rollback, new-root
  forward/rollback/forward, old-root removal, overlap-first post-removal
  rollback, and a final new-only state. Every member transition requires both
  status planes to advance, explicit process reauthentication, resolver-fresh
  handshakes in both directions for every edge touching the changed member,
  fresh durable readiness, and an encrypted canary read through every voter.
  Each completed fleet phase proves all `N*(N-1)` directed paths and advances
  the acknowledged lease/CAS canary. Separate stale
  old-root clients are rejected by each live new-only server with a typed
  authentication metric, and shutdown scans confirm the exact test canary
  bytes are absent from SQLite/WAL/SHM. This is MemoryKeyProvider wrapper
  evidence, not remote-HKMS qualification. The historical loopback
  plaintext foundation remains behind `foundation-insecure`; the immutable v1
  candidate schema still describes only its earlier formation checkpoint.
  This bounded single-host core is experimental and non-deployed. The later
  fault/expiry slice above covers one exact synthetic admission-loss plus
  malformed-last-good combination and a same-issuer leaf with a 75-second
  remaining-validity/expiry budget under deterministic mixed mutation,
  linearizable-read, complete-restore, readiness, and watch traffic. The
  expiring member stops before soft retirement while survivors continue
  through hard expiry and the stopped watch reconciles after replacement. It
  does not cover a real network partition or a broader restart/fault matrix.
  It now covers exactly one same-disk, exact-address unclean active-mutator
  restart with bounded journal/record reconciliation and higher-fence resume;
  this is not a broader process, host, storage, or deployed restart matrix.
  Resource/soak, remote-HKMS, deployed-CNF,
  supported-platform, and signed candidate evidence remain open under
  #164/#158/#143. Session payload encryption, AAD, key-provider/HKMS
  boundaries, durable formats, and Openraft's sole authority are unchanged.
- **Digest-bound local mTLS candidate evidence — `opc-session-testkit`:** a new
  closed v2 schema and typed redaction-safe record bind each successful local
  rotation-core, fault/expiry-recovery, or traffic/resource campaign to its
  pre-execution source state, exact child and parent-harness artifacts,
  generated configuration, ordered public-certificate/trust publication
  manifest, exact declared orchestration schedule, 3/5-member topology,
  directed-path count, and ordered coverage. Pre-execution bindings are
  rechecked after the campaign. Records are ephemeral unless the existing
  absolute evidence-output contract is set. The public decoder enforces a fixed
  byte cap before parsing closed JSON and applies all cross-field validation
  before returning a typed record; the opt-in bundle uses bounded
  no-follow reads and a private staged, fsynced, atomic no-replace publication.
  Candidate emission is rejected when `foundation-insecure` is compiled, and
  successful record construction remains private to the validated harness.
  Production-credit fields remain fixed false, and deployed
  network/storage, CNF/Kubernetes, platform soak, remote-HKMS, live
  metrics/alerts, independent signing, and HA-profile graduation stay open, so
  this does not complete #164/#158 or change runtime, at-rest encryption, HKMS,
  durable formats, or Openraft authority.
- **Experimental HA qualification — `opc-consensus`, `opc-session-store`, and
  `opc-persist`:** both durable domains now use one fail-closed Openraft runtime
  profile and the exact `openpacketcore/openraft` revision
  `f607e636406b16bd0ad7925dbb631da1b7a4cd96`, which resamples the election
  timeout for each campaign. Domain-level actual-leader-loss tests require a
  different survivor leader at a strictly higher term, continue session
  lease/CAS or configuration transactions, and verify restart convergence. The
  retained 3- and 5-process foundation records the observed transition and a
  generation read while the old leader is down, then independently checks its
  original workload history. Because this is a git-only interim dependency,
  the mechanically derived 26-crate normal reverse-dependency closure is
  `publish = false` until an official stable Openraft release contains the fix,
  the workspace returns to a registry checksum pin, and #143 is fully
  requalified. The profile remains `experimental`; deployed-network, complete
  fault-matrix, resource/soak, payload-key, and candidate-release evidence are
  still open. Payload envelopes, AAD, HKMS/KMS placement, and at-rest encryption
  responsibilities are unchanged.
- **BREAKING — `opc-session-store` watch consumers and legacy
  `opc-session-net` peers:** replication watches now use one documented
  inclusive cursor contract: zero normalizes to one, existing and future
  positions (including `u64::MAX`) never receive a lower sequence, and a
  delivered terminal position closes because no successor can be represented.
  Fake, standalone SQLite, and Openraft-applied SQLite retain a cursor per
  watcher and atomically capture at most 64 backlog entries while registering
  the 64-entry live channel; a larger retained backlog returns the new typed,
  non-retryable `ReplicationWatchCatchUpRequired` without suggesting a skip
  cursor. Compaction remains the distinct typed snapshot-before-resume result.
  Slow consumers are evicted, and cancelled/closed registrations are pruned.
  The production adapter performs its linearizable barrier before the atomic
  handoff and publishes only state-machine-applied entries. The compatibility
  client completes watch setup before returning, preserves an exact typed
  initial rejection, enforces contiguous sequence metadata before outer
  encryption/provider work, and terminates its dedicated connection on peer
  corruption. The v4 wire schema remains revision 4; its error set advances
  from 5 to 6, so every compatibility peer must be drained and upgraded
  together. Openraft consensus transport/schema, persisted SQLite rows,
  snapshots, payload envelopes, AAD, and HKMS placement are unchanged.
- **BREAKING — `opc-ipsec-xfrm`, `opc-gtpu-dataplane`, and `opc-types`:**
  one shared validated `DscpCodepoint` (0 through 63) now reaches both user-plane
  install surfaces. `SaParameters`/`SaState` and `GtpPdpContext` add
  `egress_dscp`; XFRM and GTP-U probes add truthful marking capability fields.
  The Linux XFRM backend uses masked output-mark tokens plus an explicitly
  configured, pinned tc egress companion to stamp tunnel-mode ESP/ESP-in-UDP
  outer IPv4/IPv6 headers while preserving ECN, IPv4 checksum correctness, and
  unrelated mark bits. It validates mark collisions and every live attachment
  before marked mutations, adopts its exact tc slot without a detach gap, and
  binds adoption to the embedded classifier's kernel tag/type/name. Stale-code
  upgrades fail closed and use a documented drain-and-replace procedure. It
  does not claim availability until exact kernel GETSA readback exists. Marked
  SA query/remove and marked policy removal now carry the lookup mark as part
  of the kernel identity. Post-ACK readback compares every stable redaction-safe
  SA field, but cannot prove key ownership; failure is explicitly indeterminate
  and never triggers a potentially destructive same-identity DELSA. Sensitive
  inbound netlink response buffers zeroize on drop. The
  GTP-U eBPF backend adds an independent per-UE DSCP map without changing FAR,
  PDR, counter, or absent-path wire layouts; ordered publication, rollback,
  DSCP-only crash-orphan recovery, additive legacy-pin adoption, and runtime
  map-loss handling fail closed. Both tc links are kernel-owned, preventing old
  loader drop from detaching a static same-slot replacement. Cleanup rechecks
  both program IDs and every named map-pin ID; partial/uncertain cleanup is
  typed indeterminate. Classic tc and bpffs pathname cleanup require the
  documented exclusive-writer boundary and do not claim atomic safety against
  uncoordinated concurrent external mutation. Provisioning reconciles lost tc
  attach ACKs by exact live program ID, propagates every rollback failure, and
  unlinks fresh pins only after exact named-map reproof plus a proven
  no-desired-hook state. A capable pre-attach probe reports `Unknown`.
  Mainline Linux GTP, mock, unsupported, and unconfigured XFRM paths reject a
  requested mark instead of silently dropping it. `None` preserves exact legacy
  netlink/packet bytes. Kernel-independent boundary tests, committed-object
  rebuild gates, and privileged real XFRM/tc and GTP-U wire captures cover both
  set and absent paths.
- **BREAKING — `opc-key` remote-seal implementors:**
  `RemoteSealProvider::unseal` now receives the canonical envelope `KeyId`, so
  remote reads select the exact historical key instead of silently using the
  provider's current active key. `KmsRemoteSealProvider` adds a constant-space,
  process-local `RemoteSealMaterialController`; its clones share publication
  only inside that process. Publication atomically changes future seals while
  an in-flight seal retains its captured key ID. Historical retention and
  revocation stay KMS/HKMS-owned; the SDK has neither a local historical cache
  nor a retirement API or enforcement gate. Redacted production KMS framing
  tests cover exact-ID requests, missing history, and in-flight publication.
  Session tests cover old/new reads, cross-tenant/AAD rejection before provider
  I/O, and a scoped three-node in-process Openraft snapshot-install,
  shutdown/restart restore with zero provider calls below the outer sealing
  boundary. Custom trait implementations and callers must upgrade together
  before any new active ID is published. Durable envelopes, Openraft/session
  wire formats, and KMS framing/schema do not change; decrypt request contents
  now use the historical envelope ID.
- **BREAKING — `opc-key` remote-seal accessors:**
  `KmsRemoteSealProvider::key_id()` is replaced by
  `material_controller()`, `publish_active_key()`, and `material_epoch()`.
  `MemoryRemoteSealProvider::key_id()` is replaced by async
  `active_key_id()`, with `rotate_key()` available for fixtures.
- **BREAKING — `opc-proto-diameter`:** the SWm request model adds DER-only
  `emergency_services` and `terminal_information` fields, while the answer
  model replaces `result_code` with the mutually exclusive typed `result` and
  adds `mobile_node_identifier`. `SwmDiameterResult` preserves whether the wire
  carried a base `Result-Code` or grouped `Experimental-Result`; normal answers
  use `SwmDiameterResult::Base(previous_result_code)`. With both new request
  fields `None`, ordinary DER bytes remain unchanged.
- `opc-proto-diameter`: standards-correct TS 33.402 unauthenticated-emergency
  evidence. Emergency-Services is accepted only on DER; vendor 10415/code 5001
  triggers correlated DEVICE_IDENTITY recovery; the first DER must carry an
  exact IMSI-based emergency NAI in a matching EAP-Response/Identity; the retry
  must add the exact recovered Terminal-Information IMEI without changing the
  first request; and the final exact-success DEA must match both Diameter
  transaction IDs and the EAP identifier while carrying the matching
  IMEI-derived MSK and Mobile-Node-Identifier. Standalone answers and
  no-MSK/NULL-auth shortcuts cannot authorize the flow. Live transports must
  consume the corresponding pending request before constructing evidence.
- `opc-proto-ikev2` and `opc-types`: redaction-safe validated IMEI/IMEISV types
  and strict TS 24.302 DEVICE_IDENTITY Notify 41101 request/response codecs.
  `Imei` preserves 14/15-digit Terminal-Information wire values; `Imei15`
  preserves every DEVICE_IDENTITY/KDF digit without applying Luhn as a wire
  rule. Existing IKE_AUTH methods and bytes are unchanged; emergency completion
  uses the existing ordinary method-2 shared-key AUTH helper with the verified
  MSK.
- `opc-tls`: a shared `TlsMaterialController` and immutable per-handshake
  client/server snapshots. Accepted same-identity rotations and rollbacks
  advance an opaque epoch; invalid, oversized, expired, wrong-key/chain/trust,
  or identity-changing candidates retain only the unexpired prior snapshot.
  Bounded `run_handshake` helpers retry an epoch change through TLS plus
  application negotiation, publish exact admitted epoch/leaf-expiry evidence,
  redact operation errors, cap concurrent attempts, and keep tickets,
  resumption, early data, and 0-RTT disabled. Fixed 3-by-4 redaction-safe
  rotation counters, exact integer material epochs, and effective-chain expiry
  are exported through `opc-redaction`; authoritative projected-source failures
  use cumulative producer accounting in the source publication critical
  section, while a one-time paired controller claim carries a non-cloneable
  process telemetry authority. Per-publication lifecycle tickets record each
  observed expiry exactly once across pre-pairing, source, and controller paths;
  only the registry's active accepted ticket can change current gauges, so an
  observed rejected or retained superseded ticket preserves active material
  evidence. Supersession alone does not synthesize expiry. Acceptance performs
  a serialized current-time expiry check and returns a typed outcome.
  Configuration and Tokio-runtime preflight precede process/controller claims,
  with dedicated runtime/claim errors that do not expand the exhaustive
  compatibility config error. The registry is excluded from
  `SdkMetrics::reset_all`; generic compatibility controllers cannot mutate it.
  Its doc-hidden composition surface is public for trusted cross-crate wiring,
  while cryptographic/material validation and the TLS controller retain
  authorization. A non-cloneable transaction permit gates coherent publication
  without invoking arbitrary code under registry locks; exported metric values
  are never read to authorize TLS or readiness. Explicit-authority constructor
  failures return that authority intact for retry.
  Failures remain counted
  across burst, notification coalescing, recovery before controller
  construction, and source closure; there is no separately droppable monitor
  or public outcome cursor. Existing `rustls_config()`, raw projected identity
  subscriptions, and identity-source event APIs remain source compatible. The
  operator campaign now derives its three-/five-member two-pass rollback
  horizon from every bounded command and
  evidence operation, binds evidence to one live-lease invocation and exact
  operation/member/checkpoint, durably publishes without replacement, keeps
  emergency withdrawal independent of evidence storage, and accounts the
  deliberate old-chain probe without silencing authentication alerts. Its
  adversarial shell harness exercises replay, ENOSPC/unwritable evidence,
  collision/sync failure, recovery signals, bounded math, and concurrent probe
  deltas; this is procedure validation, not deployed fleet qualification.
- **BREAKING — legacy direct `opc-session-net` peers:** every authenticated
  direct and consensus connection now applies one finite
  `ConnectionLifecyclePolicy`, retaining exact admitted material epoch,
  handshake time, and local/peer leaf-expiry evidence. Clients and servers stop
  new admission at soft retirement, bound the transport wait and connection
  slot by the hard deadline, and repeat mutual TLS plus identity, nonce, ALPN,
  version, and exact profile checks on replacements.
  Material-epoch changes use deterministic directed-peer jitter;
  `SessionReauthenticationControl` provides an immediate CNF trigger for
  current-generation proof. Both paths retain bounded reconnect backoff.
  Legacy watches resume from the exact delivered successor;
  mutations retry only after the complete fixed `ConnectionRetiring`
  no-dispatch proof. An authenticated post-TLS rotation race before bootstrap
  acknowledgement now returns
  `BootstrapResponse::ConnectionRetiring` on the generic transport; the
  consensus bootstrap context reserves
  `SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)`
  for the equivalent no-Openraft-dispatch proof. A client retries only after
  decoding the complete control, before sending application or Openraft request
  bytes. Authentication, scope, contract, protocol, and post-bootstrap engine
  rejections remain distinct. EOF, an incomplete
  control, or retirement after an acknowledgement write has partially
  completed fails closed; the server closes without appending a second frame.
  The server counts a successful authenticated connection/control exchange only
  after completely writing the control; the client does so only after decoding
  it completely. That decode initiates the client's bounded retry path and
  counts a reconnect attempt, not a reconnect failure. Direct v5 wire-schema
  revision advances from 5 to 6 and
  requires a coordinated drained full-profile upgrade; the consensus-only
  profile remains transport/wire revision 2. This bootstrap hardening admits
  the already-frozen revision-6 generic variant and existing consensus error
  value in their restricted bootstrap contexts; it changes neither profile
  revision nor public API. Older same-profile decoders fail closed on the
  control, so mixed-patch rolling rotation is not seamless.
  Fixed lifecycle/reconnect metrics use closed redaction-safe labels. A
  supervised backend mutation may finish
  after transport retirement; that path remains typed ambiguous, is never
  automatically retried, and requires authoritative readback or its existing
  operation-bound idempotency/fencing contract. Persisted formats, Openraft
  commit authority, and payload-encryption/HKMS/provider boundaries and
  handling are unchanged. This closes only the narrow pre-acknowledgement
  rotation race; #164/#143 retain fleet trust-removal, revocation,
  reconnect-storm, resource, and soak qualification.
- **BREAKING — `opc-proto-diameter`:** trusted dictionary decode now resolves
  exactly one command by application id, command code, and request/answer role
  before applying vendor-aware per-command AVP cardinality. Conservative SWm
  decode accepts repeatable State and, only through the explicit projected APN
  profile, repeated APN-Configuration; singleton, grouped-child, and unknown
  duplicates still fail at the second AVP offset, while raw decode keeps its
  blanket rejection. `Dictionary[Set]::find_command` now takes application id;
  overlapping/missing command profiles fail closed. Typed singleton guards,
  baseline wire encoding, and unknown-mandatory rejection remain unchanged.
- `opc-ipsec-lb`: additive `SteeringBackendKind::VipDelivered` and
  `SteeringProbe::vip_delivered()` distinguish production converged shared-L2
  floating-VIP delivery from testkit mocks. The ready mutation contract is an
  intentional no-op and claims no XDP, NIC offload, key custody, or datapath
  programming; defaults remain fail-closed as `Unsupported`.
- **BREAKING — `opc-session-net`/`opc-session-store`:** legacy direct-backend
  RPC dispatch now uses independent bounded read, mutation, lease, and watch
  setup admission; after one bounded inbound frame-read phase, one backend
  queue/work deadline plus one reserved response interval form the checked
  post-decode lifetime. Pending work observes peer
  disconnect and server cancellation. Read cancellation is retryable;
  non-CAS and lease mutations that may have crossed their effect boundary
  return `BackendOperationOutcomeUnavailable` or
  `LeaseError::OperationOutcomeUnavailable` and are never automatically
  resubmitted. Malformed, wrong-family, or semantically mismatched responses
  received after transmission use the same non-retryable classification. CAS
  retains its operation-bound idempotency outcome; a backend availability
  result after dispatch becomes an ambiguous tombstone rather than a cached
  retryable result. Production Openraft writes distinguish pre-submission
  failure from a lost result after `client_write_ff` accepts the proposal and
  persist one request identity across internal forwarding retries. SQLite
  ordinary operations and consensus-gated query paths now use one bounded
  blocking-worker admission, asynchronous connection admission, progress/interrupt
  cancellation, and a 100 ms database-busy bound; a cancelled caller cannot
  release the worker permit while SQLite is still running. Fixed timeout,
  cancellation, disconnect, and ambiguity metrics include backend-returned
  typed ambiguity and contain no session identifiers or backend text. The v4
  error-set revision advances from 4 to 5 and requires a coordinated
  compatibility-fleet upgrade. The consensus-only exact profile error set
  advances from 1 to 2 because forwarded applied responses carry the same
  nested error; consensus members also require a coordinated stop/upgrade/start.
  Config-consensus status now snapshots Openraft metrics and exact-membership
  state under one watch guard, then updates admission after releasing it, so a
  queued metrics publisher cannot deadlock a nested status read during leader
  failover.
- **BREAKING — `opc-session-store`/`opc-session-net`/`opc-session-cache`:**
  caller-authored `StoredSessionRecord::expires_at` is now bounded to the same
  365-day horizon as duration TTLs at the mutation coordinator's reference
  time. Past, immediate, and exact-maximum deadlines remain valid; one
  nanosecond more and immortal `EphemeralProcedure` records return fieldless
  `StoreError::InvalidRecordExpiry`. Intentional `None` remains valid for the
  other state profiles. Direct Fake/SQLite batches capture one injected-clock
  reference before mutation, legacy entries bind nested CAS to their immutable
  timestamp, and OpenRaft binds proposal/apply/replay to leader-authored command
  time rather than follower clocks. A bounded, payload-free preflight carries
  at most 256 expiry/state-class descriptors to that authority. Forwarding
  wrappers and the authenticated CAS/batch dispatcher await its verdict before
  idempotency admission, cache invalidation, provider/HKMS work, sealing, or
  backend dispatch. Invalid input performs no provider call or requested
  mutation; timeout/unavailability is retry-safe because only a consensus
  logical-time floor may have committed. `RecordExpiryPreflightLimitExceeded`
  is fieldless and redaction-safe. The legacy exact transport becomes
  `opc-session-net/5`, wire-schema revision 6, error-set revision 8; the
  consensus exact transport becomes `opc-session-consensus/2`, transport/wire
  revision 2, error-set revision 4. Both require a coordinated drained
  full-profile upgrade. The count-only SQLite audit advances to report version 4,
  accepts a reproducible `--expiry-reference`, and counts relational expiry
  violations while strict entry validation covers nested CAS. Violations
  require the documented backup, product-aware re-authoring, OpenRaft recovery,
  re-audit, and rollback procedure. Persisted record/log/snapshot
  representations, payload envelopes, AAD, key lookup, HKMS/KMS placement, and
  encryption-at-rest boundaries do not change; the wire profile intentionally
  does.
- **BREAKING — `opc-session-store` and consumers:** `SessionKey::stable_id` is
  now the validated `StableId` newtype instead of arbitrary `Bytes`. The
  production invariant is exactly 1 through 64 bytes across construction,
  bounded Serde, Fake/SQLite/cache/Openraft stores, restore, replication,
  watches, and session-net; valid JSON/wire/SQLite bytes are unchanged.
  `StableId::derive_hmac_sha256` defines the full-width 32-byte,
  tenant-scoped, domain-separated keyed-digest profile for subscriber-derived
  identities. New SQLite stores add matching BLOB/width checks, while existing
  stores and snapshots require the version-3 count-only identity audit before
  upgrade. Empty, oversized, or non-BLOB legacy identifiers are never echoed,
  truncated, or silently rehashed; follow the documented drain,
  application-owned remediation, re-audit, and rollback procedure.
- **BREAKING — `opc-session-store` and consumers:** `ReplicationEntry::tx_id`
  is now the validated `ReplicationTxId` newtype instead of arbitrary `String`.
  The accepted legacy representation is exactly 1 through 128 UTF-8 bytes and
  remains byte-for-byte compatible; no trimming, case-folding, parsing, or
  normalization can collapse fork/idempotency identities. New committed
  Openraft coordinator writes mint a fixed 32-byte lowercase hexadecimal ID
  from the 16-byte consensus request identity. Fake/SQLite/cache/encryption,
  rebuild/watch/snapshot/recovery, session-net, and SDK exports use the typed
  identity. New SQLite stores enforce `TEXT` plus exact width bounds; runtime
  hydration cross-checks relational and encoded IDs; report version 3 adds a
  count-only `invalid_replication_tx_id_fields` migration signal. Follow the
  coordinated audit/remediation/restart/rollback runbook. This changes no
  payload envelope, AAD, HKMS call, or encryption-at-rest boundary.
- **BREAKING — `opc-session-store`/`opc-session-cache`/`opc-session-net`:**
  replication-log reads now use one checked `ReplicationLogRange` contract at
  every adapter, wrapper, Openraft, cache, server, and client boundary.
  Sequence zero aliases inclusive sequence one; zero-limit reads are empty
  before I/O; non-empty pages must begin at the exact normalized cursor and
  remain inside the checked interval; the model-wide page maximum is 65,536.
  Overflow, one-over-limit, and compacted cursors have distinct typed errors,
  including the exact post-snapshot resume point. A compatibility client drops
  its connection and capability cache when a peer returns an otherwise
  contiguous page before or after the request. Frame shortening still exposes
  only the largest exact prefix. The v4 error-set revision advances to 4, so
  legacy session-net participants require a coordinated stop/upgrade/start.
  Production Openraft performs a linearizable barrier then reads one local
  applied state; it never unions pages from replicas with different compaction
  floors. This changes no commit authority, payload envelope, AAD, HKMS call,
  encryption-at-rest boundary, restore cursor, or watch cursor contract.
- `opc-identity`: a production `ProjectedSvidSource` for Kubernetes projected
  Secrets. It resolves one immutable `..data` target, detects and boundedly
  retries every mid-read generation switch, enforces exact file/total/
  certificate/trust/retry limits, retains only unexpired last-known-good
  material, and publishes an opaque monotonic generation with typed,
  redaction-safe availability/reason status. Existing file/socket source APIs
  and reload events remain source compatible.
- **BREAKING — `opc-session-net`/`opc-session-store`:** direct CAS
  idempotency in the quarantined protocol-v4 compatibility path is now scoped
  by the authenticated logical replica, canonical request UUID, complete
  operation digest, cluster/configuration identity, monotonic configuration
  epoch, and a server-issued process epoch. Exact successes and conflicts
  replay through one bounded single-flight cache; mismatched reuse fails typed
  before backend dispatch, and cancelled work becomes an ambiguous tombstone.
  Total and per-peer entries/bytes, retention, and cleanup work are fixed.
  Restart, retention rotation, or pressure returns
  `CasIdempotencyOutcomeUnavailable`; the public client performs no automatic
  CAS resubmission after an ambiguous exchange and requires an authoritative
  re-read before a newly derived mutation. The v4 error-set revision advances
  to 3, `Hello`/`HelloAck` add `configuration_epoch`, `HelloAck` adds
  `cas_idempotency_epoch`, direct CAS carries `idempotency_epoch`, and
  exhaustive public frame construction/matching must
  be updated in one coordinated stop/upgrade/start.
- `opc-sctp`: `DiameterSctpAssociation::connect_with_config` now opens the
  existing Diameter-framed send/receive surface over an explicit
  `SctpConnectConfig`, including bounded static local and remote multihoming.
  Unsupported kernel or namespace multihoming remains a typed capability
  failure and never degrades to one address silently.
- **BREAKING — `opc-session-store`:** bounded authoritative restore scans now read only the
  local Openraft-applied state after a linearizable barrier, seek the existing
  SQLite composite primary key, cap pages at 4,096 examined live candidates,
  1,024 returned records, 4 MiB payload, 8 MiB retained bytes, and 8 MiB
  examined key/filter metadata, and enforce one absolute entry-to-task SQLite
  operation deadline plus fixed VM-step and drop-cancellation budgets. Candidate
  and lookahead SQL omit payload blobs. Strictly bounded variable-length
  AES-256-GCM-SIV cursor tokens keep the seek key, backend epoch, record
  revision, logical time, and scope confidential and authenticated, while an
  clear cumulative position is bound into cursor authentication and supports a
  structural check of claimed progress without claiming peer completeness;
  stale, edited, mutated, or
  cross-scope reuse fails typed instead of skipping or merging state. Existing
  stores receive an O(1) cursor-key metadata migration without record backfill.
  `RestoreScanCursor` changes to a confidential bounded token and
  `RestoreScanPage` adds `cursor_profile`; exhaustive construction and matching
  must be updated.
- **BREAKING — `opc-session-net`:** the quarantined v4 compatibility profile
  advances to wire-schema revision 4; error-set revision 4 includes the
  confidential restore token, explicit durable-page profile, examined/payload
  contracts, typed stale-cursor/work-budget errors, and typed direct-CAS
  idempotency outcomes. Local fake offset
  cursors are rejected remotely. Servers validate against the narrowed request
  actually dispatched and no longer fabricate shortened-page cursors when a
  backend page exceeds the negotiated frame; callers retry the same cursor with
  a smaller record limit.
- `opc-sctp`/`opc-libsctp-sys`: bounded static SCTP multihoming through the
  Linux bindx/connectx socket UAPI. Multi-address local and peer sets are
  validated for count, family, and port; one-address configurations keep the
  existing `bind(2)`/`connect(2)` path; kernel-reported local/peer address
  inspection and typed capability-unavailable errors make fallback explicit.
  Live Linux tests prove full-set bind/connect and delivery after the
  established primary path is removed.
- `opc-consensus`: the workspace's single exact-pinned Openraft integration
  boundary, with bounded Postcard codecs, cluster/configuration/epoch identity,
  stable SQLite-safe node IDs, request identities, and transport-neutral RPC
  contracts. ADR 0019 prohibits domain crates from importing Openraft directly
  or implementing a competing election/commit/read-authority algorithm.
- `opc-session-store`/`opc-session-net`: an Openraft-backed
  `ConsensusSessionStore` and dedicated `opc-session-consensus/1` authenticated
  transport. Durable vote/log/commit/application/membership/outcome state,
  bounded atomic snapshots, linearizable readiness/reads, idempotent
  response-loss retries, committed-only journals/watches, monotonic logical
  expiry time, and three-node cold-start/partition/heal/restart tests replace
  the custom majority-visible-prefix coordinator under #127.
- `opc-session-store`: end-to-end encryption-boundary qualification passes
  plaintext and raw-key canaries through the real `EncryptingSessionBackend`,
  rotates the active key, snapshots/restarts, and verifies only opaque
  envelopes enter consensus RPCs, SQLite/Raft logs and outcomes, WAL/SHM, and
  snapshots. Openraft never owns or calls HKMS; this remains payload-envelope
  encryption rather than full-database metadata encryption.
- `opc-session-store`/`opc-key`: consensus admission now validates the exact
  canonical RFC 003 envelope, session AAD shape, embedded key ID, algorithm
  nonce, tag bound, and record-visible tenant/NF/state/generation/fence fields.
  `EnvelopeV1` can no longer be forged by attaching the enum marker to
  arbitrary bytes, including through deserialization.
- `opc-session-store`: claiming a SQLite database for Openraft is an atomic
  authority hand-off. Retained clones and freshly reopened raw SQLite handles
  reject reads, leases, CAS, journal append/rebuild, watch, restore, and prune
  paths; private committed-journal reads remain available only after the
  consensus adapter's linearizable barrier.
- `opc-session-store`: a read-only `LeaseGuard::credential_id()` accessor lets
  transport adapters verify that renewal responses preserve the opaque
  credential; guard construction remains crate-private.
- `opc-session-store`: `probe_durable_readiness` and stable readiness report
  types for fresh, bounded Openraft linearizable-read evidence. Reports
  distinguish `Ready`, `NoQuorum`, `TopologyInvalid`, and `RecoveryRequired`;
  expose configured, freshly reachable, agreeing, and required voter counts
  plus the committed barrier index through the compatibility-named index
  accessor; and use typed, redaction-safe replica
  failure classes instead of raw errors. Capability declarations and
  `SessionStorePlatformProfile::Quorum` remain admission evidence only. This
  base probe is now explicitly engine/lab evidence; production traffic uses
  authenticated topology and `probe_production_durable_readiness`.
- `opc-session-store`: Openraft-owned follower recovery now has a second
  fail-closed SQLite boundary: truncation cannot cross the persisted committed
  or applied index, and snapshot install cannot regress either floor or cross
  cluster/configuration identity. Restart validates the referenced snapshot,
  cleans a bounded set of interrupted SDK staging/orphan files, and rejects
  corrupt state before engine admission. Covered-log purge now waits behind
  asynchronous snapshot apply under one ten-second bound, fixing a lagging
  follower failure that otherwise installed the state image and then stopped
  before Openraft acknowledged recovery. Readiness adds redaction-safe
  `synchronized`/`catching_up`/`awaiting_quorum`/`recovery_required` progress
  with local log/applied/snapshot/purged counters. Deterministic tests replace
  multiple uncommitted same-index tails while preserving the committed prefix,
  reject stale/wrong-identity/corrupt snapshots, and prove restart continuity.
- `opc-session-store`: immutable replica descriptors and
  `ValidatedQuorumTopology` admission with distinct logical ID, canonical
  endpoint, expected TLS identity, failure domain, backing identity, and exact
  local-self selection. Engine topology is adapter-free: the one local SQLite
  backend and consensus-only remote peer map are supplied separately, so remote
  votes require no dummy backend or legacy remote-backend client. Descriptor-
  only admission is lab-scoped; production admission adds authenticated
  platform evidence. An explicit lab singleton reports `single-replica`, never
  quorum HA.
- `opc-session-store`/`opc-session-net`: redaction-safe authenticated peer
  bindings connect legacy compatibility adapters to exact peer scope, while the
  production Openraft transport binds descriptor identity and stable node IDs
  directly on every consensus connection.
- `opc-sa-mirror` (RFC 015): experimental live SA keymat mirroring for
  near-hitless IPsec failover in which keys never persist — producer/sink/
  takeover ports, an in-memory standby holder with epoch anti-rollback and
  fail-closed capacity, an mTLS-only keymat transport with zeroizing frame
  buffers, and takeover output pre-validated as
  `SameSpiResume { key_source: LiveMirrored }` for the fenced re-pin.
- `opc-proto-ikev2`: a seedable responder Message-ID replay window, the full
  RFC 7296 error-notify registry, public nonce encoding, and stricter
  CREATE_CHILD_SA rekey proposal/KE validation.
- `opc-ipsec-xfrm`: non-zero request IDs and wildcard-SPI policy templates so
  old and replacement Child SAs can overlap under one stable policy contract.
- `opc-ipsec-lb`: clone-shared tagged-SPI reservations; allocation and rekey
  now skip SPIs restored by another session owner.
- `opc-proto-gtpv2c`: a bounded TS 24.008 PCO container codec for P-CSCF and
  DNS address requests/responses, including repeated response containers and
  accepted-session PCO access.
- `opc-dataplane-testkit`: a bounded multi-session GTP-U reflector keyed by
  inbound local TEID, with idempotent registration and conflict detection.
- `opc-ipsec-lb`: `SessionStoreOwnershipFencer`, an ownership
  promotion adapter that acquires the session-store lease, commits a
  generation-guarded owner change, and projects the committed store fence into
  the re-pin grant. #127 now supplies the required Openraft authority; #143
  still owns networked production qualification.
- RFC 014 and `opc-mgmt-command`: the model-driven interactive operational
  console contract plus a transport-neutral, bounded command catalog with
  schema-validated reads, subscriptions, allowlisted actions, presentation
  metadata, and deterministic registry freeze.
- `opc-nacm`/`opc-nacm-config`/`opc-mgmt-authz`/`opc-persist`/
  `opc-mgmt-principal`: RFC 8341-style NACM rule-lists scoped to signed
  principal groups, principal-aware policy selection, a typed `/nacm` datastore
  model with SPIFFE group selectors, encrypted persistence round-trip support
  for rule-lists, and a signed-grant source boundary for populating
  `TrustedPrincipal.groups`.
- `opc-route-steering` and `opc-linux-route-sys`: experimental safe/mock/Linux
  route and rule steering backend with rtnetlink `RTM_NEWROUTE/DELROUTE` and
  `RTM_NEWRULE/DELRULE` support, redaction-safe errors, and probe coverage.
- `opc-ipsec-xfrm`: `query_sa` plus `SaState`/`SaReplayState` for replay and
  sequence-counter continuity, including Linux `XFRM_MSG_GETSA` decode and
  legacy/ESN replay restore attrs on SA install/rekey.
- `opc-gtpu-dataplane`: `resolve_device(name)` to inspect/adopt an existing
  Linux `gtp` netdevice by name without changing exclusive create behavior.
- `opc-key`: `KeyPurpose::IpsecSa` for sealed IPsec SA traffic-key records.
- `opc-proto-diameter` (experimental): RFC 6733 header/AVP framing, dictionary
  metadata, feature-gated base peer procedures (CER/CEA, DWR/DWA, DPR/DPA),
  registered fuzz targets, and initial Rf/SWm 3GPP application dictionaries;
  consumed as a direct protocol dependency rather than through the `opc-sdk`
  default facade/prelude.
- `opc-proto-gtpv2c` (experimental): S2b typed subset, consumed as a direct
  protocol dependency rather than through the `opc-sdk` default facade/prelude.
- `opc-proto-ikev2`: SDK helpers for IKEv2 SA lifecycle handling, including
  Delete payload encoding, `REKEY_SA` Child-SA rekey payload assembly,
  initiator Message-ID window tracking, and protected INFORMATIONAL coverage.
- `opc-proto-ikev2`: `Ikev2SaInitKeyMaterial::from_established_keys` for
  rebuilding established IKE SA key material from sealed `SK_*` bytes, plus a
  monotonic AES-GCM explicit-IV counter for HA restore without outbound nonce
  reuse.
- `opc-proto-pfcp`: typed IE coverage for the Session Modification lifecycle
  (Update PDR/FAR/URR/QER, Update Forwarding Parameters, Remove PDR/FAR/URR/QER)
  and the Session Report / usage-reporting flow (Report Type, Measurement
  Method, Reporting Triggers, Volume/Time Threshold, Volume/Time Quota,
  Monitoring Time, Offending IE, Usage Report Trigger, Volume Measurement,
  Duration Measurement, UR-SEQN, and grouped Usage Report).
- `opc-proto-pfcp`: message builders for Session Modification Request, Session
  Report Request, and Session Report Response.
- `examples/smf-reference`: end-to-end N4 exercise that has the SMF send a
  typed Session Modification Request (Update FAR + Remove PDR) and the fake UPF
  send a typed Session Report Request (Usage Report with Report Type and
  volume/duration measurements), with field and wire-byte assertions.
- `opc-mgmt-limits`: `MgmtLimits::min_sample_interval` (default 100 ms), the
  server-side floor for gNMI SAMPLE `sample_interval` and `heartbeat_interval`.
- `operator-sdk-go`: `bridge.ErrorKind` implements `fmt.Stringer`, so wrapped
  bridge errors log a named kind instead of a bare integer.
- CI: Go race-detector and golangci-lint gates, a generated-code drift check
  for the NGAP/NNRF bindings, an `opc-sdk` depth-2 feature-powerset check, a
  pinned checksum-verified gitleaks secret scan, a PR smoke-fuzz lane
  (60 s/target) alongside the scheduled run raised to 600 s/target, and
  committed fuzz corpora for the GTP-U, NAS, Diameter, and IKEv2 targets.

### Changed
- **TLS certificate lifetimes — `opc-tls` and `opc-session-net`:** coherent
  material admission and retained-connection deadlines now use the earliest
  expiry across every certificate in the configured or peer-presented chain,
  while preserving the exact leaf expiry and distinct fixed local/peer
  earlier-chain retirement metrics. Expired/future intermediates receive typed
  temporal rejection before chain rebuild. Server and client paths now classify
  certificate/trust, TLS-protocol/ALPN, and transport failures consistently.
  `TlsMaterialStatus` and `TlsAdmittedConnection` serialize the additional
  redaction-safe chain-expiry timestamp, so strict JSON consumers must accept
  that additive field. Short-lived SVID expiry is the bounded same-issuer
  compromise mechanism; generic CRL/OCSP/denylist revocation remains
  unsupported, and #164 fleet rotation qualification remains open.
- **TLS fleet-rotation mechanics — `opc-session-net`:** a bounded in-process
  test now runs real three- and five-voter Openraft/SQLite fleets over the
  production mTLS transport through leaf, presented-intermediate, root,
  overlap/removal, and pre/post-removal rollback transitions. Each changed
  voter proves fresh bidirectional handshakes and durable readiness; each phase
  preserves an acknowledged encryption-wrapper canary, and removed old-root
  chains fail to establish. This is SDK-generated loopback evidence only:
  `opc-session-testkit` still reports `foundation_counts_for_tls_rotation =
  false`. The later non-ignored testkit cases cover one exact single-host
  multi-process fault/expiry slice without advancing that schema; deployed and
  broader fault/resource/soak/remote-HKMS/signed qualification stays open.
- **BREAKING — `opc-persist`:** #177 replaces the crate's custom Raft-style
  config engine and `QuorumConfigStore` majority wrapper with
  `ConsensusConfigStore` on the exact-pinned `opc-consensus` Openraft engine.
  The old election/replication/read-index/membership/snapshot modules, private
  config TCP peer/server types, custom consensus metrics/error families, and
  the standalone consensus-node binary are removed. Config consensus now exposes
  only the shared bounded `ConsensusPeer`/`ConsensusRpcHandler` boundary;
  production mTLS, deadlines, peer authentication, and certificate/trust
  rotation remain owned by `opc-session-net` and the CNF composition, with no
  second config TCP transport.
  The authority hand-off is atomic per SQLite database: one immediate
  transaction checks legacy state, imports an approved applied snapshot when
  required, creates `config_raft_identity`, and fences every public standalone
  mutation including retained and freshly reopened backend clones.
  `SqliteBackend::conn`, `SqliteBackend::audit_key`, and `AuditKey::as_bytes`
  are no longer public; consumers use typed store operations and opaque key
  ownership instead of mutable/raw authority escape hatches. Normal open
  rejects nonempty legacy authority. Offline recovery requires the source
  file's exact SHA-256, exact latest transaction ID/version, a contiguous
  parent/version history (without assuming the retained origin is version 1),
  and explicit
  `DiscardUnknownAppendedSuffix`; unprovable target tails are discarded rather
  than inferred committed. Rollback is only a stopped-fleet restore of
  preserved pre-migration backups, not deletion or reverse translation of
  `config_raft_*` state.
  Durable log floors are immutable, encoded log entries are capped at 16 MiB,
  and persisted holes fail closed while Openraft may still replace an explicit
  uncommitted suffix. Snapshot startup verifies referenced authority before a
  bounded orphan/sidecar cleanup, and cancellation-safe guards remove receive,
  build, install, promote, and approved-recovery staging. Forwarded mutations
  and read barriers propagate the one caller's remaining timeout budget rather
  than minting a new server deadline. Payload-mismatched request-ID reuse is a
  deterministic no-op with the stable `RequestIdCollision` error and does not
  destroy the original recoverable outcome.
  The application/HKMS layer encrypts before proposal; Openraft persists and
  replicates only sealed ciphertext, deterministic metadata, and redacted
  finalized audit, never plaintext, provider/key handles, or raw key material.
  In-process formation, partition/heal, failover, response-loss, snapshot,
  fencing, and migration tests plus an AMF-lite provider-backed encryption,
  key-rotation, follower/snapshot/restart, shared-wire/live-artifact canary, and
  exact provider-call integration are three-node provider/HKMS-boundary
  qualification. Shared transport tests cover finite retained-connection
  retirement, full-handshake reauthentication, request/watch continuity, and
  rejection of removed or wrong-scope trust.
  The suite also forms a real three-node config Openraft cluster and
  commits/linearizably reads through the existing mTLS peer/server. Remote-HKMS,
  out-of-process/deployed-network integration, resource, soak, seamless fleet
  rotation, and release evidence remain `GAP-001-006`.
- **BREAKING — `opc-session-store`:** production HA construction now requires
  `QuorumTopologyConfig::new_consensus`, a file-backed local SQLite adapter,
  exact consensus peer routes, handler installation, and cluster
  initialization. `QuorumSessionStore` aliases `ConsensusSessionStore`; the
  former custom coordinator constructors and testkit majority controls are
  removed. Direct replication/rebuild/lease-sequence authority fails closed.
- **BREAKING — `opc-session-store`:** `EncryptedSessionPayload::envelope` is
  replaced by fallible `try_envelope`, and the encryption wrappers no longer
  expose their raw inner backend. This prevents marker-only payloads and
  accidental mutation around the required protection boundary.
- **BREAKING — `opc-session-store`:** the retired log-scan
  `DurableReadinessOptions` and related constants are removed. Configure the
  single complete Openraft operation deadline with
  `ConsensusSessionStore::open_with_operation_timeout`; readiness and real
  operations use that same deadline and consensus barrier.
- **BREAKING — `opc-session-net`:** production HA uses the consensus-only ALPN
  and RPC types. The writable protocol-v4 backend façade is a compatibility
  surface, not a quorum member or consensus authority.
- **BREAKING — `opc-proto-diameter`:** `SwmDiameterEapAnswer` gains
  `default_context_identifier: Option<u32>` and
  `default_apn_configuration()` so SWm DEA consumers can resolve an opt-in
  subscription-profile default extension to one exact `APN-Configuration`;
  top-level `Service-Selection` is no longer documented as the default APN.
  Struct literals must initialize the new field (`None` preserves the previous
  wire shape). Encode and parse now reject zero or duplicate child
  Context-Identifier values, duplicate child Service-Selection values, and a
  default pointer that does not resolve to a supplied configuration; APN
  profile material requires exact `DIAMETER_SUCCESS` (2001). The baseline SWm
  DEA ABNF does not enumerate this pointer; it is accepted under the extension
  wildcard for deployments projecting TS 29.272 profile semantics. Older SDK
  decoders reject its required M-bit as unknown, so deploy upgraded decoders
  before enabling `Some(id)` on encoders. Repeated projected APN configurations
  require `DuplicateIePolicy::Last` until #131 replaces the conservative
  blanket duplicate pre-scan; typed singleton duplicate checks remain enforced.
- **BREAKING — `opc-session-net`:** the wire contract is now v4. Public
  `Request` and `Response` remain available, but their Serde implementations
  delegate to private fixed-width DTOs; `Hello`/`HelloAck` gain an optional
  `contract_profile`, so exhaustive construction and matching must initialize
  or accept the new field. Restore cursors and response counters use `u64`;
  request page/count limits use `u32`; capability and size-bearing store-error
  values use `u64`; and restore `loaded_count`/`complete` are recomputed instead
  of trusted from the peer. Independent work limits cap batch operations at
  256, restore pages at 1,024 records, and replication-log pages and rebuild
  prefixes at 65,536 entries, while the contract profile pins the existing
  depth-16/256-node replication tree, 128-byte owner/custom-key/state-type
  bounds and 31,536,000-second TTL maximum. The initial profile used
  wire-schema/error-set revisions 1; #159 below advances only the schema
  revision.
  The exact `opc-session-net/4` ALPN,
  version, and profile have no v3 fallback or downgrade negotiation: drain and
  stop every client, server, and protection-wrapper participant, complete the
  #135 identity/handover and nested-payload preflights, upgrade them together,
  verify v4 authenticated restore/log traffic and fresh quorum evidence, then
  restore traffic. Version/profile/authentication/malformed-handshake failures
  clear cached capabilities and report every boolean false with
  `max_value_bytes = 0`; any cache retained after transient transport loss is
  descriptive only and cannot authorize a store operation or readiness. #159's
  follow-up outbound contract is described below.
- **BREAKING — `opc-session-net`:** protocol v4's exact contract profile advances
  to wire-schema revision 2 (error-set revision remains 1) and negotiates
  directional frame budgets. Hello gains
  `requested_response_frame_size: Option<u32>`; HelloAck gains
  `accepted_response_frame_size: Option<u32>` and
  `server_request_frame_size: Option<u32>`; exact revision-2 admission requires
  all three as `Some` checked values with
  `min_frame_size = MIN_NEGOTIATED_FRAME_SIZE = 8192` and
  `max_frame_size = MAX_NEGOTIATED_FRAME_SIZE = 16777216` (16 MiB).
  `MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases the same 8 KiB minimum.
  The profile also pins `stable_id_max_bytes = 64`,
  `replication_tx_id_max_bytes = 128`, and `cas_request_id_bytes = 36`:
  transported stable IDs are 1 through 64 bytes, replication transaction IDs
  are 1 through 128 UTF-8 bytes, and CAS request IDs, when present, are
  canonical lowercase hyphenated UUIDs. The new public `ContractProfile` field
  and exhaustive public frame construction/matching are Rust source breaks.
  Revision-1 and revision-2 peers share the `opc-session-net/4`
  ALPN but deliberately reject one another, so drain and stop every
  client/server and protection wrapper, upgrade the whole fleet, verify unequal-limit maximum
  payload round trips and slow-reader slot recovery, then restore traffic. Do
  not perform a same-v4 rolling upgrade.
- `opc-session-net`: every post-bootstrap response and watch item is fully
  bounded-encoded before a length prefix is emitted; no individual sizing or
  retained encoded-JSON byte store exceeds the negotiated response budget.
  Encoding uses lazy exact-length boxed chunks and never coalesces them; chunk
  metadata and allocator slab/RSS overhead are outside the wire-byte budget.
  Common non-pageable and
  complete-page successes use one bounded encode without a sizing preflight.
  An oversized pageable attempt emits no prefix, then may use bounded
  logarithmic sizing probes plus one final encode. One absolute deadline starts
  before the first direct encode/probe and is reused through every probe, final
  encode, prefix, payload, and flush; a slow reader is closed and its handler
  slot is released. Deadline and server-abort cancellation are also checked
  cooperatively by synchronous storage and sizing sinks between serializer
  writes/chunks; Tokio task abortion cannot preempt one synchronous serializer
  callback, so the bounded wire-field contract remains part of the shutdown
  interval.
  Server admission now returns `InvalidInput` before binding or spawning when
  the frame limit is outside 8 KiB..=16 MiB, the connection-slot count is
  zero or outside Tokio's supported range, or a configured timeout cannot be
  represented. A zero timeout remains an intentional immediate-fail policy.
  Get/CAS records and positional batch results are never truncated. Restore and
  replication-log results may return only complete cursor/contiguous-sequence
  prefixes; watch never skips an over-limit entry. A fixed SDK-owned,
  redaction-safe fallback is sent when representable, otherwise the connection
  closes without an oversized/partial frame. Rejected nested entries retain
  bounded iterative disposal.
- `opc-session-net`: transported `max_value_bytes` now uses the backend limit and
  `conservative_payload_budget(frame) = frame.saturating_sub(8192) / 8`, reserving
  record/key/error-envelope space, worst-case JSON byte-array expansion, and
  equal escaping/metadata headroom. The clamp takes the backend, accepted
  response, and server request minima so it covers both directions.
  The advertised value is executable across unequal client/server frame limits,
  but remains descriptive rather than readiness. It is zero at the exact 8 KiB
  minimum, 130,048 bytes at the 1 MiB default, and 2,096,128 bytes at the
  16 MiB ceiling. Advertising SQLite's full 1 MiB value limit requires a frame
  of at least 8,396,800 bytes; 16 MiB is the recommended setting. This is a
  per-frame bound: at the default 128 connection slots, simultaneous
  ceiling-sized encodes can retain about 2 GiB before metadata/TLS/runtime
  overhead. The aggregate scales with `with_max_connections`, so aggregate byte
  permits and distributed resource/soak evidence remain #143. A
  mutation may commit before response encoding/delivery fails; no response is
  an ambiguous outcome that requires request-ID/idempotency, fencing, and an
  authoritative re-read rather than an assumed rollback or blind retry. Diagnostics use finite
  `response_family` values and fixed `frame_too_large`, `page_shortened`,
  `write_timeout`, `transport`, and `encoding` reasons, and exclude keys,
  payloads, owners, transaction IDs, peer identities, and backend/peer-controlled
  error text.
  #159 does not rewrite the persisted store format. #167 now promotes its
  stable-ID rule into the structural model/persistence/privacy/audit/migration
  contract without changing compliant bytes. #168 now supplies the bounded
  durable transaction-ID type, canonical coordinator mint, exact legacy
  preservation, SQLite/recovery validation, and version-3 migration audit
  coordinated with #127/#128/#143. Before revision 2, quiesce writers and use a reviewed
  decoder-first migration for any out-of-profile retained record, log,
  snapshot, restore source, or replay source; never truncate or rename an
  identity to make it fit. Binary rollback requires a drained coordinated fleet
  at one exact revision and a rollback decoder that can read the retained target
  representation before old writers restart, or a coherent checkpoint/reverse
  migration; the separate `OPCH`/#135 rollback barrier still applies.
  Session-net's response deadline remains part of the shared production
  transport. #177 removes `opc-persist`'s private TCP peer/server and uses the
  same transport-neutral consensus ports instead of defining another deadline,
  retry, or certificate lifecycle. #163 implements the shared finite connection
  lifecycle; fleet credential/trust evidence remains #164/#158, while distributed
  resource/failover/soak plus payload-protection qualification remains #143.
- **BREAKING — `opc-session-store`:** the old backend-bearing quorum member and
  raw-vector coordinator surfaces are removed. Migrate HA engine callers
  through an adapter-free `QuorumTopologyConfig`/`ValidatedQuorumTopology`;
  production callers additionally use `try_from_attested`, while descriptor-only
  and `try_new_consensus_lab_singleton` paths remain lab-scoped. Supply exactly
  one local SQLite backend and the remote consensus-peer map when opening each
  node.
- **BREAKING — `opc-session-net`:** protocol v3 introduced remote restore scans
  and authenticated replica identity before the v4 boundary above. Production
  constructors
  accept opaque authenticated TLS configs plus bindings derived from one
  immutable manifest; the manifest hashes the cluster ID, explicit generation,
  and complete descriptor set. The exact v3 ALPN and handshake had no v2
  fallback, so that transition required a coordinated upgrade and did not
  support mixed v2/v3 rolling upgrades. Public `Request`/`Response` enums
  gain handshake and restore-scan variants, while `StoreError` gains
  restore-scan, `InvalidReplicationSequence`, and `InvalidSessionTtl` variants,
  and `LeaseError` gains `InvalidSessionTtl`; external exhaustive matches must
  add arms for them. The new validation errors are serialized on v3 only in
  response to malformed replication metadata or oversized TTLs. Those changes
  do not alter otherwise-valid v3 traffic, but older v3 peers cannot decode a
  newly returned variant and must be upgraded in the coordinated fleet rollout.
  The separate operation-tree contract below adds stricter v3 semantics.
- **BREAKING — `opc-session-store`/`opc-session-net`:** replication operation
  trees are now limited by public
  `MAX_REPLICATION_OPERATION_DEPTH = 16` and
  `MAX_REPLICATION_OPERATIONS_PER_ENTRY = 256`; the root is depth 1 and every
  node, including `Batch`, counts toward the total. `StoreError` gains the
  fieldless serialized `ReplicationOperationLimitExceeded` variant, so
  exhaustive matches must add an arm and older v3 peers cannot decode it.
  Mixed old/new v3 fleets are also not confidentiality-safe because an older
  wrapper may forward a deeply nested CAS without encryption/sealing. Upgrade
  every client, server, and wrapper participant as one coordinated fleet; do
  not claim rolling compatibility. Protocol v4 now pins these limits and the
  error revision in its fixed-width DTO and handshake contract.
- **BREAKING — `opc-session-store`/`opc-session-net`:** `OwnerId` and
  deployment-specific session-key type names now accept exactly 1 through 128
  UTF-8 encoded bytes. `SessionKeyType::Other(String)` is replaced by the
  structurally validated `Other(CustomSessionKeyType)`, and runtime callers use
  the fallible `SessionKeyType::other`. The five canonical reserved spellings
  (`subscriber-context`, `pdu-session`, `teid-mapping`, `pfcp-seid`, and
  `handover-transaction`) always decode to their well-known variants and cannot
  be constructed as `Other`; ordering is by the canonical persisted string,
  not enum declaration order. Serde, SQLite hydration, restore scans, lease and
  fenced-mutation reads, replication-log hydration, and session-net request and
  response decoding now apply the same invariants. Existing valid protocol-v3
  JSON retains its string shape, but this is a Rust source break and a stricter
  semantic-admission boundary: an older v3 participant may still emit values a
  new participant rejects. Drain and upgrade every session-net client, server,
  and wrapper as one coordinated stop/upgrade/start. Protocol v4 now makes this
  identity admission part of the exact contract profile.
  `HandoverEnvelope::unpack_raw` and `HandoverSessionRecord::unpack_raw` now
  return `Result`; both types' public `unpack_json` methods use
  `HandoverEnvelopeDecodeError` instead of `serde_json::Error`; and
  `HandoverError` gains `InvalidEnvelope`. Callers and exhaustive matches must
  migrate to the redaction-safe typed failure. Newly
  packed handover envelopes use the `OPCH` magic plus an exact version byte.
  The bounded non-`OPCH` classifier accepts current-valid original syntax and
  some bare payloads; ambiguous, zero-length, truncated, oversized JSON-looking,
  malformed, or typed-invalid claims fail before mutation. New
  `unpack_*_with_format` APIs expose syntactic format, which is not provenance.
  The identity audit does not classify live or nested-log payloads, so rollout
  requires a complete product-aware decrypted replay preflight and coordinated
  upgrade of every handover reader/writer. After the first live/replayable
  `OPCH` write, rollback requires a coherent fleet checkpoint or reviewed
  reverse migration of records, logs, snapshots, and restore sources.
- Documentation and package metadata now distinguish scoped implementation
  evidence, Cargo publication eligibility, and production maturity. Historical
  status snapshots, release-evidence primitives, and conditional
  session/protocol profiles no longer imply current production approval.
- **BREAKING — `opc-ipsec-xfrm`:** XFRM SA requests, policy templates, and
  decoded SA state now carry an optional `XfrmRequestId`; callers using public
  struct literals must initialize the new field.
- **BREAKING — `opc-ipsec-lb`:** same-SPI failover callers must migrate
  `AntiReplayResume` struct literals to either `ExactWindowRestore` or
  `BoundedReopening`, rename the checkpoint field to
  `checkpointed_send_iv_next`, and supply protocol-typed
  `send_iv_forward_jump` evidence. ESP ESN counter-mode evidence must include
  the caller-attested maximum peer receive-sequence lag; IKE IV64 evidence is
  unchanged. Custom `OwnershipFencer` implementations must support exact
  retry-proof validation and read-only committed-grant recovery. Re-pin
  requests now carry a deployment-unique transition ID and the exact
  predecessor fence; custom `OwnershipSource` implementations must return an
  authoritative SA owner/fence snapshot. `RePinCoordinator` now also requires
  an `OwnershipSource` and returns `RePinError`. Its recovery partial is
  intentionally single-use and no longer `Clone`; retain and replay the
  original request after cancellation, or pass a returned partial to
  `RePinCoordinator::retry`. Identical steering installs and re-pin audit
  events are now required to be idempotent so ambiguous acknowledgements
  converge without duplicate side effects.
- **BREAKING — `opc-ipsec-lb`:** session-store ownership records must use the
  exact resolver key, `AuthoritativeSession` class and `ipsec-lb-ownership`
  state/key types, a non-zero fence, no expiry, a valid `OwnerId`, and a
  plaintext payload. Birth/pre-transition records use an empty payload;
  promoted records carry the SDK's versioned transition ID and request
  fingerprint metadata. Existing TTL-bearing records and records with any
  other payload shape must be migrated before adopting the stricter
  source/fencer boundary.
- `opc-proto-pfcp` changed Cargo publication eligibility to `publish = true`.
  Publication eligibility is not a production-maturity graduation; its
  `Production Profile v1` name remains a compatibility identifier for a
  conditional codec candidate.

### Security
- **RFC 006 signed-evidence binding — `opc-evidence`:** manifest and complete
  bundle signatures now use distinct versioned domain separators and
  deterministic signing bytes whose field and map ordering cannot change under
  Cargo feature unification. Bundle signing binds the configured signer
  identity; release verification requires an authenticated verifier identity
  matching the manifest. Unsafe, duplicate, or ambiguous manifest paths and
  malformed SHA-256 digests fail closed with redacted errors. `GateEvaluator`
  now requires a verified signed bundle whenever release evaluation receives a
  conformance, SBOM, VEX, provenance, performance, or governance artifact and
  rejects it unless the separately supplied bytes exactly match that bundle,
  preventing an unsigned substitution from driving a release decision. The
  signed manifest also binds the canonical record, gap, and waiver inputs used
  by the gate; signed conformance-report records must match those inputs, and
  provenance, manifest, and configured commit identities must agree without
  echoing mismatched values. Pre-change signatures are deliberately rejected
  and must be regenerated after upgrade; no legacy-signature fallback is
  provided. External HSM/Sigstore/Cosign custody and end-to-end release-workflow
  wiring remain open under #143; no production qualification claim is made.
- `opc-session-store`: add the bounded, read-only
  `opc-session-store-audit identity-invariants` pre-upgrade command for existing
  SQLite stores. It requires explicit non-zero row, per-entry JSON-byte, and
  total JSON-byte budgets; the per-entry budget cannot exceed the total or
  SQLite's signed `i64` length range. It scans a single drained snapshot in fixed 256-row
  pages; and emits versioned count-only JSON for relational owner/key-type and
  full nested replication-entry violations. `compliant` exits 0,
  `violations_found` exits 1, and `incomplete` or command/setup failure exits 2.
  Reports and errors never echo database paths, row identities, owner/key
  values, or replication JSON. The audit does not truncate, rename, rewrite, or
  repair state. Violations require audited migration/store replacement and a
  new audit; an incomplete result blocks upgrade but budget exhaustion may be
  resolved by increasing the explicit budgets and re-running the audit.
- `opc-session-store`: newly packed handover envelopes carry an exact `OPCH`
  magic/version header. The bounded non-`OPCH` classifier accepts current-valid
  original syntax and some bare payloads; ambiguous, malformed, zero-length,
  truncated, oversized JSON-looking, unknown, or typed-invalid claims return a
  fieldless error before mutation. `HandoverEnvelopeFormat` makes the syntactic
  result explicit without claiming provenance. Identity audit compliance does
  not certify live or replayable payload copies; use the documented complete
  handover preflight and one-way migration/rollback barrier.
- `opc-session-store`: `EncryptingSessionBackend` and
  `RemoteSealingSessionBackend` now use bounded iterative traversal to protect
  every nested replicated CAS before replicate/rebuild delegation and to
  unprotect every nested CAS before log/watch exposure. Outbound entry/prefix
  preflight occurs before provider/backend work; returned page/item preflight
  occurs after the backend read but before transformation or caller exposure.
  Both enforce depth 16 and 256 total operation nodes.
  Provider calls are sequential and transformations are staged: a late provider
  error may follow earlier provider calls, but causes no backend delegation on
  writes and no partial entry/page exposure on reads. This closes #147's
  traversal/confidentiality gap only; it does not establish consensus, wire
  stabilization, or production HA.
- `opc-session-store`/`opc-session-net`: existing replication logs are not
  automatically scrubbed. Before the coordinated #147 upgrade, audit both tree
  shape and nested payload encoding offline without logging payloads. An entry
  within the new limits may be rewritten/rebuilt through the configured
  protection wrapper. An over-depth/over-count historical entry fails closed
  before transformation and is never clamped or split; it requires an audited
  semantic-preserving offline migration or store replacement before the new SDK
  reads it. Raw inner-backend rebuild does not add protection. #143 remains
  mandatory and separately requires seamless SVID rotation,
  payload-protection key rotation, and trust-bundle rotation evidence.
- `opc-session-net`: bind every production connection's live certificate
  SPIFFE URI to the claimed stable `ReplicaId`, expected opposite replica,
  cluster, and complete-manifest configuration ID before backend dispatch; the
  client verifies its fresh challenge is echoed by the server. DNS/FQDN/IP
  aliases and resolver overrides remain routing
  only. Wrong, ambiguous, malformed, cross-cluster, and stale-configuration
  identities fail closed, while raw Rustls configs can no longer enter the
  production session client/server constructors. Session caches, tickets,
  resumption, early data, and 0-RTT are disabled so reconnects revalidate live
  SVIDs instead of cached certificates. This closes #125 identity
  binding only; it does not provide consensus, durable commit authority, or
  fork recovery. It also does not yet qualify seamless certificate/trust-bundle
  rotation without service interruption; long-lived connection retirement,
  trust overlap/revocation, reconnect storms, and maximum authentication age
  remain distributed production evidence in #143. Session TTL is unrelated to
  certificate or trust lifetime.
- `opc-ipsec-lb`: require an RFC 6311-style outbound IV forward-jump for both
  persisted and live-mirrored same-SPI failover state, with protocol-matched
  64-bit counter evidence, explicit ESP peer receive-lag bounds, checked
  RFC 4303 ESN reconstruction arithmetic, non-zero resumed SA identifiers,
  exact restored-counter validation, and SA-to-steering-key binding before
  ownership is mutated.
- `opc-sbi`: bind the validated JWT-SVID to the mTLS peer identity. The
  validator now rejects a token whose subject does not match the transport
  peer (`TokenBindingMismatch`) and, in production, a request that carries no
  peer identity (`MissingPeerBinding`). Previously the authorized identity was
  derived solely from the token's `sub`, so a valid token obtained by another
  workload could be replayed over its own mTLS channel and accepted as the
  token's subject (confused-deputy / token replay).
- `opc-sbi`: enforce the OAuth2 scope against the requested service. A token is
  now denied when it lacks the scope for the SBI service it invokes, so a token
  granted only `nnrf-disc` can no longer call `nnrf-nfm`.
- `opc-tls`: document that an unconstrained `PeerPolicy` authorizes any trusted
  peer (authentication without authorization) and add `is_unconstrained` so
  configuration layers can fail closed.
- `opc-evidence`: bind embedded bundle blobs (SBOM, VEX, conformance report,
  provenance, ...) to the bundle signature; they could previously be swapped
  without invalidating it.
- `opc-node-resources`: run the structural BPF checks (program type, attach
  point, capability bound) in every environment, gating only the strict
  signing/digest provenance on Production.
- `opc-privacy`/`opc-data-governance`: enforce an absolute singleton-cohort
  floor even when k-anonymity enforcement is disabled, and block the
  destructive `Anonymize` disposal action under a legal hold.
- `opc-session-net`: bound server-side frame reads with a configurable idle
  timeout so a stalled peer is reaped instead of exhausting connection slots
  (slowloris).
- `opc-gnmi-server`: Subscribe rejects SAMPLE `sample_interval` and
  `heartbeat_interval` below `MgmtLimits::min_sample_interval`; previously any
  nonzero interval was accepted, so a single 1 ns subscription drove the whole
  stream's tick (authenticated-client CPU DoS).

### Fixed
- **Identity-bound GTP-U/XFRM steering evidence — `opc-gtpu-dataplane`:** the
  privileged Linux qualification now exercises the deployed per-bearer profile
  end to end: ESP-in-UDP/4500 decrypt on one of multiple shared-reqid inbound
  SAs must carry its full-width output mark through forwarding and select the
  dedicated uplink TEID, while a dedicated G-PDU must stamp its mark before
  XFRM OUT and select the dedicated SPI instead of the otherwise-identical
  default SA. A new redaction-safe `datapath_snapshot` API succeeds only after
  proving both exact live tc program IDs and every exact named bpffs map pin,
  reads the held counter map directly, aggregates all per-CPU values, and
  repeats the identity proof. This removes ambiguous same-name `bpftool` map
  evidence without changing forwarding behavior, packet bytes, counter slots,
  or the pinned-map schema.
- **GTP-U removal recovery — `opc-gtpu-dataplane`:** default and marked bearer
  forwarding-resource removal now treats Aya's Linux `ENOENT` delete result as
  idempotent absence, matching its lookup semantics. This prevents an optional
  absent DSCP entry from stranding either a default-bearer PDR or a `Removing`
  owner after its FAR was deleted. A marked-bearer
  install that encounters a valid persisted tombstone finishes the
  already-committed FAR/DSCP/PDR/owner deletion instead of reporting
  `AlreadyExists` for non-forwarding state. The recovery call returns the new
  typed `GtpuError::RetryRequired` and never republishes in the same call; a
  fresh retry can then install an `Active` owner and its marked uplink FAR.
  Endpoint, DSCP, local-TEID, and selector drift cannot turn the tombstone into
  false idempotent success, while corrupt dual-schema or owner-index state
  still fails closed without mutation.
- **Cold consensus reconnects preserve first-RPC progress — `opc-session-net`:**
  DNS/TCP/mTLS/bootstrap now consumes at most two thirds of the caller's
  existing logical budget, leaving a bounded nonzero remainder for the first
  negotiated RPC without increasing any Openraft or qualification deadline.
  Cached lanes clear shared reconnect cooldown only after a complete validated
  reusable response, preventing stale sockets from restarting connection
  churn during exact-address member replacement.
- **Honest durable config outcomes — `opc-config-bus`, `opc-persist`, and
  `opc-amf-lite`:** a write that has reached the Openraft state machine can no
  longer be reported as a definite persistence failure merely because its
  acknowledgement, caller deadline, or post-publication recovery-marker clear
  was lost. Ambiguous writes return the distinct `OutcomeUnknown` code, fence
  further mutation, and retain encrypted request/idempotency replay metadata
  for authoritative readback without exposing raw keys in Raft, SQLite, logs,
  or snapshots. SQLite resolves the domain-separated replay digest with one
  unique indexed read, so reconciliation remains available regardless of
  history length. Ordinary commits, pending commit creation, explicit confirm,
  cancel, and rollback retain distinct encrypted request fingerprints so a
  semantically different same-key request cannot alias the original result.
  Commit-confirmed decisions now compare the applied head and
  append their successor in one state-machine operation, preventing competing
  leaders from committing sibling decisions. Existing `ManagedDatastore`
  implementations remain source-compatible through `append_commit` and
  `mark_confirmed`; they must implement the new fail-closed
  `append_commit_write` extension before serving config-bus writes. Config
  command and RPC payload revisions advance to 2; exact RPC decoding and
  formation compatibility make cross-revision paths in a rolling mixed-binary
  deployment fail closed before a revision-2 node admits writes, so consensus
  members require a coordinated drained stop/upgrade/start.
  Persisted revision-1 commands for the original append, confirm, and
  rollback-point intents remain readable and replayable; revision-1 commands
  cannot claim either new revision-2 intent. Their semantic request digest is
  stable, so a revision-2 retry with the same durable ID replays the exact
  revision-1 outcome. Existing forwarded-reply discriminants retain their
  prior ordering inside the revision-2 payload.
- **Projected-mTLS restart readiness — `opc-identity` and
  `opc-session-testkit`:** waiting for an initial projected SVID now also
  guarantees that the paired TLS-controller publication is ready, preventing
  an immediate restart-time controller from observing an empty feed. The
  qualification harness also starts a blocking readiness round only when its
  complete consensus-operation budget remains, preserving bounded failure
  diagnostics instead of reporting a residual child-response timeout.
- **Bounded reconnect admission — `opc-session-net`:** reconnect cooldown and
  exponential backoff now live in per-client, per-peer gates: one is shared
  across sequential calls and concurrent consensus lanes, and another is
  shared by the legacy direct/watch paths. This
  prevents logical RPC boundaries from resetting retry pressure during
  certificate soft/hard expiry. Material or explicit-reauthentication epoch
  changes supersede old waits and in-flight handshakes; only a current,
  dispatch-usable authenticated connection resets the gate. Cached consensus
  lanes retain deterministic jitter for material rotation, while explicit
  reauthentication retires them immediately for current-generation proof and
  newly established stale-epoch connections still fail before Openraft request
  bytes. A transport-observed newer epoch now publishes the fixed `superseded`
  terminal, while an attempt guard dropped before explicit classification
  publishes `abandoned`; actual I/O/deadline expiry remains `timeout`. Inbound
  handlers use the same guard, preserving honest attempt accounting through
  shutdown. Openraft authority, HKMS/encryption/AAD boundaries, and durable
  formats are unchanged. The #164 synthetic fleet recovery envelope correction
  is documented separately above.
- **Single Openraft RPC deadline authority — `opc-consensus`,
  `opc-session-store`, and `opc-session-net`:** the session Raft adapter now
  forwards Openraft's soft TTL to deadline-aware network peers and no longer
  installs a second hard timeout around the transport future. The remote mTLS
  peer applies the lesser of that soft TTL and its configured family ceiling,
  returns an explicit timeout from lane/connect/handshake/frame work, and
  conserves connection-attempt accounting before Openraft's sole outer hard
  deadline can cancel the call. In-process and compatibility peers retain their
  prior outer-hard-deadline behavior unless they explicitly implement the new
  deadline-aware method. Openraft authority, HKMS/encryption/AAD boundaries,
  and durable formats are unchanged.
- **Conditional S2b Create Session identity — `opc-proto-gtpv2c`:**
  ProcedureAware Create Session Request decode now accepts the TS 29.274
  UICC-less emergency identity shape (MEI instance 0 plus an instance-0
  Indication carrying UIMSI) when IMSI is absent. IMSI-bearing requests and all
  other required request IEs retain their existing validation, while an absent
  IMSI without both emergency identity signals still fails closed.
- `opc-proto-diameter`: RFC 6733 CER/CEA command metadata now marks
  Host-IP-Address, Supported-Vendor-Id, Auth-Application-Id,
  Inband-Security-Id, Acct-Application-Id, and
  Vendor-Specific-Application-Id as repeatable. Trusted conservative decode
  therefore accepts the multihomed CER/CEA messages emitted by the peer
  helpers, while Failed-AVP and every other singleton remain fail-closed;
  watchdog/disconnect commands and raw reject-all decode are unchanged.
- `opc-yanggen`: generated semantic validation now supports an absolute
  `leafref` on a `leaf-list` by checking each vector element against the target
  set. Generated code compiles, accepts empty and fully resolved lists, and
  reports the unresolved value and index while the scalar-leaf path remains
  unchanged.
- `opc-session-store`: `FakeSessionBackend` now stages compound replicated
  entries and whole-state rebuilds before atomically swapping live data. A late
  child/replay failure no longer leaves partial records, leases, fences,
  credential counters, pruning effects, log state, or watch events behind;
  successful compound entries preserve child order and publish exactly one
  outer log event, while rebuild preserves existing watchers without replaying
  history to them. A shared Fake/SQLite conformance suite covers the contract.
- `opc-session-net`: `ServerHandle::abort_and_wait` now provides a deterministic
  listener-and-connection teardown barrier, and connection tasks are registered
  without a spawn-before-tracking cancellation window. Quorum capability tests
  no longer race abrupt asynchronous teardown; they preserve cached descriptive
  operations only after clean transport loss, mask fresh-negotiation features,
  clear the entire cache after authentication, version, or malformed-handshake
  rejection, and continue to require fresh quorum evidence for every real
  operation.
- `opc-session-store`/`opc-session-net`/`opc-session-cache`/
  `opc-session-testkit`: all public `Duration` inputs used for session refresh
  and lease TTLs now use `MAX_SESSION_TTL` (exactly 365 days) and exact checked
  deadline arithmetic.
  Zero remains valid as immediate expiry and the exact maximum is accepted;
  larger values return redaction-safe `StoreError::InvalidSessionTtl` or
  `LeaseError::InvalidSessionTtl` before direct, batch, nested replication,
  wrapper, cache, quorum, Fake/SQLite, database, log, watch, or
  cryptographic-provider effects. Clients reject before resolution/dialing;
  authenticated servers reject after receiving the request but before backend
  dispatch and can keep the connection usable. This closes #137's
  panic/input-safety boundary only, not the durable consensus or production-HA
  work in #127/#143.
  Before upgrading persisted state, audit legacy replication logs for
  TTL-bearing entries above 365 days: they now fail closed during
  replay/rebuild and are not silently clamped or rewritten. Cross-field
  replication validation admits at most one microsecond of positive deadline
  drift solely for legacy `seconds_f64` rounding; new deadlines remain exact,
  the TTL maximum is unchanged, and larger mismatches fail closed.
  Caller-authored absolute record expiry is now separately bounded under #148
  as described in the breaking entry above; iterative protection of CAS
  payloads below multiple replicated-batch levels is closed in the security
  entry above under #147.
- `opc-session-store`/`opc-session-net`/`opc-session-cache`: replication-log
  entries now reject sequence zero with the typed, redaction-safe
  `StoreError::InvalidReplicationSequence` before quorum assessment, state
  mutation, cryptographic provider work, database access, cache invalidation,
  or network I/O. Rebuild sequence prefixes are fully validated before
  replacement; sequence increments are checked; SQLite rejects signed-range
  overflow, invalid positions when read, and row/payload disagreement; and
  authenticated servers return the typed wire error without dropping the
  connection. Direct,
  wrapper, cache, SQLite-corruption, quorum, and real-mTLS regressions cover
  zero, one, exact and forged duplicates, gaps, and `u64::MAX`. This closes the
  malformed-sequence boundary tracked by #138; it does not provide the durable
  sequence/commit authority still required by #127.
- `opc-runtime`: wildcard-bound UDP listeners can now pair
  `recv_from_with_destination` with `send_to_from` so Linux/Android replies use
  the exact concrete destination address observed on receive as their source.
  The bounded packet-info send rejects invalid family, port, source-address,
  and payload selections; platforms without ancillary source selection fail
  explicitly unless a concrete bind already guarantees the requested source.
  This supplies the SDK primitive tracked by #141; each consuming CNF must
  still thread the observed destination through every reply path and prove the
  peer observes its floating VIP as the source.
- `opc-session-store`/`opc-amf-lite`: durable readiness no longer succeeds from
  a bound server or cached capabilities while real quorum operations fail.
  Probes and reads now use the same Openraft linearizable barrier, while writes
  use `client_write`; the earlier custom majority-prefix assessment is removed.
  AMF-lite now keeps traffic readiness behind a continuously supervised
  session-store gate, and low-cardinality metrics expose probe outcomes,
  configured/required counts, the committed barrier index, and bounded failure
  reasons. AMF-lite is an unpublished engine/conformance harness; this base
  probe gate is not production platform-topology authority. Production CNFs
  must use attested topology and the production readiness APIs described above.
  #127 closes durable sequencing; #128 hardens current-format
  Openraft recovery; operator-safe legacy-fork recovery (#129) and
  majority-authoritative restore (#133) remain blockers.
  Protocol-v4 wire stabilization is now
  implemented under #134; #135's
  scoped model/persistence admission is implemented above. Checked TTL and
  replication-sequence rejection are closed under #137/#138; production
  qualification remains #143.
- `opc-session-store`: quorum construction now rejects empty/undersized/even HA
  membership, missing or ambiguous self, duplicate logical IDs, canonical
  endpoints, declared TLS identities, failure domains, backing identities, and
  duplicate process-local adapter instances before I/O. The denominator is
  immutable validated membership and result accounting is keyed by `ReplicaId`,
  so one conforming SDK backend instance cannot be wrapped into multiple votes.
  Declared backing identity and authenticated peer binding remain separate
  requirements. A real
  mTLS SQLite regression proves that bare logical self is independent from FQDN
  endpoints. This closes #123 configured-topology admission only. Fresh
  durable readiness was scoped separately to #124 and is described above;
  #127–#129 and #133 remain production blockers; #134's fixed-width v4 wire
  boundary and #135's scoped identity
  admission and #137/#138 input bounds are closed above, and the full
  qualification remains #143.
- `opc-session-net`: remote backends and replication servers now carry
  validated cursor-paged restore scans, shorten multi-record pages to the
  effective client/server frame limit, and return a typed error when one
  record cannot fit. This implements the transport parity tracked by #126; it
  does not implement bounded majority-authoritative restore (#133) or session
  HA qualification (#127–#129). Fixed-width v4 admission is implemented under
  #134; #135's
  scoped model/persistence admission is implemented above.
- `opc-persist`: standalone default-feature test builds no longer depend on
  fault-injection symbols that exist only with `dangerous-test-hooks`; CI now
  compiles the default package contract before workspace all-feature unification
  can mask it.
- `opc-proto-diameter`: the SWm DEA parse now matches vendor-specific AVPs by
  (vendor-id, code) instead of routing every vendor AVP to the unknown-AVP
  rejection path, so a conformant DEA carrying mandatory 3GPP subscription
  AVPs (TS 29.273) no longer fails to parse; genuinely unknown mandatory AVPs
  remain fail-closed. The DEA additionally gains a typed, redaction-safe
  decode/encode surface for `Service-Selection` (RFC 5778) and
  `APN-Configuration` (TS 29.272 §7.3.35) with `Context-Identifier`,
  `PDN-Type`, `EPS-Subscribed-QoS-Profile`, and `AMBR` children.
- `opc-proto-gtpv2c`: S2b F-TEIDs now use the standardized ePDG/PGW data-plane
  interface type 31; the control-plane constants remain 30 and 32.
- `opc-ipsec-xfrm`: XFRM policy templates now encode all-ones algorithm
  masks (`aalgos`, `ealgos`, `calgos`) instead of zero masks, so installed
  policies can be satisfied by negotiated ESP SAs instead of dropping inbound
  packets with `XfrmInTmplMismatch`.
- `opc-yanggen`: generated Rust artifacts now use fully prefix-qualified
  schema-node paths for every segment across schema registry metadata, gNMI,
  NETCONF, NACM, and audit-facing path attribution while preserving
  unambiguous relaxed lookup compatibility.
- `opc-persist`: a committed `MarkConfirmed`/`CreateRollbackPoint` whose target
  `tx_id` is absent on a node (compacted away, or restored from an older
  snapshot) no longer aborts the consensus apply transaction. Applying a
  committed entry is now a deterministic no-op in that case instead of freezing
  `applied_index` and wedging the node's state machine.
- `opc-persist`: the durability preflight no longer reports `same_filesystem`
  and `locking_compatible` as unconditionally true; they are derived from real
  checks (device-id comparison and the network-filesystem safety check).
- `opc-proto-ngap`: reject trailing bytes after a decoded NGAP PDU instead of
  silently discarding them and re-emitting them on encode.
- `opc-alarm`: the persist audit sink runs its append on a worker thread with
  its own runtime, decoupling fail-closed audit from the caller's runtime
  flavor and lifecycle, and maps a DB-path panic to a meaningful reason.
- `sdk-reference-operator`: a failed drain during deletion now retains the
  finalizer and requeues instead of removing it unconditionally; only a
  completed or timed-out drain releases it, so sessions are not cut.
- `opc-api-nnrf`: `PlmnId` and S-NSSAI are generated with TS 29.571 object-form
  serde (`{mcc,mnc}` / `{sst,sd}`) so the types interoperate with conformant
  NRF peers. The committed generated types now match the generator output
  (`NfProfile`, `NfService`, and `SubscriptionData` PLMN/S-NSSAI fields use the
  object-form wrappers), and CI regenerates both NNRF and NGAP bindings to
  fail on any future drift.
- `opc-config-bus`: the commit-confirmed rollback deadline is armed on the
  monotonic tokio clock instead of the wall clock, so an NTP step no longer
  stretches or shortens the safety-rollback window; the durable marker still
  records wall-clock time for restart re-arm.
- `sdk-reference-operator`: bridge and drain call errors now preserve the
  underlying cause chain (`errors.As`/`errors.Is` recover the typed bridge
  error) while keeping the CLI path out of messages, and child Deployment
  owner references set `BlockOwnerDeletion` so foreground cascade deletion
  waits on the child.

## [0.2.0] — 2026-06-12

### Added
- Behaviour-pinning tests for randomness usage in `opc-crypto`, `opc-sbi`, and
  `opc-persist` ahead of the rand 0.10 migration.
- JWT-SVID validation verdict tests in `opc-sbi` covering valid tokens, expiry,
  audience/issuer mismatch, future `nbf`, missing/unknown `kid`,
  HS256/RS256 key-confusion rejection, and the dev bypass path.
- An on-disk SQLite fixture database and compatibility test in `opc-persist`
  that guard the stored format across rusqlite version changes.
- Community and governance files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `NOTICE`, and `.github/CODEOWNERS`.
- GitHub issue and pull-request templates.
- `CHANGELOG.md` tracking release changes.
- `opc-sdk` facade crate with feature-gated re-exports, a `prelude`, the
  `minimal_cnf` end-to-end example, and an integration smoke test.
- `docs/quickstart.md` — guided first build of a minimal CNF.
- `opc-key-vault` (experimental): HashiCorp Vault Transit `KeyProvider` adapter
  using the wrapped-data-key envelope pattern.
- `opc-session-net` (experimental): networked session replication transport
  (length-prefixed, version-handshaked wire protocol; mTLS via `opc-tls`;
  deadline-bounded remote backend client composing into `QuorumSessionStore`).
- `FileSvidSource` in `opc-identity`: file-based SPIFFE SVID loading with
  rotation polling and fail-closed handling, for cert-manager-mounted secrets.
- Rust↔Go contract versioning for `operator-lifecycle-cli` (`CONTRACT_VERSION`,
  `version` subcommand, `contractVersion` response envelopes) with matching
  validation and `ErrContractMismatch` in the Go reference operator bridge.
- CI hardening: MSRV (1.81) job, `cargo-deny` license/advisory gate with
  `deny.toml`, CycloneDX SBOM generation in releases, scheduled fuzz workflow,
  and a `RUSTDOCFLAGS="-D warnings"` docs gate.
- `docs/adr/0013-ngap-asn1-strategy.md` and `docs/design/openapi-codegen-plan.md`.

### Changed
- Workspace dependency `rand` 0.8 → 0.10, with direct callers migrated to the
  new API. `opc-crypto` continues to source nonce entropy from the OS via
  `getrandom::SysRng`.
- `opc-sbi` dependency `jsonwebtoken` 9.3.1 → 10.4.0, using the `aws_lc_rs`
  backend with PEM support. No source changes were required because the JWT
  validation API remained compatible; the `aws_lc_rs` backend avoids the
  `rsa` crate and the RUSTSEC-2023-0071 advisory that the `rust_crypto`
  backend would pull in, keeping `cargo audit`/`cargo deny` clean without a
  standing exception. The cost is the `aws-lc-sys`/`cmake` build dependency,
  reconciled in ADR 0014 point 9; a future migration to `rust_crypto` is
  planned once `rsa` ships a constant-time release.
- crates.io publishing metadata (description, keywords, categories,
  documentation, readme) and per-crate READMEs for all publishable crates;
  intra-workspace path dependencies now carry `version` keys.
- Workspace publish tiering: six experimental crates (`opc-session-net`,
  `opc-key-vault`, `opc-proto-pfcp`, `opc-proto-nas`, `opc-proto-ngap`,
  `opc-api-nnrf`) are now marked `publish = false` and documented in
  `CONTRIBUTING.md` with per-crate graduation requirements.
- README claims corrected: the SDK is 5G-centric (GTP-U is the only EPC-shared
  component) and in-process quorum semantics are distinguished from the
  experimental networked replication in `opc-session-net`.
- `#![deny(missing_docs)]` adopted in `opc-types`, `opc-protocol`, and
  `opc-proto-gtpu`.
- `operator-sdk-go` Go module: `conditions`, `bridge`, `drain`, `workload`,
  `opmetrics`, and `testing` packages for CNF operator construction.
- Reference operator finalizer + drain orchestration (`lifecycle.openpacketcore.io/drain`)
  with 5-minute timeout and graceful shutdown via `opc-runtime` admin endpoint.
- `workload.RenderDeployment` with deterministic, golden-file-tested manifest
  synthesis for control-plane, AF_XDP fast path, and SR-IOV fast path profiles.
- RFC 009 §17 Prometheus metrics (`opc_operator_reconcile_total`,
  `opc_operator_reconcile_duration_seconds`, `opc_operator_drain_total`, etc.)
  registered on controller-runtime's registry; event-recorder wiring for phase
  transitions, drain outcomes, and contract skew.
- Helm chart `operators/helm/sdk-reference-operator/` (v0.1.0) with cert-manager
  and manual certificate modes, ServiceMonitor toggle, and workload-synthesis
  opt-in flag.
- `docs/building-a-cnf-operator.md` — downstream-team operator guide (313 lines).
- `opc-proto-pfcp` (experimental v0): PFCP header + IE TLV layer with raw
  preservation; Heartbeat Request/Response; fuzz target + seed corpus.
- mdbook docs site (`book.toml`, `docs/SUMMARY.md`, `docs/introduction.md`) with
  GitHub Pages deployment workflow.
- `opc-proto-nas` (experimental v0): NAS-5GS plain 5GMM/5GSM headers,
  security-protected envelope recognition (no crypto), 5GS mobile identity
  decoding (SUCI/5G-GUTI structured views), and message-type registries,
  with spec-byte fixtures, fuzz target, and CONFORMANCE scope.
- `scripts/publish-order.py`: topological crates.io publish order with a
  `--check` CI gate (graph acyclic, version keys, no publishable→internal
  dependencies); CONTRIBUTING gains a Releasing section.
- Rustdoc for the entire public API of `opc-runtime`, `opc-sbi`,
  `opc-config-bus`, `opc-session-store`, and `opc-alarm`, now enforced with
  `#![deny(missing_docs)]` across all eight core crates.
- `examples/smf-reference/`: first standalone, outside-the-workspace
  reference consumer of the SDK — a deliberately bounded reference SMF
  proving runtime startup, NRF registration/heartbeat/deregistration via
  `opc-sbi`, real PFCP/N4 bytes over UDP via `opc-proto-pfcp`, and session
  state in `opc-session-store`. Includes a fake UPF end-to-end test over
  loopback UDP and its own CI job.
- `opc-proto-pfcp` typed IE layer: decode/encode for Cause, Node ID, F-SEID,
  F-TEID, PDR/FAR/QER/URR ID, Precedence, Apply Action, Source/Destination
  Interface, Network Instance, UE IP Address, Outer Header Creation/Removal,
  Recovery Time Stamp, QFI, Gate Status, MBR, and GBR; grouped-IE recursion
  (Create/Created PDR, PDI, Create FAR, Forwarding Parameters, Create QER,
  Update QER, Create URR) with configurable `max_depth` enforcement; unknown
  and vendor IEs preserved byte-exact via `TypedIe::Raw`. Conformance tests
  with hand-authored spec-byte fixtures citing TS 29.244 section numbers;
  negative tests for truncation, wrong length, and depth exceedance. Fuzz
  target extended with typed-IE decode loop.
- Diagnosed a `rasn` 0.28 APER encoder alignment bug that prevents
  `opc-proto-ngap` from re-encoding typed NGSetupRequest values; a
  self-contained repro has been prepared for an upstream issue. The
  affected re-encode path is documented in the crate's CONFORMANCE notes.
- `opc-api-nnrf` (experimental): generated Rust types for 3GPP TS 29.510
  `NfProfile` and `NfService` from official OpenAPI YAML. Python generator
  `scripts/generate-api-nnrf.py` resolves `$refs`, maps primitives to Rust,
  and emits serde-friendly structs with extensible string enums
  (`NfType`, `NfStatus`, `NfServiceStatus`). `make generate-api` target
  produces deterministic output.
- `operator-sdk-go/rollout`: RFC 009 §12 rollout strategy policy evaluation.
  `AllowedStrategies` and `Evaluate` decide safe strategies from NF
  characteristics; `BuildDeploymentStrategy` synthesises Kubernetes
  `DeploymentStrategy` for rolling, partitioned, canary, blue-green, and
  manual strategies. Integrated into `workload.RenderDeployment`. Envtest
  coverage verifies strategy fields are persisted correctly on a real
  API server.
- `opc-proto-ngap` (experimental v0): NGAP (3GPP TS 38.413) codec built on
  `rasn` per ADR 0013 Option A. NGAP-PDU framing for all three outcome
  classes with outcome-aware dispatch, typed APER decoding of
  NGSetupRequest (field-level external `asn1c`/libngap fixture) and
  InitialUEMessage, and raw-preserving encode so decode->encode
  round-trips byte-exactly. NGSetupResponse/NGSetupFailure are surfaced
  raw until external fixtures exist for them, and typed (canonical)
  encoding is out of scope for v0 — see the crate's CONFORMANCE.md.
  Offline generator `scripts/generate-ngap.py` (Wireshark ASN.1 +
  `rasn-compiler`) and `make generate-ngap`; fuzz target `decode_ngap`
  with seed corpus and CI registration.
- `opc-sbi`: `NrfClient` now implements `NrfDeregNotifier` so consumers can
  wire a real NRF client directly into `NrfDrainHook` without a wrapper.
- `opc-session-store`: add `SessionStore<B>` facade that bundles a
  `SessionBackend` and `SessionLeaseManager` into one handle, constructible
  from any backend implementing both traits. `FakeSessionBackend` and
  `opc_session_net::RemoteSessionBackend` both slot in.
- `opc-proto-pfcp`: add `TypedIe::encode_value()` for value-only encoding and
  `InformationElement::from_typed()` to build raw IEs directly from typed IEs.
  The reference SMF response path now uses typed IEs end-to-end instead of
  hand-building raw value bytes.
- `opc-session-store`: add `OwnedSession` helper that bundles a key, lease, and
  background renewal task for single-owner records, with renewal failures
  surfaced through a `tokio::sync::watch` channel. The reference SMF ownership
  marker no longer uses a hand-rolled renewal loop.
- `opc-types`: add `from_static()` constructors for `TenantId`,
  `NetworkFunctionKind`/`NfKind`/`NfType`, and `opc_session_store::StateType`
  so deterministic literals no longer need `Result` plumbing.
- `opc-types`: add `Snssai::with_sd()` and `Snssai::without_sd()` with strict
  six-digit-hex SD validation and rustdoc examples.
- `opc-types` and `opc-sbi`: add typed constructors for standard NF kinds
  (`amf`, `smf`, `upf`, `nrf`, `ausf`, `udm`, `pcf`, `nssf`, `nef`, `smsf`)
  and a standard SBI service-name constants module so NRF profile building no
  longer relies on free strings.
- `opc-sbi`: add `NrfClient::with_default_client()` convenience constructor
  for plain-HTTP NRF clients.
- `opc-protocol`: confirm `EncodeError::code()` and `DecodeError::code()`
  accessors and re-export `EncodeErrorCode`/`DecodeErrorCode` from the crate
  root; no consumer changes required.
- `opc-api-nnrf` (experimental): expanded generated TS 29.510 types to cover
  the NRF NFManagement payloads used for registration, heartbeat, and
  subscription/notification exchanges: `SubscriptionData`, `NotificationData`,
  `NotifCondition`, `NotificationEventType`, and `ConditionEventType`.
  Added `tests/compat_sbi.rs` demonstrating that an `opc-sbi::nrf::NfProfile`
  serializes into the generated `opc_api_nnrf::NfProfile` at the serde value
  level after casing normalization.
- `opc-proto-nas` (experimental v1): IE-level decoding for 5GMM
  Registration Request (§8.2.6) and Registration Accept (§8.2.7), including
  structured mandatory fields, ngKSI, 5GS mobile identity reuse, and
  optional-IE iteration with raw preservation of unknown IEs. Added BCD
  unpacking for PLMN (MCC/MNC with 2- and 3-digit MNC), routing indicator,
  and IMEI/IMEISV with spec-byte fixtures for filler nibbles, odd digit
  counts, and MNC padding. Integration tests, extended fuzz target, and
  regenerated/added corpus seeds cover byte-exact round-trips.

### Changed
- `opc-session-net` (experimental): `RemoteSessionBackend` now keeps a single
  persistent TCP/TLS connection per backend instance (one in-flight request at
  a time) instead of opening a fresh connection per request. Lost connections
  are re-established with the existing backoff retry, still bounded by the
  per-call deadline. `ServerHandle::abort()` now also aborts in-flight
  connection handlers so tests can simulate server crashes. Added integration
  tests for transparent reconnect after restart and for surfacing a
  backend-unavailable error within deadline when a request is in flight during
  disconnect.

- ADR 0014 (dependency and toolchain policy) and ADR 0015 (protocol codec
  conformance policy); ADR 0013 amended with the outcome of the first NGAP
  codec attempt.

### Fixed
- MSRV raised from 1.81 to 1.88, the measured floor of the resolved
  dependency graph (transitive dependencies had silently drifted past the
  declared version, so the previous MSRV claim was untrue); the CI gate now
  compiles the full workspace on exactly the declared version.
- `opc-proto-pfcp` wire format corrected to TS 29.244: octet-1 flag layout
  (S = bit 1, MP = bit 2, FO = bit 3, spare = bits 5–4 — previously scrambled),
  message priority encoded/decoded in the final header octet's high nibble
  (previously dropped on encode and always zero on decode), vendor-specific IE
  Length semantics per §8.1.1 (the field counts the 2-octet Enterprise ID;
  round-trip was previously broken), and the header Length field is now
  honored with trailing bytes returned to the caller. Verified by
  hand-authored spec-byte tests, byte-exact round-trip assertions, and a
  quickcheck property; corpus seeds regenerated; `BorrowDecode`/`OwnedDecode`/
  `Encode` trait implementations added; `opc-proto-pfcp` registered in the
  fuzz CI workflow (the committed fuzz target previously failed to compile).
- Reference-operator `sdkbridge` now threads the reconcile/webhook
  `context.Context` into the CLI bridge instead of `context.Background()`,
  so cancellation propagates to the subprocess.
- gofmt violations in three Go files fixed; gofmt check gates added to both
  Go CI jobs.
- Flaky test root causes fixed: the `opc-sdk-integration` observability
  tests raced each other on the process-global metrics registry (now
  serialized with a shared test mutex; was failing ~1 in 4 runs), and the
  `opc-persist` split-brain e2e post-heal poll window was widened to a
  bound that only genuine convergence failures can trip.
- `opc-testbed` could not be published: it depends on `opc-schema-validate`,
  which was marked `publish = false`; the dependency crate is now
  publishable (caught by the new publish-order graph gate).
- The consensus e2e harness deadlocked on Linux when reaping killed cluster
  nodes: teardown awaited a child's exit on a second tokio runtime, but
  Linux child-exit notifications (SIGCHLD) dispatch through the runtime
  that spawned the child, which was parked at that moment. Teardown now
  reaps synchronously with bounded `try_wait` polling; macOS was unaffected
  (kqueue process events) which is why the suites only hung in CI.

## [0.1.0] — 2026-06-09

### Added
- Initial public release of the OpenPacketCore SDK.
- Rust workspace with runtime chassis, protocol framework, config bus, session store, security substrate, alarm substrate, and testbed.
- Go reference operator demonstrating lifecycle management.

[Unreleased]: https://github.com/openpacketcore/openpacketcore-sdk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/openpacketcore/openpacketcore-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openpacketcore/openpacketcore-sdk/releases/tag/v0.1.0
