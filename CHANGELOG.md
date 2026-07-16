# Changelog

All notable changes to the OpenPacketCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
  procedure-aware Create Bearer (95/96) and Delete Bearer (99/100) support now
  validates mandatory nested IEs, canonical shared TFT values, S2b-U F-TEID
  roles, mutually exclusive delete forms, partial results, and exact
  request/response bearer correlation. A bounded transport-neutral triggered
  transaction registry prevents duplicate application dispatch and replays
  exact committed response bytes across retransmissions.
- **3GPP dedicated-bearer IKEv2 primitives — `opc-proto-ikev2`:** typed TS
  24.302 R17 multiple-bearer QoS, TFT, modified-bearer, AMBR, and private-error
  Notify codecs now compose with strict opened-payload builders/views for new
  non-rekey `CREATE_CHILD_SA`, bearer-modification `INFORMATIONAL`, and
  Child-SA deletion exchanges. The boundary enforces payload cardinality,
  ESP SPI and KE/proposal relationships, response proposal/transform and
  traffic-selector correlation, canonical shared TS 24.008 TFT bytes, and
  exact error/success separation while leaving admission, SPI allocation,
  retransmission timers, cryptographic sealing, and dataplane installation to
  the product.
- `opc-sctp`: an explicit, default-off `DiameterInboundPpidPolicy` escape hatch
  can accept inbound PPID 0 from a configured legacy clear-text Diameter peer.
  Standard PPID 46 remains accepted and is always used outbound; DTLS remains
  strict. The policy survives single-address and static-multihoming Diameter
  construction, while association metrics count accepted legacy messages and
  a redaction-safe warning is emitted at most once per association.
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
  now build notify-only `NO_PROPOSAL_CHOSEN` and `INVALID_KE_PAYLOAD` responses
  with a zero responder SPI, canonical response flags, and Message ID zero.
  The generic entry point accepts exactly one allowlisted IKE-SA-shaped error;
  the invalid-KE convenience builder encodes the accepted non-zero
  Diffie-Hellman group as exactly two big-endian octets. Cleartext
  `INVALID_SYNTAX`, non-zero Protocol IDs, SPI bytes, ambiguous lists, and
  malformed data fail closed. Source validation, response rate limiting,
  retransmission behavior, and other unauthenticated anti-amplification policy
  remain product responsibilities.
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
  the connection conservation equation remains mandatory. Schedule v5 binds
  this as `new-attempts-plus-baseline-outstanding/v1`. Cancellation-classified
  `abandoned` outcomes, protocol/backend outcomes, and drain overruns remain
  forbidden throughout the fault and clean intervals. Schedule v5 advances the
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
  `same-disk-exact-address-active-mutator/v2` profile checks six sequential
  stages independently: termination and process reaping within 5 seconds,
  outage/survivor progress within 26 seconds, replacement-child startup within
  45 seconds, Openraft readiness/catch-up within 26 seconds, reconciliation of
  at most 262,144 exact journal entries within 25 seconds, and mutation resume
  under a strictly higher same-owner fence within 26 seconds. The composed
  crash-to-resume ceiling is 153 seconds, but no stage may borrow unused time
  from another stage or substitute that total for its own bound. Schedule v5
  binds the scenario, count, six bounds, and total, so v1 evidence cannot
  satisfy the new assertions. This corrects the under-composed v1
  qualification deadline, which incorrectly charged termination, outage work,
  startup, Raft catch-up, journal reconciliation, and higher-fence resume to
  one 26-second clock. A stage that finishes after its fixed deadline fails
  with a closed terminal-stage plus elapsed-millisecond diagnostic rather than
  preserving an earlier ambiguous error that hides where the overrun occurred;
  Schedule v5 binds this as `terminal-stage-elapsed-millis/v1`. A child that
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
  `SessionStorePlatformProfile::Quorum` remain admission evidence only.
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
  local-self selection. Production topology is descriptor-only: the one local
  SQLite backend and consensus-only remote peer map are supplied separately,
  so remote votes require no dummy backend or legacy remote-backend client. An
  explicit lab singleton reports `single-replica`, never quorum HA.
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
  raw-vector coordinator surfaces are removed. Migrate HA callers through a
  descriptor-only `QuorumTopologyConfig`/`ValidatedQuorumTopology`; migrate
  one-replica tests and labs through `try_new_consensus_lab_singleton`. Supply
  exactly one local SQLite backend and the remote consensus-peer map when
  opening each node.
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
  reasons. #127 closes durable sequencing; #128 hardens current-format
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
