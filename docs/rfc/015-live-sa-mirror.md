# OPC-SDK-RFC-015: Live SA Keymat Mirror

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-07-10  
**Audience**: HA/failover engineers, IPsec NF implementers (ePDG/N3IWF), security reviewers

## 1. Abstract

This RFC defines `opc-sa-mirror`, the SDK primitive for near-hitless IPsec SA
failover in which **SA key material never persists**. An SA owner mirrors
freshly derived keymat to a designated standby over an authenticated mTLS
channel; the standby holds it exclusively in zeroizing memory; on owner loss
the standby yields the keymat together with validated
`opc_ipsec_lb::SameSpiResume` evidence (`ResumeKeySource::LiveMirrored`) so the
existing fenced re-pin (`RePinCoordinator`) can move the SA without a rekey or
UE re-attach, and without any key ever touching a store.

This is the producer + transport + standby-custody half of the "live mirror"
continuity tier whose consumer half already exists in `opc-ipsec-lb`
(`ResumeKeySource::LiveMirrored` is accepted by the re-pin coordinator, and the
mandatory outbound-IV forward-jump applies to mirrored counters exactly as to
persisted ones).

## 2. Motivation

The sealed-SA HA path (session store + `EncryptedSessionPayload` + KeyProvider
sealing) persists live IPsec session keys, sealed, at rest. Its
confidentiality reduces entirely to KEK custody, and a strict at-rest review
(NIST SP 800-53 SC-28, SP 800-57 key-retention guidance) flags any operational
session key written to disk regardless of the envelope. The alternative HA
shape ("stateless control / dataplane split") removes the finding by
construction: session metadata persists freely, keys replicate only live,
memory-to-memory, to a hot standby.

The SDK had no primitive for that key plane. `opc-session-net` is
store-replication: its server takes an `Arc<dyn SessionStoreBackend>` and
**persists** everything it receives — the wrong plane by definition.
`opc-ipsec-lb` is contractually key-material-free (its crate docs and
conformance tests forbid key handling). Hence a sibling crate.

## 3. Scope

### 3.1 In Scope

- The custody invariant and plane boundary (§4).
- The SA keymat lifecycle under live mirroring (§5).
- Port/trait surface: producer, standby sink, standby takeover source (§6).
- The live-keymat mTLS transport and wire framing (§7).
- Composition with the existing fenced re-pin, forward-jump, and anti-replay
  evidence (§8).
- Memory-custody controls and their division between SDK and deployment (§9).
- Conformance tests (§10).

### 3.2 Out of Scope

- Kernel/XFRM installation of the yielded keymat (CNF adapter, e.g. via
  `opc-ipsec-xfrm`).
- Standby placement/assignment policy (which node stands by for which SA is
  CNF/operator policy; per ADR 0018 the SDK ships the mechanism only).
- Metadata continuity (S2b/GTP context restore is the session store's job; it
  carries no keys and is unchanged).
- Multi-standby quorum for keymat. One designated standby per producer client;
  a CNF wanting N standbys composes N producer clients.
- Rekey-on-failover and re-attach fallbacks (already possible without this
  crate; they are the degraded tiers when no mirror exists).

## 4. The custody invariant

> **The plane that persists never holds keys; the plane that holds keys never
> persists.**

Enforcement in this crate is structural, not procedural:

1. `opc-sa-mirror` has **no dependency** on `opc-session-store`, `opc-persist`,
   or any storage crate. There is no code path from a mirror frame to a store.
2. The keymat type (`MirroredSaKeymat`) does **not** implement
   `serde::Serialize`/`Deserialize`. It cannot be handed to any generic
   persistence or logging layer that serializes its inputs. (A `compile_fail`
   doctest pins this.)
3. Key bytes live only in `zeroize::Zeroizing` buffers — in the producer's
   hand-off struct, in the transport's frame buffers, and in the standby
   holder — and are wiped on drop at every stage.
4. `Debug` output redacts key material everywhere (same discipline as
   `opc-key::KeyHandle`).
5. The transport server's sink port is `SaMirrorSink`, whose only shipped
   implementation is the in-memory holder. It is deliberately **not** the
   session-store backend trait, so the mesh cannot be "accidentally" pointed
   at a persisting backend.

## 5. Keymat lifecycle

```
IKE_AUTH / CREATE_CHILD_SA (owner)
        │  fresh KEYMAT (RFC 7296 §2.17) exists in process memory
        ▼
SaMirrorProducer::mirror_install ──mTLS──► SaMirrorSink (standby, memory only)
        │                                        │
        ▼                                        │ periodic
kernel install (owner XFRM)                      │ SaMirrorProducer::mirror_checkpoint
        │                                        ▼
   ...traffic...                        counters merged (monotonic)
        │
        ├── rekey  → mirror_install with a higher KeyEpoch (supersedes)
        ├── delete → mirror_withdraw (standby wipes)
        ▼
   OWNER LOSS
        ▼
StandbyKeymatSource::take_for_repin
        │  yields MirroredSaKeymat + validated SameSpiResume{LiveMirrored}
        ▼
RePinCoordinator::repin (fence → audit → steer)   [unchanged, authoritative]
        ▼
kernel install on standby, keymat buffer dropped ⇒ zeroized
```

### 5.1 Where the producer obtains keymat — normative

The producer mirrors the **freshly derived keymat at SA install/rekey time**,
i.e. the bytes the CNF's IKE layer just computed from the RFC 7296 §2.17 PRF+
expansion, captured **before** the only remaining copy is inside the kernel.

Kernel read-back (e.g. dumping XFRM SA state) is explicitly rejected as a
source:

- it is not portable across dataplane backends (XFRM, DPU, SR-IOV offload);
- it widens the attack surface by requiring and normalizing a "read keys out
  of the kernel" capability;
- it races with live traffic and rekeys, producing ambiguous provenance.

The mirrored counter values, by contrast, are *checkpoints* (stale lower
bounds by design) and MAY come from periodic dataplane queries; §8 explains why
staleness is safe for counters and catastrophic for it to be ignored.

### 5.2 Ack semantics

`mirror_install` returning `Ok(())` means the standby has accepted custody in
memory. Only after that ack may the CNF claim tier-1 (live-mirror) protection
for the SA. A CNF MUST NOT block SA establishment on mirror success — mirror
failure degrades the SA to the rekey/re-attach tiers, it does not fail the
attach. That policy trade-off (and any retry cadence) belongs to the CNF.

### 5.3 Epochs

`KeyEpoch` is a non-zero, per-SA monotonically increasing generation counter
assigned by the producer (bumped at every rekey). The standby:

- rejects installs whose epoch is lower than the held one (`stale_epoch`) —
  a replayed or reordered frame can never roll custody back to old keys;
- accepts an equal-epoch reinstall only if the key bytes are identical
  (constant-time comparison) — this makes producer retries after ambiguous
  transport outcomes idempotent while rejecting equivocation (`mirror_conflict`);
- replaces held keymat on a higher epoch, zeroizing the previous generation;
- treats `mirror_withdraw(sa, epoch)` as "wipe if held epoch ≤ epoch", so a
  stale withdraw cannot destroy a newer generation, and withdrawing an absent
  SA is idempotent `Ok`.

## 6. Ports

All ports live in `opc-sa-mirror` and follow the SDK's port-first convention:
the CNF wires adapters at its composition root; nothing here is ePDG-specific.

### 6.1 `SaMirrorProducer` (owner-side, outbound)

```rust
#[async_trait]
pub trait SaMirrorProducer: Send + Sync + fmt::Debug {
    async fn mirror_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError>;
    async fn mirror_checkpoint(&self, checkpoint: SaCounterCheckpoint) -> Result<(), SaMirrorError>;
    async fn mirror_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError>;
}
```

Shipped adapters: `RemoteMirrorProducer` (mTLS client, §7) and
`InProcessMirrorProducer` (test fake wiring a sink directly, no network).

A `mirror_checkpoint` answered with `SaMirrorError::NotFound` signals that the
standby does not hold the SA (e.g. the standby restarted and lost its memory —
which is correct and expected: the standby's key custody is deliberately as
ephemeral as the owner's). The producer re-establishes tier-1 coverage by
re-sending `mirror_install` with the current epoch.

### 6.2 `SaMirrorSink` (standby-side, inbound; called by the transport server)

```rust
#[async_trait]
pub trait SaMirrorSink: Send + Sync + fmt::Debug {
    async fn accept_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError>;
    async fn accept_checkpoint(&self, checkpoint: SaCounterCheckpoint) -> Result<(), SaMirrorError>;
    async fn accept_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError>;
}
```

### 6.3 `StandbyKeymatSource` (standby-side, takeover)

```rust
pub trait StandbyKeymatSource: Send + Sync + fmt::Debug {
    fn take_for_repin(
        &self,
        sa: SaId,
        params: RepinTakeoverParams,
    ) -> Result<LiveMirroredTakeover, SaMirrorError>;
    fn held_epoch(&self, sa: SaId) -> Option<KeyEpoch>;
}
```

The methods are synchronous by contract: a conforming holder keeps keymat in
local process memory, so yielding it must not perform I/O. A "remote holder"
would break the tier-1 model (the node that takes over must already have the
keys) and is deliberately unrepresentable.

`take_for_repin` is **take** semantics: on success the entry is removed, so a
second local taker gets `NotFound`. The caller owns the yielded buffer until it
drops it (zeroize-on-drop); a failed re-pin does not lose the keymat — the
caller may retry the re-pin with the takeover it already holds, or drop it and
fall back to re-attach. Validation failures (§8) leave the entry in custody.

`InMemoryStandbyHolder` implements both §6.2 and §6.3.

### 6.4 Keymat is opaque

`MirroredSaKeymat` is `(KeymatFormat, Zeroizing<Vec<u8>>)`. The SDK never
interprets the bytes: the CNF defines its own encoding of enc/integrity keys,
salts, and algorithm parameters (it must already have one to install SAs), and
tags it with a CNF-owned `KeymatFormat` discriminant so a standby can reject a
format it cannot install. This keeps every cipher-suite and dataplane detail
out of the SDK and keeps the SDK from ever needing to parse secrets.

## 7. Transport

### 7.1 Security

- mTLS only, via `opc-tls` (`rustls`, SPIFFE SVID verifiers, `PeerPolicy`).
  The composition root builds `ClientConfig`/`ServerConfig` with
  `TlsConfigBuilder`, which pins peer trust domains/tenants/NF kinds.
- **No plaintext mode exists — not even behind a test feature.** This is
  stricter than `opc-session-net` (`insecure-test`) because these frames carry
  live traffic keys. Tests exercise the codec and dispatch over in-memory
  duplex streams and full mTLS over loopback.
- Forward secrecy comes from the TLS key exchange (TLS 1.3 by default in the
  rustls config); a recorded mirror stream is not decryptable with the SVID
  private keys alone.

### 7.2 Framing

`opc-session-net`'s frame helpers are generic, but they (a) live in a crate
that hard-depends on `opc-session-store` and (b) serialize the whole message
through non-zeroizing JSON buffers. Both disqualify them for keymat, so this
crate ships a sibling codec with the same length-prefixed style:

```
u32 BE header_len | header JSON | u32 BE secret_len | secret bytes
```

- The JSON header (`Hello`, `Install`, `Checkpoint`, `Withdraw`, and the
  responses) contains **no secrets** — SA identity, epoch, format, counters.
- Key bytes ride only in the raw tail, read directly into a
  `Zeroizing<Vec<u8>>`; encode paths assemble frames in `Zeroizing` buffers.
- Only `Install` may carry a non-empty tail; every other frame (and every
  response) must have `secret_len == 0` or the peer fails the connection.
- Frames are bounded (64 KiB default) and reads are deadline-bounded
  (anti-slowloris, same rationale as `opc-session-net`).
- A `Hello { contract_version, node_id }` handshake precedes traffic;
  version mismatch fails closed.
- Server rejections carry a **static, redaction-safe code string** only; the
  client maps known codes back to typed `SaMirrorError` variants and collapses
  unknown codes to a protocol error (no untrusted free text in errors/logs).

### 7.3 Endpoints

- `RemoteMirrorProducer::new(addr, Arc<ClientConfig>, deadline)` /
  `new_with_resolver(server_name, resolver, ...)` — single connection, one
  in-flight request, connection taken out of its slot for the duration of an
  exchange so cancellation drops it rather than delivering a stale response
  (the `opc-session-net` client's cancellation discipline). Transient I/O
  errors retry with backoff inside the per-call deadline; §5.3's idempotency
  rules are what make those retries safe.
- `SaMirrorReceiver::new(Arc<dyn SaMirrorSink>, Arc<ServerConfig>)` with
  `with_max_connections`, `with_max_frame_size`, `with_idle_timeout`, and
  `listen(bind_addr)` returning a handle + bound address (mirrors the
  `SessionReplicationServer` lifecycle).

## 8. Composition with the fenced re-pin

`take_for_repin` builds and **pre-validates** the resume evidence:

```rust
pub struct RepinTakeoverParams {
    /// Deployment-attested outbound-IV forward jump (floor-enforced).
    pub forward_jump: SendIvForwardJump,
    /// Deployment-attested bound on replayed-window reopening.
    pub max_reopened_packets: u64,
}

pub struct LiveMirroredTakeover {
    pub keymat: MirroredSaKeymat,
    pub epoch: KeyEpoch,
    pub resume: SameSpiResume, // key_source == ResumeKeySource::LiveMirrored
}
```

- `checkpointed_send_iv_next` is the holder's merged (monotonic-max) counter
  checkpoint; `restored_send_iv_next` is computed as
  `checkpoint + forward_jump` — never chosen by the caller — and the whole
  `SameSpiResume` is passed through `validate_for_repin` before the entry is
  removed. A mirrored counter is a **stale lower bound** (the owner kept
  sending after the last checkpoint), so the mandatory forward-jump floor
  (`MIN_SEND_IV_FORWARD_JUMP`) and the ESP ESN reconstruction ceiling apply to
  live-mirrored resumes exactly as to persisted ones; nonce reuse on AES-GCM
  would be catastrophic (RFC 5282).
- Anti-replay evidence is always `AntiReplayResume::BoundedReopening` with the
  holder's watermark as both checkpoint and restored value. Live mirroring is
  asynchronous, so bitmap continuity can never be honestly claimed;
  `ExactWindowRestore` is unrepresentable through this path, and the caller
  must attest a non-zero `max_reopened_packets` bound.
- Checkpoint merging in the holder is monotonic per field within an epoch:
  a replayed or reordered checkpoint frame can raise but never lower the
  bases from which the forward jump is computed. A new epoch resets counters
  to that install's initial values (new keys ⇒ fresh counter space).
- **Fencing is unchanged and remains the only ownership authority.** Local
  take-semantics on the holder are a hygiene measure, not a safety argument;
  two *nodes* are prevented from both owning an SA's inbound SPI by
  `OwnershipFencer` (monotonic fence, fingerprint-bound transitions) exactly
  as before. This crate adds no bypass: the takeover output is an ordinary
  `SameSpiResume` that must ride an ordinary `RePinRequest` through
  `RePinCoordinator::repin`.

### 8.1 Normative takeover order

1. `take_for_repin` → validated evidence + keymat in hand.
2. `RePinCoordinator::repin` → fence commit, audit, steering install.
3. Install keymat + restored counters into the standby's dataplane
   (`restored_send_iv_next` MUST be the counter actually installed — the
   transition fingerprint binds it).
4. Drop the takeover buffer (zeroize). Inject `ForwardingProof` when observed.

A CNF MAY pre-install **receive-side** SA state before step 2 to shrink the
blackout window, but MUST NOT transmit on the SA before the fence is granted:
transmission is what consumes outbound IVs, and only the fence proves the
previous owner is excluded. On re-pin failure the caller still holds the
keymat and may retry, or drop it (zeroize) and fall back to re-attach.

## 9. Memory-custody controls

SDK-enforced (this crate):

- `Zeroizing` buffers at every stage; zeroize-on-drop is conformance-tested.
- No `Serialize` on keymat (compile-fail-pinned); manual `Debug` redaction.
- Bounded standby capacity — at capacity, new installs are **rejected**
  (fail closed, producer sees `capacity_exhausted`) rather than silently
  evicting some other SA's HA coverage.
- Epoch anti-rollback and constant-time idempotency checks (§5.3).
- Redaction-safe errors: static field/reason strings, I/O errors reduced to
  kind + os-error code, no peer-controlled text propagated.

Deployment-required (out of SDK reach, normative for Option-D claims):

- Key-holding processes run with swap disabled (or `memlock` for the holder's
  arena), `RLIMIT_CORE=0`, and ptrace denied.
- SVID policy on both mirror endpoints restricted to the CNF's own identity
  (`PeerPolicy` — a mirror endpoint must never accept arbitrary trusted peers).
- The standby process is subject to the same controls as the owner; mirrored
  custody is not a lesser custody.

## 10. Conformance

Shipped with the crate (`cargo test -p opc-sa-mirror`):

- Codec round-trips over in-memory duplex streams; oversized frames, secret
  tails on non-install frames, and version mismatches fail closed.
- Holder: epoch rollback, equivocation, capacity, monotonic counter merge,
  withdraw idempotency, ESP zero-sequence rejection, take-once semantics.
- Takeover evidence validates under `SameSpiResume::validate_for_repin` and is
  accepted end-to-end by `RePinCoordinator` with mock steering/fencer/audit.
- Keymat: `Debug` redaction, zeroize-on-drop (`ZeroizeOnDrop` bound +
  observable wipe), non-serializability (`compile_fail`).
- Full producer → mTLS → sink → takeover path over loopback with SPIFFE SVIDs.
- The fake mesh (`InProcessMirrorProducer`) proves the ports compose without
  any network.

## 11. Open questions for SDK owners

1. **Hand-off audit surface.** Mirror installs/takeovers are auditable today
   by decorating the ports (and every takeover already lands in the re-pin
   audit stream). Should the SDK later standardize a `MirrorAuditSink` event
   vocabulary (AC-6(9)-style in-memory hand-off audit), or is the decorator
   pattern the intended long-term answer?
2. **Wire-format stability.** The crate is `publish = false` / experimental
   like `opc-session-net`; the frame layout is versioned via `Hello` but not
   yet a compatibility commitment. Graduation criteria should be decided
   together with `opc-session-net`'s.
3. **Standby assignment.** Rendezvous selection (`opc-ipsec-lb::selector`)
   could pick standbys deterministically from the shard set; left product-side
   for now per ADR 0018.
