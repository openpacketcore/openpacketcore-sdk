# Canonical empty IKEv2 replies

Status: design approved; V1 byte primitive and zero-write receive handler
implemented in `opc-proto-ikev2`.
The [`canonical` module](../crates/opc-proto-ikev2/src/canonical.rs) supplies
record-derived byte regeneration, without receive-window or transmission authority.
The [`empty` handler](../crates/opc-proto-ikev2/src/recovery/empty.rs) composes
the primitive with receive admission and lifecycle checks. The current
[recovery restrictions](../crates/opc-proto-ikev2/README.md) still apply,
including deployment refusal when canonical replies cannot be qualified.
The existing construction and implementation described below are AES-GCM V1.
The [CBC-V1 extension](#cbc-v1-extension) specifies AES-CBC recovery separately;
its frozen-format and crypto code reviews are complete. Production CBC canonical
replies are enabled through the typed window with current provider qualification.
Fragmented recovery is outside both profiles.

The objective is to regenerate exactly the same authenticated empty
INFORMATIONAL response after a crash without a durable write per response.
The retained SA record supplies a fixed recipe for the response. Re-evaluation
must produce the same complete IKE bytes as a cached retransmission would.
This is a conditional argument about one immutable GCM input tuple, not
permission to reuse a nonce for another message.

## Domain and nonce construction

Let `D` identify one established IKE SA, key epoch and local sending direction.
Its immutable inputs are the nonzero original-initiator and original-responder
SPIs, the original-role direction, the negotiated AES-GCM-16 algorithm, and
the exact directional `SK_e` material. Only AES-128, AES-192 and AES-256 with a
16-octet tag are in scope. Use the existing
[IV domain](../crates/opc-proto-ikev2/src/iv_reservation/domain.rs) binding;
no new KDF, derived encryption key, caller-selected key or nonce hash is added.

For initiator-to-responder output, select `SK_ei`; for responder-to-initiator
output, select `SK_er`. These are the original roles of this particular IKE
SA, not which side initiated this INFORMATIONAL exchange. Split the selected
material into the AES key `K` and its trailing four-octet salt `S` (20, 28 or
36 octets total). The salt followed by the eight-octet explicit IV forms the
12-octet GCM nonce, as specified by
[RFC 5282, sections 4 and 7.1](https://www.rfc-editor.org/rfc/rfc5282.html#section-4).

For Message ID `m`:

```text
0 <= m <= 0xffff_ffff
B       = 0xffff_ffff_0000_0000
IV64(m) = B + u64(m)                 (checked addition; no wrap)
IV(m)   = ff ff ff ff || BE32(m)     (8 octets)
N(D,m)  = S(D) || IV(m)              (12 octets)
```

Thus `m = 0` selects `B`, and `m = 0xffff_ffff` selects `u64::MAX`.
The mapping is injective into exactly the upper `2^32` explicit IVs. ID zero
is a legitimate request ID on an established SA: the original responder's
first request, and the first request after an IKE rekey, can use it. Admit an
authenticated empty INFORMATIONAL at zero under the same window rules as any
other ID; an RFC 6311 ID-zero sync Notify remains a different, nonempty class.
See [RFC 7296, section 2.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.2).
Exhaustion never wraps back to zero under the same key epoch.

The existing [ordinary sealing boundary](../crates/opc-proto-ikev2/src/protected_payload_crypto.rs)
is `IKEV2_AES_GCM_NORMAL_IV_END = B`. All other output, including ordinary
requests, sync packets, nonempty responses and empty acknowledgements of
nonempty requests, uses ordinary `SK`/`SKF` IVs below `B`.
Only the fixed-format builder may use the reserved region. This is
a local sending partition; it does not restrict authenticated peer IVs.

SA identity and key epoch are represented by the bound key/salt and fixed
header inputs. **SPIs, direction labels and epoch numbers are not extra nonce
bits.** An unrelated descriptor with the same `K,S` cannot safely select a
different SPI pair, direction or format: it would repeat `N` with different
associated data. Fresh IKE key derivation and exclusive ownership of the key's
binding and nonce domains are prerequisites, not consequences of constructing
a descriptor. The persisted binding and V1 enablement mechanism below prevent
the canonical path from assembling a second domain from mutable session fields.

## Exact response bytes

Define format `V1` once for the lifetime of the key domain. It contains one
unfragmented `SK`, no preceding payloads, no inner payloads, no optional
padding, and a 16-octet tag. All integers below use network byte order.

The plaintext is **one octet `00`**, the zero Pad Length;
the inner payload list and the Padding field are both empty. In particular,
the GCM plaintext is not a zero-length string. This padding choice and the
AAD ending at the `SK` generic header follow
[RFC 5282, sections 3 and 5.1](https://www.rfc-editor.org/rfc/rfc5282.html#section-3).
The IKE header fields use
[RFC 7296, section 3.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.1).

| IKE byte offsets | Width | Exact value and origin |
| --- | ---: | --- |
| 0–7 | 8 | Original initiator SPI from `D`. |
| 8–15 | 8 | Original responder SPI from `D`. |
| 16 | 1 | `2e`: next payload is `SK` (46). |
| 17 | 1 | `20`: IKE version 2.0. |
| 18 | 1 | `25`: INFORMATIONAL (37). |
| 19 | 1 | `28` for original-initiator output; `20` for original-responder output. Response bit set, Initiator bit fixed by `D`, Version and reserved bits zero. |
| 20–23 | 4 | `BE32(m)`, echoing the admitted request's Message ID. |
| 24–27 | 4 | `00 00 00 39`: complete IKE length 57. |
| 28 | 1 | `00`: `SK` inner Next Payload is None. |
| 29 | 1 | `00`: `SK` critical and reserved bits zero. |
| 30–31 | 2 | `00 1d`: `SK` length 29. |
| 32–39 | 8 | `IV(m)`. |
| 40 | 1 | Ciphertext `C` of the sole plaintext octet `00`. |
| 41–56 | 16 | Full GCM authentication tag `T`. |

The associated data `A(D,m)` is exactly bytes 0–31. The explicit IV is part
of the nonce and lies outside `A`. There is no authenticated field after the
`SK` header and before the IV. The length arithmetic is:

```text
P           = 00
SK body     = 8 IV + 1 ciphertext + 16 tag = 25 octets
SK payload  = 4 generic header + 25 body   = 29 octets
IKE message = 28 IKE header + 29 SK        = 57 octets
(C,T)       = AES-GCM-Encrypt(K, N(D,m), P, A(D,m), tag_bits=128)
wire        = A(D,m) || IV(m) || C || T
```

IP addresses, UDP ports and checksums, the UDP/4500 non-ESP marker, transport
framing and routing are outside these 57 IKE bytes and the AEAD inputs. See
[RFC 7296, section 2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
Timestamps, retry counts, receive floors, sync proposals, lifetimes, local
restart numbers and mutable endpoint data appear nowhere in the construction.

The builder creates its own headers. It does not copy a request header,
padding, or ignored request bits. Request validation still follows the
ordinary receive rules; this output specification does not introduce a new
requirement to reject every receiver-ignored input bit or legal request
padding choice. Such inputs cannot affect any response byte.

## Required invariant and ownership

For any two permitted evaluations `x,y`, the contract is:

```text
(Kx, Nx) = (Ky, Ny)  =>  Px = Py AND Ax = Ay AND tag_bits_x = tag_bits_y = 128
                    =>  Cx = Cy AND Tx = Ty AND wire_x = wire_y
```

The nonce-selecting inputs determine every byte in the table: the durable
binding fixes SPIs and direction; `m` fixes both header Message ID and IV;
`V1` fixes all other header bytes, lengths and padding. Merely fixing the
plaintext is insufficient. A different flag, SPI, length or authenticated
payload header under the same `K,N` would invalidate the construction even
if the plaintext remained `00`.

### Persisted binding and V1 enablement

The single source of canonical authority is the epoch binding in its
`Ikev2AesGcmIvRecord`, stored atomically with the SA's keys. It binds both SPIs,
the original-role direction, algorithm, exact key/salt and immutable format.
Its ordinary IV high-water may advance; these binding fields may not. A
canonical capability has private fields and can be derived only from that
committed binding, either after its initial durable activation or through a
restored committed window. The existing
[window restore](../crates/opc-proto-ikev2/src/recovery.rs) already compares
the IV record's domain with the window's sending domain. Canonical restoration
must use that same record and equality check, including the format marker.
It cannot take a second, freshly assembled descriptor as its source of truth.

The construction and restoration contract is:

1. `fresh()` creates the immutable `V1` enablement marker with the new epoch,
   before its first encryption, including the first protected IKE_AUTH.
   Persist it in the IV record with the first reservation, or atomically
   alongside that reservation and the keys. Neither ordinary encryption in a
   V1 epoch nor canonical capability release may precede that commit. This is
   initial key setup, not a write per empty reply.
2. Restrict the general-purpose `Ikev2AesGcmIvDomain::new` assembly function to
   crate-private use. Public canonical construction consumes the immutable
   new-epoch binding at `fresh()` or derives from its restored record.
   Canonical restoration accepts no inputs beyond the persisted record.
   The committed-window descriptor must derive from the same binding too.
   A bare domain, a separately constructed window descriptor, or raw
   `Ikev2SaInitKeyMaterial::from_established_keys` supplies no canonical
   capability. Thus the current public `new(new_spis, old_keys)` route cannot
   construct a second canonical domain. General descriptor construction alone
   cannot set the V1 marker or acknowledge its durable activation.
3. Restore reads the whole immutable binding and marker from the same trusted
   persisted epoch as the IV record and keys, and cross-checks the intended
   window domain. An absent, unknown or mismatching marker refuses canonical
   sealing; no missing field defaults to V1. An older record without the marker
   stays ineligible. There is no retrofit setter, marker upgrade or format
   negotiation on an existing key. Obtaining V1 requires a fresh IKE key epoch.
4. The entire reserved range `[B, 2^64)` belongs to V1 for that key's life,
   even at IDs not yet used. Another deterministic class must reserve a
   separately reviewed partition from the ordinary range or use fresh keys;
   it cannot repurpose any part of V1's range. All software versions serving
   an existing V1 epoch must reproduce its frozen bytes. A different format
   requires fresh keys.

The consumer must still establish fresh-key provenance and record integrity,
and keep one IV record per epoch. Calling `fresh()` on used keys or fabricating a
second persisted binding violates the ordinary allocator's contract as well;
neither the marker nor descriptor equality is a global historical-key registry.
An SA with unknown IV history must first establish fresh IKE keys through the
normal protocol. Relabelling it or resetting its counter is insufficient.

Both domain `new` constructors are now crate-private. The
[constructor migration table](../crates/opc-proto-ikev2/README.md#constructor-migration)
names replacements for fresh allocation, allocator restore expectations,
`Ikev2AesGcmIvRecord::from_persisted` and committed-window domain assembly.
`Ikev2AesGcmEpochInputs` supplies the complete new or persisted binding;
`from_persisted` also requires the exact stored optional format marker.
The `[Unreleased]` changelog records these API changes. No SDK durable storage
format or automatic migration is introduced.

### Binding trust and volatile cache ownership

For an untrusted or mixed record, unknown prior IV use, or unknown key
provenance, derive or restore **no canonical capability**, invalidate any
existing capability for that epoch, discard all its canonical bytes held in
memory, and withhold send authority. Cached bytes do not bypass this refusal.
If any part of the binding itself is in doubt—either SPI, original-role
direction, algorithm, key, salt or V1 marker—only a fresh SA applies. Do not
repair or replace the binding while retaining its keys. Unknown IV history
or key provenance likewise cannot be cured by relabelling the record.

Before calling `Window::restore`, record reconciliation applies only to state
that changes legitimately, such as an ordinary IV high-water or an uncertain
reservation write, while the immutable binding and its provenance remain
trusted. Read the window and IV records from one consistent fenced snapshot.
Every failed window restore now permanently revokes its canonical epoch;
correcting the records afterward cannot restore that canonical service.
Reconciliation never authorizes reusing bytes from a discarded or doubted capability.

Key the volatile reply cache by the **capability instance, its full immutable
binding and Message ID**. Check the binding including SPIs, role, algorithm,
key/salt and V1 marker, not just an epoch label or SPI pair. Invalidation
discards the entries; they cannot transfer to a replacement capability, even
if it reconstructs equal fields. Reconciliation or capability recreation must
not reset the process's attempt/release history for an undeleted SA. The ledger identifies the exact
sending key and salt by a full SHA-256 fingerprint, independently of capability
instance, SPI pair, role or epoch label. Its hash input is the fixed label
`opc-ikev2-canonical-key-salt-v1` followed by a zero octet and key/salt bytes.
A second fingerprint binds both directional key fingerprints, SPIs, original
role, algorithm and exact optional marker, using the distinct label
`opc-ikev2-canonical-binding-v1` followed by a zero octet. These are internal
bookkeeping identifiers, never encryption keys, nonces or persisted format
inputs. This identification assumes SHA-256 collision resistance, with no
digest truncation. A second binding with the same sending key/salt is refused
and revokes the first, even if it was built by mistake. Trust loss before first
capability creation also leaves a recent deletion tombstone.

The process registry is a hash map with expected O(1) key lookup; its global
lock is released before taking a per-key lock or sealing. Static ledger state
contains only fingerprints, counters, ownership metadata and verified ciphertext.
Key copies belong to the live capability and are zeroized on drop. The caller's
outer SA and persisted-record objects retain their own key-ownership obligations.
Replies own exactly 57 verified octets and no ledger lock; consumer-held copies
must be discarded when trust or transmission authority is lost.

As the receive window advances beyond replies it must retain, the consumer
calls `retire_through(m)`. The ledger monotonically closes all IDs at or below
`m`, including unseen IDs, and drops their individual entries. Attempts and
release status above that floor remain unchanged. Recreation cannot reopen the
floor, and `u32::MAX` closes every ID without wrap. Once an SA is permanently
deleted, call `delete()` on its capability or `delete_epoch(&iv_record)` after
that capability has dropped. After rekey, keep the old epoch available for
permitted retransmissions until the old SA has been deleted. Deletion and
invalidation clear all per-ID state and leave only a recent key fingerprint
tombstone.

Only live ledgers count toward `IKEV2_CANONICAL_MAX_TRACKED_KEYS` (1,048,576).
They are never evicted, including while a capability is dropped and recreated.
The per-process live-SA cap must exceed the largest consumer session count per
Pod, allowing for simultaneous old/new SAs and recovery headroom. Consumers must
size their maximum concurrent sessions below that bound and delete ledger state
when its SA is deleted. `RegistryFull` can occur only at this concurrency bound.
Deletion churn imposes no lifetime or per-day limit on SA epochs.

Deletion and trust-loss tombstones occupy a separate bounded FIFO, keeping the
most recent `IKEV2_CANONICAL_MAX_TOMBSTONES` (1,048,576) distinct fingerprints.
Repeated deletion of a retained tombstone does not refresh its position. The
oldest fingerprint is evicted when the FIFO fills. Revocation marks the old
ledger unusable before removing it from the live map, with no global lock held
while waiting for its per-key lock. A delayed revocation checks ledger identity
before removal, so it cannot remove a newer ledger admitted after FIFO eviction.

**Residual after tombstone eviction:** restoring a deleted SA's record requires
a consumer bug, but can create a fresh ledger once its fingerprint ages out.
With its original persisted binding it can only repeat the identical V1 packet,
so no different `(A,P)` is encrypted under the nonce. The once-per-process release
rule limits fault exposure; it is not a strict lifetime refusal of deleted keys.
A changed binding already violates A1 below, with the same exposure as after a
process restart. Consumers must never restore deleted records, and FIFO eviction
does not establish fresh keys or authorize reuse. Recent tombstones still catch
accidental old-key/new-SPI reuse shortly after deletion.

### Sealing authority

The only new sealing entry point takes the capability derived from this record
and a typed Message ID, owns all response bytes and derives its nonce
internally. It takes no arbitrary plaintext, `PayloadChain`, header, padding,
explicit IV, tag length, key override or general `allow_reserved` option. Before authorizing
a reply, the surrounding handler must authenticate and classify the same-domain
empty INFORMATIONAL request; a caller's boolean about raw bytes cannot supply
that evidence. The builder supplies reproducible bytes,
not authentication, receive-window or transmission authority. The private
encryption core uses the existing admitted crypto module.
Every reply, including a cache hit, requires the consumer to check current
receive admission and `Ikev2CommittedWindow::ready()` and retain send authority
through transmission. A minted capability does not follow later changes to
window lifecycle; the public `ready()` check reports only its current lifecycle
state and grants no receive or send authority by itself.
The public raw `IkeEncryptionOperations::seal_aead` primitive is unpartitioned
and must not be used directly with these SA keys.

## Provider qualification and packet checks

Before the first canonical seal in a process, each enabled GCM algorithm must
pass frozen V1 known-answer vectors through the admitted module's
`execute_aead_seal`. Compare the expected literal output, not merely a
seal/open round trip. Use dedicated public test keys and salts, never live SA
keys or their reservation state. All vectors for that algorithm must pass.
Store the result once per process and algorithm; concurrent callers share the
same check and cannot race ahead. A mismatch or operation failure latches
canonical refusal for that algorithm in the process. A prior process's success
is not reused after restart.

The installed [IKE module](../crates/opc-proto-ikev2/src/crypto_module.rs) is
once-only for a process, so this check runs again after a module/version change
at restart. Existing identity, declared-validation, capability and readiness
checks still apply on each operation; a cached known-answer success cannot
override them. The reviewed standards interpretation below applies to the SDK
software module. Other modules require qualification for explicit reserved IVs,
identical repeated evaluations, the frozen V1 answers and the default refusal
for declared-validated modules. A provider refusing repeated IVs releases no
packet; there is no alternate-provider or alternate-IV fallback.

Every newly generated packet must also pass these checks before release:

1. Rebuild the expected 40-byte prefix from the immutable binding, `m` and
   V1 constants in a separate buffer, independently of the output/header
   construction buffer. Compare every byte 0–39, including all AAD and the IV.
   Require the total packet length to be exactly 57.
2. Open the complete packet through the admitted open path with that binding
   and the expected AAD. Require the raw decrypted plaintext to be exactly
   the one octet `00`, before any padding removal. An empty decoded payload
   list alone is insufficient.
3. On any prefix, authentication, plaintext or provider failure, release
   nothing. Return only immutable verified bytes; do not publish a partial
   packet or fall back to different inputs, IV or provider. Tests inject both
   prefix and tag faults. The check mitigates transient faults; it does not
   prove that a faulty module or a correlated failure of the check is impossible.

Release at most one newly generated, verified packet per `(sending key, salt,
Message ID)` while its undeleted ledger is retained in the process, for the local
sending direction fixed by the binding. A packet
withheld by the self-check has never been released or sent. It may be sealed
again with the identical bound inputs, IV and provider, up to **three total
attempts**, including the first. Charge each attempt before evaluation; no
failure, cancellation or concurrent call may refund or reset it. A panic while
holding the ledger poisons it and prevents further sealing, including recreation.
Withheld outputs are never logged, persisted, returned in an error or shown in
Debug output. SDK-owned buffers are zeroized on drop, including error and unwind
paths; provider-internal temporaries remain the provider's responsibility. A retry is
permitted only while all capability, binding and module gates still pass;
latched known-answer failure or loss of binding trust remains a refusal.
After three withheld attempts, no further attempt for that epoch/ID is allowed
while its ledger remains registered. This is volatile accounting, with no
per-reply durable write. The deleted-record/FIFO residual above is separate.

After the first successful release, the empty-request handler reuses
those immutable bytes in memory for every permitted retransmission. It cannot
seal that ID again, even if fewer than three attempts were used. Cache eviction,
capability recreation and mutable-state reconciliation cannot reopen a released
ID or refresh the attempt budget; an ID whose bytes were discarded gets no
further response from that ledger. The cache remains bound to the capability
instance and full binding described above. A new process may regenerate from
the retained trusted V1 binding. The window-one handler retains one empty
request identity and compacts canonical IDs below its applicable reply window.

## Refusals and protocol boundary

At the layer responsible for each check, refusal releases no canonical
response; it must not fall back to sealing different bytes under the derived
nonce. Encoding alone never proves that a request may be answered.

| Attempt | Required refusal or boundary |
| --- | --- |
| Nonempty reply, including any Notify, Delete, error or extension payload | Reject this builder; use the ordinary committed exchange path when otherwise permitted. |
| Empty acknowledgement to a nonempty request | Excluded from the zero-write handler. Its request effects and response belong to the ordinary committed path. |
| Different exchange, request flag, header/padding/length choice, truncated tag, `SKF`, or unencrypted prefix | No such output parameters exist; reject any incompatible context before encryption. |
| Foreign SA, changed SPI/role/profile, wrong directional key or salt, malformed key length, zero SPI | Reject a mismatch against the trusted bound epoch. No consumer-selected encryption key is accepted. |
| Identical `SK_ei` and `SK_er` key/salt material | Reject the epoch, as the existing IV-domain constructor does. Direction flags alone do not separate nonces. |
| Absent/unknown/mismatching marker, attempted in-place format change, bare or second descriptor | No canonical capability; only the single committed V1 binding or its checked restoration can supply it. |
| Untrusted/mixed record, unknown prior IV use, or unknown key provenance | Derive or restore no canonical capability, invalidate any existing one, discard the epoch's volatile canonical bytes, and withhold send authority. A doubted binding requires a fresh SA. |
| Unresolved outcome for legitimately mutable state, with the immutable binding and provenance still trusted | Withhold capability/send authority and reconcile that mutable state through the existing fenced record rules before calling window restore. Read both records from one consistent snapshot; a failed restore is terminal for canonical use. Never reconcile a changed or doubted binding into continued use of its keys, or reuse discarded cache entries. |
| ID outside `0..=u32::MAX`, exhausted ID state, narrowing cast or arithmetic wrap | Reject; never truncate, wrap or reinterpret exhaustion as zero. |
| Unauthenticated, wrong-SA, wrong-role, malformed, nonempty or non-INFORMATIONAL incoming packet, including RFC 6311 sync | No canonical-response authorization. A response packet cannot be treated as an empty request. |
| Failed receive-window admission, quiescence, `AwaitLocalSync`, `OutcomeUncertain` or closure | No bypass through this primitive. Cryptographic reproducibility does not confer lifecycle authority. |
| Frozen V1 known-answer mismatch or failure | Latch canonical refusal for that algorithm in this process; no packet. |
| Module declares `ValidationState::DeclaredValidated` without explicit canonical opt-in | Refuse by default, even if ordinary module admission succeeded. |
| Rebuilt prefix mismatch or self-open failure, including non-`00` plaintext | Release nothing. Permit only the identical-input retry rule above, at most three total attempts before a first release; no retry after release or exhaustion. |
| Unavailable/unadmitted crypto capability, seal failure or wrong output length | Return an error with no packet; no alternate cipher or fresh-IV fallback. |
| ID at or below the live ledger's closed floor, or a key with a retained deletion tombstone | Refuse. Compaction never resets the live ledger's budget; the FIFO residual is described above. |
| New key domain at the process's concurrent live-SA cap | Return `RegistryFull`; live ledgers are never evicted and deletion history does not consume capacity. |

Receive admission and empty-request handling are composed by `reply_empty`.
It authenticates and classifies the complete request before replying:
Response flag clear, INFORMATIONAL exchange 37, the peer's Initiator flag,
and one complete `SK` as both first and last outer payload, with no `SKF`.
After payload-chain validation, reuse `PayloadChain::is_empty()`; Next Payload
None with trailing bytes, or a non-None type without a payload, is not empty.
ID zero is allowed for this class when the receive window admits it.
The handler must
respect strict/declared floors and any permitted reconstruction mode, and
restrict below-floor traffic to the applicable exact-cache rule. In normal
operation a volatile expected-receive value starts at the committed floor;
only the admitted empty handler advances it. The next nonempty exchange
commits the advanced floor with its response and outcome. Reconstruction
observations must also feed the RFC 6311 peer-request drop floor. None of
these rules is implemented or weakened by the sealing primitive.

For the zero-write handler, canonical refusal means **no reply to an
empty request**. There is no ordinary-IV, committed-window or other fallback.
A V1 epoch answers an empty request only with V1, or not at all. DPD-sending
peers are unsupported in a durable deployment whose canonical path cannot
operate, for example with a declared-validated module lacking opt-in, an
unqualified module or a failed known-answer check. The consumer must refuse
that configuration up front, checking the intended algorithms and canonical
module policy/qualification before accepting such peers. A runtime refusal
after successful preflight still withholds the reply; it does not enable a
fallback.

Locally generated canonical reply bytes never enter durable committed
request/response caches, sync history, or IV-floor evidence such as
`minimum_send_iv_end`. They neither
reserve an ordinary IV nor raise `exclusive_end`. Passing them to ordinary
cache/IV-evidence APIs must refuse: their IV is at least `B`, above any
ordinary reservation end; at `m = u32::MAX`, computing IV + 1 would overflow.
The volatile byte reuse described above is separate from those durable caches.
Do not weaken ordinary restore checks to accommodate canonical packets.
Peer packets remain eligible to use the full wire IV range; the local reserved
prefix alone is not a classifier for peer traffic.

## Proof sketch and its assumptions

In addition to the usual AES/GCM security and key-secrecy assumptions, the
canonical reuse argument has these explicit premises:

- **A1:** one binding (SPIs, original-role direction and algorithm) and one
  format per `(K,S)` for the key's whole life, including IKE rekey transitions.
  The single persisted binding and immutable V1 marker enforce that boundary;
  inventing another IV record with used keys is outside the fresh-key contract.
- **A2:** the ordinary/reserved partition has held under `(K,S)` since its
  first encryption, for every writer, node and software version.
- **A3:** the entire range `[B, 2^64)` belongs exclusively to V1.
- **A4:** every implementation evaluating `(K,S)` computes standard GCM.
  Per-process, per-algorithm frozen known-answer checks qualify the admitted
  module; a round trip alone does not establish conformance.
- **A5:** every released evaluation is fault-free or its corruption is
  detected and withheld by the separate prefix and open checks. An undetected
  correlated fault in generation and checking remains outside this premise.
- **A6:** the two directional key/salt pairs differ, as the domain check
  already requires.

This canonical nonce-safety proof does **not** require correct admission,
request authentication, writer fencing or storage freshness. Under A1–A6, a
wrongly admitted request, a fenced-out owner or an older record with the same
immutable binding can only produce the same V1 bytes for `m`. Record integrity
and binding immutability still matter; changing a binding is not mere rollback
of its mutable high-water. Authentication and current fenced state remain
mandatory for protocol authority, ordinary IV allocation and operation effects.
This narrower proof does not relax any of those ordinary-path requirements.

1. **One domain, different IDs.** `B + m` is injective over `u32`, so different
   IDs select different nonces for its fixed `K,S`. Ordinary IVs are strictly
   below `B`; their nonces cannot collide with canonical ones under that
   key/salt. The same ID on an ordinary request therefore causes no collision.
2. **One domain, same ID.** All of `K,N,P,A` and the tag length are identical
   by construction. GCM is deterministic for those inputs. The repeated
   ciphertext/tag gives the same authentication equation, rather than a new
   equation arising from different authenticated data under the reused nonce.
   A4 and A5 keep the evaluated transcript fixed; the key remains secret.
   This is not a general nonce-misuse-resistant mode.
3. **Crash, restart or uncertain send.** Before encryption there is no output;
   after encryption, before or after transmission, the same retained recipe
   regenerates the exact output. No fresh counter or random padding is read.
   Restart uses the same immutable binding and format, even if its mutable
   floor is old. The operational rules still deny a capability, discard volatile
   canonical bytes and withhold send authority for untrusted or mixed records.
   Mutable-state uncertainty can be reconciled only with a trusted binding.
   A rolled-back receive floor can change which requests are
   considered, but cannot change their V1 bytes; later admission work must
   separately prevent replayed effects. An old owner emits identical canonical
   bytes too. Writer fencing still governs ordinary encryption and state
   changes; this argument does not authorize multiple active owners.
4. **Both directions.** A different AES key separates `(K,N)` pairs. If the
   AES key happens to be equal but the salts differ, the full nonces differ.
   Equal key-and-salt pairs in both directions are refused. Response flags
   cannot substitute for that refusal, because they change `A`, not `N`.
5. **IKE rekey.** A new epoch uses freshly derived IKE key material and its
   own original roles and SPI pair. The lifetime contract forbids assigning
   an already-used `K,S` pair to a distinct header/format domain. Retaining an
   old epoch briefly for retransmissions preserves its old binding; it never
   uses new SPIs with old keys. Child-SA rekey does not create a new IKE key
   epoch or reset the IKE ID/IV domains. Fresh derivation provides the usual
   negligible key-collision assumption, not a global historical-reuse detector.

Under those assumptions, equality of `K,N` implies equal salt and explicit
IV, hence equal `m` and the same permitted domain binding. The only remaining
case is the identical transcript of step 2. In particular, the proof fails
if a restored descriptor can change the SPIs, direction, format or keys
independently of that binding.

## Standards interpretation and module validation declarations

The accepted cryptographic interpretation is re-evaluation of one identical
protected message, not a new GCM input set. It is consistent with exact
regeneration in [RFC 7296, section 2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.3),
the substance of the unique-IV rule in
[RFC 5282, section 3.1](https://www.rfc-editor.org/rfc/rfc5282.html#section-3.1),
and the distinct-input requirement in
[NIST SP 800-38D, section 8](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
This interpretation is accepted for the SDK software module; another admitted
module requires the qualification above. RFC 7296 section 2.3 does not waive
window admission or authorize inventing a replacement for a forgotten response.
In a V1 epoch, an empty request receives only the exact V1 response, or no
response; it can never switch to a differently generated empty reply.

**Canonical regeneration deliberately departs from the literal restart rule
in SP 800-38D section 9.1 item 3**, which prohibits repeating a previous IV
after power is restored. The justification is the identical-input argument
under section 8. The existing ordinary IV reservations and committed
ordinary/sync recovery follow section 9.1's technique of persisting the IV end
ahead of use and discarding unused positions on restore. This departure starts
with the canonical path. It carries **no validated-module claim**, including
no claim that it is covered by FIPS 140-3 validation.
In-process readback makes no AEAD sealing call: the existing position remains limited
to cross-process regeneration and identical-input retries before first release.

Before canonical qualification or sealing, inspect the admitted module's
`ValidationState`. `DeclaredValidated` must refuse by default, even if ordinary
module admission passed. A consumer may explicitly opt in to this documented
canonical-path departure through a dedicated option whose default is off.
Do not infer opt-in from general module admission, recovery support or V1
creation. Opt-in does not confer a validation claim, override the module's
security policy, bypass its refusal, or skip known-answer and packet checks.
`NotValidated` still requires all normal admission and canonical checks.

## Replay observations and key usage

A passive observer already sees the SPIs, direction, Message ID, IV and
length. Repetition identifies the same canonical reply and reveals its known
empty content; it introduces no new plaintext relation or independent tag
equation beyond the first transcript. An active attacker replaying a captured
authenticated request may observe a response, its timing and rate. That can
reveal reachability or continued availability of the SA's reply recipe.
This equality and traffic-analysis leakage is accepted here because exact
IKE retransmission already exposes the same stable bytes.

A captured response can also be replayed without possessing the key. It is
not proof of fresh peer activity, a restart, durable progress, a current
receive floor, Child-SA state or completion of an application operation.
Consumers must not refresh lifetimes, move endpoints, change keys/bearers,
repeat effects or extend recovery deadlines just because this replay was
seen. Freshness claims require the surrounding protocol's fresh request and
window checks. Regeneration adds no stronger liveness claim. Authentication,
bounded work and response rate limiting remain necessary for replay floods.

### Accepted aggregate usage limit

The accepted design limit is **at most `2^33` distinct transcripts per
directional key** (`SK_e`, including its salt): at most `2^32` ordinary
positions under the existing
[reservation ceiling](../crates/opc-proto-ikev2/src/iv_reservation.rs), plus at
most `2^32` canonical IDs. The ordinary ceiling and nonwrapping Message-ID
domain already enforce these bounds. Skipped ordinary positions count against
their ceiling; repeated evaluation of V1 at an existing ID adds no transcript.
Restart does not reset either domain, and IKE rekey starts a new one with fresh
keys. No new ceiling, canonical counter or durable write per empty reply is
required by this design.

Each canonical transcript encrypts one plaintext block and has four GHASH
input blocks (two AAD, one padded ciphertext, one length block). Crypto review
accepted its contribution on top of the ordinary ceiling. This limit is not
a claim of unlimited key lifetime or a universal confidentiality target for
arbitrary message sizes. A tighter target is a choice of the existing ordinary
ceiling and rekey policy, independent of canonical regeneration. If two
directional domains deliberately share the AES key with different salts,
their nonces remain disjoint but an AES-key security calculation must sum both
domains; the `2^33` figure is per directional key, not a claim that such sharing
halves the total load. Re-evaluations still consume module invocations and CPU,
so byte reuse, provider qualification and rate limits remain applicable.

## Tests and qualification exit criteria

Tests preceded implementation. The independent Python/OpenSSL calculation tool
first passed all 1,125 published NIST CAVP `gcmEncryptExtIV*` encryption vectors
with a 96-bit IV and a 128-bit tag, then calculated the 24 frozen V1 packets.
[Its provenance](../crates/opc-proto-ikev2/tests/data/canonical_empty_v1.provenance.json)
retains representative published inputs/results, the archive digest, tool and
crypto-backend versions. The independent calculation also rejects every AAD-bit
flip and either incorrect AAD boundary for every frozen packet. External review calculations may cross-check
them, but must not replace independently produced, pinned project fixtures.
The fixtures define V1 compatibility: CI must check exact bytes, and updating
expected bytes is not a fix for an existing-key wire change. A new format
requires fresh keys. A seal/open round trip alone is insufficient.

| Test group | Required evidence |
| --- | --- |
| Independent wire vectors | AES-128/192/256-GCM-16, both original directions, distinct four-byte salts, IDs zero/one/an interior value/`u32::MAX`; full literal 57-byte packets checked against an independently calculated GCM result, with the calculation's provenance retained. |
| Byte audit | Assert every field/offset in the table, plaintext `00`, exactly 32 AAD bytes, IV/ciphertext/tag lengths, and decryption through the existing admitted open path. No padding or flag is taken from the request. |
| Associated-data boundary | Independent decryption must fail using bytes 0–27 or 0–39 as AAD instead of 0–31. Flip each of the 256 individual bits of bytes 0–31, with fixed nonce/ciphertext/tag; every independent GCM authentication must fail. |
| Encoder parity | Compare canonical bytes 0–31 with the ordinary window encoder's empty INFORMATIONAL response for the same domain/ID, using `Domain::header(Informational, m, true)` and internal `seal`. The different IV also changes the ciphertext/tag, which are outside this comparison. This needs test access, not a new production admission bypass. |
| Domain arithmetic and ID zero | First/last reserved values, nonwrapping arithmetic, representative/property-generated ID pairs for injectivity, and refusal of exhaustion/out-of-range adapters. Include admitted empty ID-zero requests from the original responder and after IKE rekey; keep both distinct from nonempty RFC 6311 ID-zero sync. |
| Repeat and restore | Record-derived capabilities and crashes before seal/after seal/before send/after send all yield identical packets with no reply-triggered IV reservation, durable write or RNG request. Vary local time, retry count and transport metadata without changing IKE bytes. |
| Forbidden variation | Public API has no arbitrary payload/header/padding/IV/key/tag controls; runtime boundaries reject foreign contexts. Test-only observation of crypto inputs must not become a public bypass. |
| Global nonce monitor | One property-style mixed workload observes actual `(K,N) -> (A,P)` inputs across ordinary requests/responses, empty acknowledgements of nonempty requests, sync in both directions, canonical replies, restart and IKE rekey. Cover both roles and all three key sizes; every observed pair maps to exactly one input tuple. |
| Key binding | Wrong local role, SPI, algorithm, key, salt and malformed lengths refuse against the expected descriptor; identical directional key/salt pairs refuse. Equal AES key with different salts exercises nonce separation. Tests must not claim a fresh descriptor detects historical key reuse. |
| Binding and marker enforcement | Absent/unknown/mismatching markers refuse; a marker cannot change within an epoch. Before initial marker/reservation commit no capability is released. A bare/second descriptor, new SPIs with old keys, or reconstructed raw key material cannot mint one. Restore cross-checks the same IV/window binding; the former public assembly route is unavailable. |
| Trust loss and cache ownership | Untrusted/mixed records, unknown IV history or unknown key provenance release no capability or packet and discard prior volatile bytes. Doubting each binding field requires a fresh SA; mutable high-water reconciliation cannot change the binding. Cache entries require the same capability instance and full binding, and cannot transfer after invalidation or recreation. |
| Module qualification | A consistently wrong provider can pass a round trip but must fail frozen known answers. Check each algorithm once per process despite concurrent callers, repeat after restart, latch failures, and keep normal module identity/readiness checks. Separate-process tests respect once-only module installation. |
| Declared validation | `DeclaredValidated` without canonical-specific opt-in refuses before qualification/sealing; general admission is insufficient. Explicit opt-in still requires all known-answer/self-check gates and never suppresses a module's own refusal. |
| Packet fault checks | Inject a changed prefix, tag, output length and unexpected raw plaintext. Independent prefix rebuilding and admitted open must prevent every corrupted packet from being released, including a prefix corruption that the generation path itself used. |
| Withheld-attempt budget | Success on attempt one, two or three releases one verified packet; three withheld evaluations prevent a fourth. Every retry uses identical inputs/IV/provider and passes all gates. Concurrency, cancellation, cache eviction, capability recreation and reconciliation never reset counts. After release, retransmit cached bytes with no further seal; after their discard, do not reconstruct in that process. |
| Rekey and format | New IKE keys and roles select the new domain; old-domain tokens cannot seal for it. Child rekey leaves the IKE domain intact. Format changes on old keys refuse; unchanged `V1` restores identically across supported software versions. |
| Ordinary exclusion | Keep reserved-IV refusal tests for all ordinary direct/counter/reservation `SK` and `SKF` sealers, including `B`, an interior reserved value and `u64::MAX`; receive/open still accepts legal peer use of that range. |
| Classification and failures | Nonempty input/output, non-INFORMATIONAL exchanges, response-as-request, Notify/sync/Delete, fragments, unauthenticated or malformed requests, foreign domain and provider failure produce no canonical reply or effects at the relevant boundary. |
| Deployment refusal | Reject durable configurations with DPD-sending peers when any required canonical algorithm/module policy or qualification refuses. No ordinary-IV or committed-window fallback exists, including after a runtime refusal; every answered empty request in a V1 epoch uses V1. |
| Later window composition | Empty at floor `F`, then nonempty at `F+1`; duplicate/gap/exhaustion; restart reconstruction and below-floor cache rules; no bypass of declared sync floors or terminal/quiescent states; reconstruction IDs enter the sync drop floor; no fresh-liveness or repeated-outcome side effects. Cached replays reuse volatile bytes without a second seal; an ID retired from that cache cannot trigger re-encryption in the same process. |
| Durable cache/IV evidence exclusion | Canonical bytes cannot be imported into committed caches, sync history or `minimum_send_iv_end`. Cover ordinary high-water refusal and the `m = u32::MAX` IV + 1 overflow without weakening restore. |
| Accepted usage bounds | Exercise ordinary ceiling and final canonical ID independently, rekey/exhaustion and restart without resetting either domain. Repeated IDs add no transcripts or persistence. Include domains sharing an AES key when recording aggregate test usage. |
| Third-party peer interoperability | In composed qualification, verify a third-party peer accepts one-octet plaintext, reserved-range IVs, both directions, ID zero and exact repeats after restart. Retain peer/version and packet evidence. |

The implemented primitive tests are in
[`qualification_tests.rs`](../crates/opc-proto-ikev2/src/canonical/qualification_tests.rs),
[`admission_tests.rs`](../crates/opc-proto-ikev2/src/crypto_module/admission_tests.rs)
and the private [`wire` tests](../crates/opc-proto-ikev2/src/canonical/wire.rs)
and [`ledger` tests](../crates/opc-proto-ikev2/src/canonical/ledger/tests.rs).
The ledger tests count retained entries across many keys and IDs, verify closed
floors and deletion, exhaust the live-ledger bound, pin the key-free static object
graph by exhaustive field/type checks, and count hash probes rather than time
restoration. Thousands of deletion cycles with a small cap must never exhaust
live capacity; tests cover the most recent N refusals, exact FIFO eviction order,
duplicate deletion, retained live release/attempt history and delayed revocation
after re-admission. Public tests cover owned `Send` replies without same-thread lock
deadlocks, deletion across capability lifetimes and lifecycle-check refusals.
Existing ordinary reservation, window, protected-payload and sync suites remain
part of qualification. Public compile-fail examples pin constructor restrictions,
non-cloneability and the lack of raw ID or output-variation entry points.

The table's **later window composition** group is implemented in
[`empty_recovery.rs`](../crates/opc-proto-ikev2/tests/empty_recovery.rs): empty
at F followed by committed nonempty work at F+1, strict/sync floors, lost-prefix
reconstruction and effect/liveness rules. `reply_empty` checks current module
admission and window readiness on every call, retains identical bytes, and
borrows the window exclusively through response use. Enabling empty replies on
a restored window always selects SDK prefix reconstruction above a trusted floor.
Restore and enable are separate: a capability-active or pending-sync enable
refusal leaves the checked runtime and epoch available for retry once the cause
clears. The first nonempty result commits the repaired floor and ends the mode.
Restoration reports uncertain freshness
until a new inbound or sync boundary commits in this runtime. Admission also
records IDs in the volatile sync drop history, including failed canonical
evaluations. No endpoint, key, bearer, lifetime or outcome effects are authorized.
The [README](../crates/opc-proto-ikev2/README.md#zero-write-empty-requests-and-restart-reconstruction)
maps these choices to RFC 7296 §§1.4, 1.4.1 and 2.1–2.4 and specifies the common
`window.delete()` hook for every permanent teardown, including RFC 6311 terminal
cleanup and old-SA deletion after rekey. Every failed window restore revokes
canonical state. Failures before window restore need `delete_epoch` without a
runtime.
Deployment refusal is exposed as per-algorithm `preflight`; the consumer still
owns configuration admission and must refuse unqualified DPD deployments.

The older `canonical_replies` constructors are now restricted: the window
helper is crate-private and the allocator helper is test-only. Their primitive
qualifications run inside the crate, including process-isolated provider tests.
Public callers use checked window restore followed by `enable_empty_replies`
and `reply_empty`, which couple canonical output to receive admission and floor
advancement. This API restriction changes neither the V1 construction nor its
release contract. Public compile-fail callers pin both restrictions.

### In-process readback preservation

Replacing a runtime during fenced in-process readback currently drops its
canonical capability and cached bytes while retaining released-ID history.
The replacement refuses the most recent released ID with `AlreadyReleased`.
If the peer lost that reply, it may stall until synchronization or expiry.
This fail-closed limit on RFC 7296 §2.3 reply retention is covered by the
integration tests; it is not solved by permitting another release from a new
capability. A process restart has a separate ledger lifetime and retains the
existing V1 regeneration contract.

Use `window.reconcile(profile, keys, &record, &iv_record)` for in-process readback
with this contract:

1. Require fencing and resolution of outstanding writes before accepting the
   latest atomic record. Re-run domain/profile/key, packet, generation, sync and
   IV high-water validation without recreating the canonical capability. The
   complete immutable binding must match; mixed, stale or invalid state revokes
   the epoch and requires teardown. Validation is separate from the existing
   restore wrapper's failure cleanup, preserving that cleanup contract.
2. Preserve the same canonical capability instance, verified last reply, attempt
   and release ledger, volatile receive floor, pending identity and observed
   sync history when no new inbound boundary landed. Outbound-only commits must
   not discard that prefix or cache. Adopt a newly landed inbound result or sync
   cutover through the existing boundary rules, without moving a live floor back.
3. Fence old completion tokens and adopt durable outcomes as history, never as
   fresh effect permission. Reconciliation alone supplies no fresh liveness.
   Resume only the lifecycle allowed by the validated committed record; pending
   or terminal sync cannot be bypassed. The exclusive mutable borrow prevents
   reconciliation while an SDK reply still borrows the window.
   Record-trust failures remain terminal. A failed provider pre-check preserves
   the trusted epoch for retry; valid lifecycle states reconcile successfully
   and remain visible through `ready()`.
4. Regressions cover a lost last DPD reply across cancelled/uncertain outbound
   commits, both landed and unlanded readback, exact cache reuse with no extra
   seal, landed inbound/sync boundaries, changed bindings, stale tokens and
   provider withdrawal. Cover both roles and all supported GCM sizes. Do not
   reset attempts or release flags, permit a second release after capability
   recreation, alter the V1 transcript or change crash regeneration.

The following reviewed contract governs implementation of the in-place API.

#### Slice 9 design delta: readback invariants

`Ikev2CommittedWindow::reconcile(&mut self, profile, keys, record,
iv_record) -> Result<(), Ikev2WindowError>` resolves fenced readback on the
existing runtime. It returns no packet or completion token. This section makes
the plan above precise, including the design review's D1–D10 requirements.

1. **One checked lineage.** The caller settles or fences every outstanding write
   and reads both records from one consistent snapshot. Validate packets, keys,
   profile, counters, sync metadata and IV coverage as restore does, using the
   runtime's full immutable binding (both SPIs, original role, both directional
   keys/salts, algorithm and V1 marker). **D4:** only the IV record's
   `exclusive_end` may rise; its sending domain, receive domain, marker and limits
   are unchanged. Its required end is the maximum of the last checked end and
   every IV sealed in the witness, whether landed or not. Validate the witness's
   cached packets, initiating attempts and `minimum_send_iv_end` using restore's
   coverage checks. **D5:** keep the live allocator during in-process readback:
   it retains burned allocations and prepared ranges. Do not restore it from
   readback. If rebuilding it is unavoidable, use the same fenced snapshot and
   discard the reserved tail as on process start. No old send permission revives.
2. **Identify what landed.** Before exposing a prepared record for persistence,
   retain its exact candidate and transition kind privately in the window.
   Quiescence permits at most one such unresolved candidate. Readback accepts
   either the last acknowledged window record or that exact candidate, field
   for field: even `minimum_send_iv_end` must match. Same-generation changed fields,
   older records and unexplained successors are refused. Clear the candidate
   at each acknowledgement's equality check, before any subsequent fallible
   retirement or clock check, or after successful readback. This bounded volatile witness
   adds no durable field, write or consumer-selected boundary flag.
   **D2:** capture at the prepared value's construction, never at admission:

   | Record-exposing constructor | Witness kind | Adopt receive boundary if landed |
   |---|---|---|
   | `prepare_request` | outbound | no |
   | `prepare_completion` | outbound | no |
   | `prepare_response` | inbound | yes |
   | `Ikev2AdmittedSyncInitiation::prepare` | sync | yes |
   | `complete_sync` (`Recovered`) | sync | yes |
   | `close_sync` (`CloseIkeSa`) | sync | yes |
   | `Ikev2AdmittedSyncResponse::prepare` | sync | yes |

   The responder witness is captured after `prepare` raises the required IV end
   for its sealed response. A witness exists only while the runtime is quiescent.
3. **Preserve the owner.** Successful reconciliation keeps the identical
   canonical capability instance, full binding, policy and ledger. It never
   calls acquire, drops/recreates the capability, clears its attempt/release
   history or changes V1 bytes. Repeated readback of the same record is
   idempotent for canonical state. At most three evaluations and one new release
   per sending key/salt/ID still apply; a released ID can only reuse its verified
   cached bytes. A forgotten/retired reply stays refused in this process.
4. **Preserve or advance the receive boundary.** An unchanged record or landed
   outbound request/completion keeps the live receive floor, phase, pending
   request identity, last empty request/verified reply and observed peer-ID
   history. Generation growth alone is not an inbound boundary. Only the exact
   landed inbound-result or sync candidate adopts a boundary: retire superseded
   replies, clear the pending identity and enter the current phase. **D3:** both
   commit and readback adopt `max(live, recorded)`, where `None` (exhausted) is
   the top, including `CloseIkeSa` after a volatile empty prefix. Never lower the
   live floor or reopen a closed canonical ID. An already acknowledged boundary
   does not reset receive state again, but retirement is retried as D6 requires.
5. **Fence effects independently.** Every reconciliation attempt retires the
   ordinary/sync completion-token identity, including at an unchanged generation;
   this identity is distinct from the retained canonical owner. Readback creates
   no effect, send action or fresh liveness observation. Landed outcomes are
   history for fenced, idempotent consumer restoration. A pending local sync
   remains blocked and loses response-completion authority until its existing
   higher-proposal retry path; no cached responder sync reply is recreated.
   **D10:** even unchanged readback without a witness drops a live proposal's
   response authority. This conservative rule matches restore: an ensuing retry
   spends another of the event's at most three attempts with a fresh higher proposal.
   Preserve observed clock/deadline and terminal-close knowledge. A landed sync
   boundary absorbs the observed peer floor before retiring its volatile copy;
   an unlanded attempt cannot erase it or pending ordinary work.
6. **Failures grant nothing (D1).** There are exactly three outcomes:
   - Retryable: before validation, check that the module is installed, admitted,
     ready and serviceable for this epoch's AEAD. Failure returns the distinct
     `ReconcileUnavailable` error, keeps capability/cache/witness and live state,
     and leaves quiescence and the new token identity in place. A provider blip
     at this check never revokes the epoch.
   - Success: a valid record reconciles even in `AwaitLocalSync`,
     `OutcomeUncertain`, `CloseIkeSa` or latched closure; `ready()` reports that
     lifecycle after reconciliation.
   - Terminal: every other failure, including a packet that fails to open after
     the pre-check passed, or invalidation/poisoning during retirement. Revoke the
     runtime's binding and both supplied records' bindings, discard cached bytes,
     and remain quiescent until `delete()`. Never retry a permanently revoked SA.

   **D6, exact order:** rotate token identity and keep quiescence; run the D1
   pre-check; validate on scratch state and compute the monotone floor; retire
   superseded IDs on the held capability; publish the record, IV record and
   receive state together; clear the witness and quiescence last. Re-run this
   idempotent retirement on every successful reconcile, even unchanged readback
   or a previously acknowledged boundary. Retirement through the new floor
   minus one applies when adopting a boundary. For unchanged/outbound readback,
   preserve the last empty reply required by item 4: retire only IDs older than
   that retained request, including its failed-seal history. With no retained
   request, retire through the floor minus one. `None` closes through MAX.
   Check the held ledger even when no ID can retire. A retirement failure
   publishes no partial record/floor/phase and is terminal.

   Every later `reply_empty`, including a cache hit, still checks
   readiness, admission, exact request identity and current provider policy.
   Its exclusive borrow excludes simultaneous reconciliation; the consumer's
   external SA/send fence remains required through transmission.

Qualification will cover both original roles and all GCM sizes: landed/unlanded
outbound request and completion, cancelled preparation, repeated readback,
exact lost-DPD retransmission with no new seal/write/IV, preserved failed-seal
attempts, inbound and both sync boundaries, pending work, MAX exhaustion,
same-generation mutation/rollback/foreign binding, stale ordinary and both sync
tokens, provider withdrawal/recovery, and permanent revocation. A subprocess
restart separately retains the existing V1 regeneration contract. These tests
implement response retention and exact retransmission in
[RFC 7296 §§2.1–2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1),
without treating replay as liveness (§2.4); sync keeps
[RFC 6311 §§5.1, 8.3 and 9](https://www.rfc-editor.org/rfc/rfc6311.html#section-5.1).

**D7, additional required regressions:** (a) landed CloseIkeSa after a volatile
empty prefix on commit and readback; (b) unlanded sealed candidate above the
readback IV end; (c) changed limits alone or marker alone; (d) another runtime's
unexplained successor revokes both runtimes; (e) permanent revoke during reconcile
publishes no partial state and a later enable reports `Invalidated`, not
`CapabilityActive`; (f) retryable failure fences an old token even after later
success; (g) reconcile before empty enable acquires nothing and permits subsequent
enable; (h) the `(K, N) → (A, P)` monitor, canonical seal count and ordinary IV
position remain unchanged across each readback/retransmission kind; (i) responder
witness includes the IV end added during `prepare`.

**D8, documented lifecycle:** use reconcile for in-process readback; it acquires
no capability. Use restore for process start. Restore-replacement in one process
still discards the last empty reply's bytes while retaining its release history,
so it retains the F5 limitation and is not the in-process reconciliation path.
**D9:** reconciliation makes no AEAD sealing call; the SP 800-38D position above is unchanged.

Live peer/lab execution is not part of this change. Third-party acceptance of padding, reserved
IVs, both directions, ID zero and exact restart repeats remains an explicit
composed qualification gate. Unit tests and the accepted construction are not
peer-interoperability evidence.

The construction, binding/provider mechanisms, software-module interpretation
and aggregate limit passed design review. The implementation adds the exact
key/salt fingerprint ledger, zeroizing withheld-output handling and API migration
specified above. Independent review of the receive handler and composed peer
qualification remain required before deployment.

## CBC-V1 extension

Status: approved construction and confirmed frozen labels, field encodings and
byte table. The complete immutable descriptor, typed window/sync/readback
integration and bounded canonical cache are implemented. CBC markers may be
persisted only inside that fresh-epoch descriptor, atomically with the keys.
The integration has passed crypto code review and production CBC canonical
replies are enabled through the checked window. Deployments must run
`preflight_cbc` for every intended profile and refuse a configuration if any
preflight fails. Provider policy, full binding, lifecycle and release checks
remain in force. GCM V1 bytes and its binding/reservation contract remain
unchanged. CBC-V1 is a distinct typed profile, not another interpretation of
a GCM format byte or IV record.

### K1: IV key and permutation

Let `D` contain the established epoch binding below, `dir = 00` for
original-initiator output and `01` for original-responder output, and `m` be the
admitted request's 32-bit Message ID. Integers use fixed-width network byte
order. Freeze the following octet strings, including the single terminating
zero on the KDF label and no terminator on `L96`:

```text
KDF_LABEL = ASCII("opc-ikev2-canonical-cbc-iv-key-v1") || 00  (34 octets)
L96       = ASCII("opc-cbc-iv-1")                           (12 octets)
P0        = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0f
S_D       = KDF_LABEL || BE64(SPIi) || BE64(SPIr) || dir
            || BE16(12) || BE16(AES key bits) || BE16(INTEG id)
            || BE16(PRF id) || 01                          (60 octets)
K_iv(D)   = first keylen octets of prf+(SK_d, S_D)
X(m)      = L96 || BE32(m)
IV(D,m)   = AES-ENC(K_iv(D), X(m))
C(D,m)    = AES-ENC(SK_e(dir), IV(D,m) XOR P0)
```

`keylen` is 16, 24 or 32; AES key bits are 128, 192 or 256. The PRF is the
epoch's negotiated HMAC-SHA1, SHA2-256, SHA2-384 or SHA2-512 (IDs 2, 5, 6, 7).
Use the established `SK_d`, including any negotiated PPK mixing; SKEYSEED,
traffic keys, fresh randomness and public data are not alternative key sources.
The seed offsets are 0–33 label, 34–41 SPIi, 42–49 SPIr, 50 direction, 51–52
ENCR, 53–54 key bits, 55–56 INTEG, 57–58 PRF and 59 format. For example,
SPIi `0102030405060708`, SPIr `1112131415161718`, initiator output, AES-128,
SHA2-256-128 integrity and SHA2-256 PRF give this seed:

```text
6f70632d696b6576322d63616e6f6e6963616c2d6362632d69762d6b65792d7631000102030405060708111213141516171800000c0080000c000501
```

Derive through the admitted `execute_prf_plus` at capability creation. Keep
`K_iv` only in that live capability in zeroizing memory; never persist, log,
publish, place it in a static or supply it to an ordinary sealer. The derivation
is independent of clock, entropy, writer, process and retry count. An IKE rekey
gets new `SK_d` and SPIs; a Child SA rekey changes neither. Preserve the old
epoch's existing keys until deletion so its replies remain reproducible.

The admitted `execute_cbc_encrypt` with `K_iv`, one block `X(m)` and a 16-zero
chaining block implements the AES forward permutation. That internal chaining
block is never the transmitted IV. A second admitted CBC encryption, under
directional `SK_e` with the computed IV and exactly `P0`, produces `C`.
`execute_integrity_checksum` under directional `SK_a` authenticates the whole
header, IV and ciphertext with the negotiated truncation. No direct software
crypto, entropy substitution, alternative KDF or runtime fallback is permitted.
Provider refusal of either one-block operation withholds the packet.

### K2: independent release self-check

Before releasing any newly generated bytes:

1. Require the exact profile length from K3. Independently rebuild bytes 0–31
   from the binding, `m` and frozen constants in a separate buffer and compare.
2. Pass the packet's bytes 32–47 through admitted `execute_cbc_decrypt` under
   `K_iv`, with a zero chaining block. Require the raw 16-byte result to equal
   independently assembled `L96 || BE32(m)`. Do not reuse the sealer's IV/input
   buffer as the expected value. This inverse check is mandatory: a faulty IV
   can otherwise yield a packet with a valid MAC and the correct plaintext.
3. Use admitted `execute_integrity_verification` to verify the ICV over bytes 0–63
   before decrypting the traffic ciphertext. Then use admitted CBC decryption
   under directional `SK_e` and the transmitted IV; require the raw plaintext
   to equal all 16 octets of `P0`, before any padding removal.

All checks must succeed. Withhold and zeroize faulty output and temporary
secret/plaintext buffers; expose neither bytes nor crypto internals in errors.
The existing three charged attempts, single release, cache and retirement rules
apply unchanged. A successful authenticated open alone is insufficient.
Known-answer qualification checks the derivation separately. As with GCM, the
fault model excludes a correlated failure that corrupts generation and its
independent checks consistently.

### K3: exact bytes and supported profiles

All 48 triples of three AES-CBC key sizes, four integrity transforms and four
PRFs are in scope. Each triple needs its own successful K6 qualification before
preflight admits it; an unknown or uncovered triple is refused. The CBC format
octet is `01`, meaningful only inside a CBC descriptor. It cannot stand in for
the GCM marker. This layout is frozen for every epoch carrying CBC-V1:

| Offsets | Length | Value |
| --- | --- | --- |
| 0–15 | 16 | `BE64(SPIi) || BE64(SPIr)` |
| 16–18 | 3 | `2e 20 25`: SK, IKE version 2.0, INFORMATIONAL |
| 19 | 1 | `28` for original-initiator output; `20` for original-responder output |
| 20–23 | 4 | `BE32(m)` |
| 24–27 | 4 | `BE32(IKE length)` from the integrity table |
| 28–31 | 4 | `00 00 || BE16(SK length)` |
| 32–47 | 16 | `IV(D,m)` |
| 48–63 | 16 | `C(D,m)` |
| 64–end | 12–32 | Truncated HMAC under `SK_a(dir)` over bytes 0–63 inclusive |

| Integrity transform | ID | Key octets | ICV octets | SK length | IKE length |
| --- | --- | --- | --- | --- | --- |
| AUTH_HMAC_SHA1_96 | 2 | 20 | 12 | 48 (`0030`) | 76 (`0000004c`) |
| AUTH_HMAC_SHA2_256_128 | 12 | 32 | 16 | 52 (`0034`) | 80 (`00000050`) |
| AUTH_HMAC_SHA2_384_192 | 13 | 48 | 24 | 60 (`003c`) | 88 (`00000058`) |
| AUTH_HMAC_SHA2_512_256 | 14 | 64 | 32 | 68 (`0044`) | 96 (`00000060`) |

The shortest empty IKE padding is 15 zero octets followed by Pad Length `0f`;
this is IKE padding, not PKCS#7. The builder owns all headers and padding.
Authenticated legal noncanonical request padding remains accepted and cannot
affect reply bytes. IP/UDP framing and the non-ESP marker remain outside this
wire format. A format or KDF change requires a new reviewed marker on fresh
epochs; upgrades must retain these bytes for existing CBC-V1 epochs.

### K4: immutable binding, ledger and storage

The CBC descriptor binds both nonzero SPIs, local original role/sending
direction, ENCR and key bits, INTEG, PRF, `SK_ei`, `SK_er`, `SK_ai`, `SK_ar`,
`SK_d` and the CBC format marker. Validate all key lengths against the profile.
Refuse equal `SK_ei`/`SK_er` or equal `SK_ai`/`SK_ar`. No binding field may change
on restore or readback; a mismatch refuses and permanently revokes the epoch.

Once activation is authorized, persist the descriptor atomically with the
epoch's keys and SA record before acquiring its first canonical capability.
No derived key and no per-reply data is persisted. Fresh epochs only is the
lifecycle policy; existing epochs cannot gain or change a marker. CBC has no
IV partition, so this write may follow IKE_AUTH: it need not precede the first
ordinary encryption. A missing, unknown or mismatched marker grants no
canonical authority. Unqualified CBC-V1 empty replies have no random-IV fallback.

Use separate, labelled SHA-256 fingerprints, with `LP(x) = BE16(len(x)) || x`:

```text
ledger_key = SHA256(ASCII("opc-ikev2-canonical-cbc-ledger-key-v1") || 00
                   || BE16(12) || BE16(key bits) || BE16(INTEG id)
                   || LP(sending SK_e) || LP(sending SK_a))
binding    = SHA256(ASCII("opc-ikev2-canonical-cbc-binding-v1") || 00
                   || BE64(SPIi) || BE64(SPIr) || dir
                   || BE16(12) || BE16(key bits) || BE16(INTEG id)
                   || BE16(PRF id) || 01
                   || LP(SK_ei) || LP(SK_er) || LP(SK_ai) || LP(SK_ar)
                   || LP(SK_d))
```

The ledger identity deliberately excludes SPIs, direction, PRF and `SK_d`, so
a second binding over the same sending encryption/integrity keys reaches the
same ledger and is refused, revoking the first. The full binding covers those
fields and both key directions. Fingerprints are key-free process indexes,
never persisted recipe inputs or encryption keys; compare them in constant
time. Retain the global live-ledger limit, FIFO tombstones, exact ownership and
all delete hooks. No static may retain `K_iv` or any raw `SK_*`; extend the
static-state whitelist test accordingly.

The zeroizing cache entry and returned canonical reply need a bounded buffer
of up to 96 octets with a checked actual length. Neither unused tail bytes nor
truncation may reach the caller. Preserve the 57-byte GCM representation on the
wire and the prohibition on durable caching of canonical reply bytes.

### K5: profile-typed recovery

Separate CBC and GCM domain, epoch record, capability and packet evidence
types, with sealed profile dispatch for the shared window lifecycle. GCM alone
has an IV record/high-water, allocator, allocation token, reservation retry and
required-IV-end evidence. CBC has an immutable descriptor and ordinary random
sealing operations. A CBC window or authenticated CBC packet cannot be passed
to a GCM counter extractor or reservation check. Do not model CBC by a dummy
counter, ceiling, optional GCM allocation or a branch that merely skips a GCM
check; CBC-specific constructors and methods cannot accept such evidence.

The migration checklist covers:

- `recovery/packet.rs`: GCM `sending_iv_end` and `require_reserved_iv` accept
  only authenticated/sealed GCM evidence. CBC complete SK opening and sealing
  use the CBC lengths and admitted ordinary sealer, without an allocation token.
- Restore and reconcile: GCM retains D4 IV coverage and D5's live allocator.
  CBC validates the immutable descriptor and authenticated packets, with no
  IV arithmetic, reservation retry or allocator to retain.
- `recovery/record.rs` and `recovery/sync_record.rs`: CBC sync records have no
  `minimum_send_iv_end` field or floor-retention method. GCM keeps these in its
  own record/evidence type; they are absent from CBC's persisted representation.
- D1 preflight: CBC checks admitted, ready and serviceable CBC cipher,
  integrity transform and PRF before validation. Withdrawal returns retryable
  `ReconcileUnavailable`, preserving the capability, cache, witness and live
  state, while fencing old tokens. Every other failure follows D1's existing
  terminal/success rules.
- Sync readiness: CBC checks cipher, integrity and entropy, including actual
  module support. The offer and sync path cannot pass through AEAD-only checks.
  Canonical readiness additionally checks PRF, policy and K6 qualification.
- `canonical_module_declares_validation` and the qualification registry:
  dispatch on the typed profile/triple; CBC never qualifies under a GCM entry.

All seven witness constructors, exact pending-record matching, monotone live
floors, token rotation, D6 retirement order, in-process reply retention, pending
work and sync deadlines carry over. Reconcile generates no packet and releases
no bytes for either profile. GCM-only APIs remain available for GCM callers;
shared implementation cannot introduce GCM fields into a CBC record.

### K6: qualification and standards interpretation

Before a process's first canonical seal for each `(ENCR/key bits, INTEG, PRF)`
triple, run frozen known answers through the production CBC-V1 sealer, including
the `SK_d` derivation, zero-chaining-block permutation, traffic encryption,
integrity and independent release checks. Compare complete literal bytes and
intermediate `K_iv`/IV fixtures. Cache only key-free qualification state; latch
failure for that triple. A provider refusing the internal zero chaining block
fails qualification, with no software fallback. Ordinary CBC round trips alone
cannot qualify deterministic regeneration across implementations.

Pin independently generated fixtures for all 48 triples, both directions and
IDs `0`, `1`, `0x12345678`, `u32::MAX` (384 packets). Validate the independent
generator against FIPS 197 Appendix C, SP 800-38A F.1/F.2 for all AES sizes,
RFC 3602 §4, RFC 4231/2202, RFC 4868 §2.7, RFC 2404, NIST CAVP SP 800-135 IKEv2
prf+ vectors and the existing SDK prf+/complete-message fixtures before pinning
its output. Reviewer examples are cross-checks, not the source of expected data.

[RFC 7296 §3.14](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.14)
requires unpredictable CBC IVs; first generation at a new `m` meets that
requirement under the secret independent IV key. Exact regeneration repeats
the same message as permitted by
[§2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.3).
[SP 800-38A §5.3 and Appendix C](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
state unpredictability per encryption execution; Appendix C's first method
uses the traffic key's forward cipher on a nonce unique to that execution.
CBC-V1 instead uses an independent key and repeats the identical input when
regenerating. That departs from the literal per-execution wording; the security
argument is that it encrypts no new message, and key separation avoids coupling
IV generation to traffic encryption. This is an interpretation, not a NIST
validation or a claim about a module's security policy. `DeclaredValidated`
canonical CBC opt-in stays off by default, even if ordinary CBC is admitted.
Opt-in cannot bypass admission, known answers or the release self-check.

[RFC 8247 §2.1](https://www.rfc-editor.org/rfc/rfc8247.html#section-2.1)
requires AES-CBC-128/256; 192-bit support is optional. Its
[§2.3](https://www.rfc-editor.org/rfc/rfc8247.html#section-2.3)
requires SHA2-256-128 integrity. Supporting the other existing triples does not
change negotiation policy or claim a requirement for SHA2-384-192.

### K7 and carry-over decisions: tests and ordinary CBC

Inject a wrong IV followed by internally consistent ciphertext and ICV: K2 must
withhold it even though ordinary open succeeds. Also inject prefix, ciphertext,
ICV and length faults. Pin whole-packet parity with the ordinary test-vector
sealer and the window's empty response header. Check every MAC-covered/ICV bit,
omission of each MAC span, receive-direction keys, every KDF/binding field,
equal directional keys and provider policy changes.

CBC restore and readback tests use authenticated packets with random IVs whose
top bits are set. Withdrawal of integrity or PRF must be retryable at D1; CBC
sync readiness must include entropy and integrity. Run the window/witness,
readback, sync and crash/restart suites in both roles across supported profiles.
Prove exact post-restart replies with zero durable writes, qualification failure
latching and validated-module refusal without opt-in. The process monitor
checks one packet for each `(sending keys, binding, m)`, zero canonical entropy
draws, and one 16-octet draw per ordinary seal.

The implemented qualification spans all 48 triples and both original roles.
`recovery/profile/lifecycle_tests.rs` exercises all seven record-exposing paths
(including both initial and retry initiation), exact cancelled/landed witnesses,
same-generation outcome substitution, pending identities, all completion-token
types, clock and latched-close retention, exhausted live floors and crossed sync.
Provider-isolated cases also cover retryable D1 failures without loss of the
cache or witness, bounded nonce collisions and separate nonce/IV entropy draws.
`recovery/profile/restart_tests.rs` runs nine fresh child processes, each with
288 live fixture epochs across the profile/role/Message-ID matrix. Abrupt exits
skip window and capability destructors before enablement, after enablement,
after verification/submission and at ordinary acknowledgement boundaries.
Restoration checks exact ordinary replay, canonical packet equality despite
different authenticated peer padding, zero empty-exchange record changes,
post-DPD ordinary admission and Message-ID exhaustion. The linked-library test
also checks all 384 frozen packets under both canonical policies without a
test-only send fixture. These SDK software fixtures do not establish third-party
peer interoperability; composed peer qualification remains a separate gate.

There is **no ordinary-IV rejection-sampling guard in any epoch**. Ordinary and
sync CBC keep fresh random IVs from admitted entropy, exact committed ordinary
retransmission bytes, and no derivation, inverse call or descriptor lookup on
their sealing path. Existing caller-RNG and explicit-vector entry points retain
their contracts; recovery uses the admitted-entropy entry point exclusively.
An ordinary IV equal to a canonical IV does not warrant a new failure mode for
this fixed public plaintext; exclusion would not eliminate CBC block-input
collisions. No new CBC IV ceiling is introduced. Existing Message-ID exhaustion
and SA lifecycle limits remain in force; canonical traffic adds at most `2^32`
distinct one-block inputs per direction, subject to CBC's usual aggregate
birthday bound. No GCM nonce argument is claimed for CBC.

Fragmented SKF recovery and ESP counter synchronization remain out of scope.
Composed third-party peer qualification is required before any CBC interop
claim; software fixtures and this design are not peer acceptance evidence.
