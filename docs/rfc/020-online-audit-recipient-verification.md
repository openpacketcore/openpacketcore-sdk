# RFC 020: Authority-owned online audit recipient verification

**Status:** Proposed public API and trust contract; not approved or declared
implemented. A maintainer must approve the RFC before an implementation PR can
cite it as an approved contract. An ADR or source candidate is not RFC approval.

**Date:** 2026-09-26

**Version:** 0.1.0

**Tracking:** [SDK #959](https://github.com/openpacketcore/openpacketcore-sdk/issues/959).
Related: [RFC 003](003-security-substrate.md),
[RFC 010](010-data-governance-privacy.md), and
[ADR 0025](../adr/0025-management-audit-continuity.md).

## Problem and proposed decision

The existing trusted local `AuditExportVerifier` accepts an `AuditKeyRing`.
Its HMAC signing material also permits producing valid authentication tags;
giving it to an export recipient cannot establish verification-only custody.
Export authorization does not reduce that cryptographic capability.

Add an online verification exchange owned by the existing audit authority.
The authority would retain its signing keys, frozen export and verifier. An
authorized recipient would return the actual page bytes it received and obtain
an online report bound to its fresh request and the complete frozen range.
This is an additive API over the existing audit continuity policy, export
admission and independent checkpoint port; it creates no new service, backend
or authority credentials for the recipient.

## Trust and application boundary

The recipient trusts the selected authority to execute verification honestly,
and the existing independent checkpoint authority to retain its monotonic
state outside the configuration database's restore domain. Historical signing
keys remain under authority custody. The recipient receives no signing key,
keyring accessor, signing operation or checkpoint-write credential.

The embedding application must authenticate and authorize the recipient for
export, independently authenticate the expected authority, and protect the
request/reply channel's integrity and confidentiality. Every server call must
receive an `AuditCaller` derived from that authenticated context. A decoded
caller claim, nonce, manifest or session binding is not authentication or
permission to export. The application must bind routing and session ownership
to that context and feed client acceptance methods only replies from the same
authorized authority exchange. It must enforce framing and aggregate connection
limits before allocating transport input and drop session owners on disconnect.
This RFC supplies no listener, TLS configuration, credential provisioning or
replacement application authorization policy.

Reports are online observations, not portable cryptographic proofs. A forged
report must not enter client acceptance through an unauthenticated route.
This mode does not defend against a hostile authority or compromised admitted
channel, and promises neither offline verification nor non-repudiation. It
cannot prove that a recipient durably archived bytes merely because the
recipient returned them or a transport delivered a reply.

## Proposed public API and immutable binding

These are proposed names and contracts, not a statement of API availability.

| Proposed type or operation | Contract |
| --- | --- |
| `AuditRecipientClient` | Recipient-owned, non-cloneable state containing the independently selected authority, recipient scope, fresh random request nonce and accepted binding. No signing or store capability. Accepting a final report consumes it. |
| `AuditRecipientVerificationRequest` | Bounded untrusted request with a version, authority identity, recipient scope and nonce. The authority compares it with independent caller/store inputs before admission. |
| `ConsensusConfigStore::begin_recipient_audit_export` | Takes authenticated recipient scope, exact expected retained floor, fixed lifetime and request; reserves the existing export slot, reads current authority/checkpoint state, and freezes the whole retained range. |
| `AuditRecipientSessionBinding` | Complete immutable request, authenticated manifest and actual checkpoint checked at freeze. Every subsequent call supplies this exact binding; possession alone grants no authority. |
| `AuditRecipientExportSession` | Authority-owned frozen rows, historical key references and streaming verifier. No public construction, deserialization or clone capability. Generates pages, accepts received bytes and is consumed by finish. |
| `AuditRecipientVerificationReport` | Bounded wire data containing the exact binding and separately identified fresh finish checkpoint. Decoding it authenticates nothing and cannot construct a `VerifiedAuditExport`. |
| `CompletedAuditRecipientVerification` | Authority-local, non-deserializable completion retaining the genuine verification result, frozen export and permit. Only its report crosses the recipient boundary. |

The manifest retains the existing exact authority/recipient, exclusive floor,
predecessor and signing anchor/epoch at that floor, inclusive tail, terminal
root/signing anchor/epoch, row count, issuance, expiry and export nonce. The
request nonce additionally binds the recipient's fresh exchange. Full binding
equality is required; matching only a tail counter or a caller-supplied digest
is insufficient. The complete `ConfigConsensusIdentity` and `AuditCaller` are
compared, not display names or partial selectors. Saved reports cannot resume
a fresh client. A wrong opening reply poisons that client rather than replacing
its selected authority.

## Received bytes and complete frozen range

The exchange would proceed as follows:

1. Begin validates the request and whole-second lifetime, acquires the existing
   export permit before ledger/provider work, reads the quorum-current
   authenticated ledger and independent checkpoint, and freezes the complete
   retained range. An older requested floor returns `Pruned`; a future floor is
   invalid. The authority must not silently select a different range.
2. Page generation uses the existing authenticated manifest/cursor and bounded
   export page. Generating a page does not verify receipt. The recipient sends
   the actual encoded page bytes it received through the authenticated channel;
   the verifier must not substitute a freshly generated server page for them.
3. The authority decodes and verifies those bytes with the existing streaming
   verifier. It checks the exact manifest, offsets, order, row count, both
   chains, historical transitions and predecessor/terminal boundaries. Omitted,
   duplicated, reordered, substituted, truncated or tampered data cannot yield
   a complete verification. Any received-page validation failure poisons the
   session. Even an empty range requires its one terminal page; duplicate
   terminal receipt is refused.
4. Finish consumes the session, requires verified complete receipt and performs
   the fresh checks below. Page generation or the absence of a next cursor
   alone cannot manufacture successful completion.

Request, binding and report messages would have a 32 KiB encoded ceiling. Their
acceptance must reject malformed input and unsupported request versions; decode
alone remains unauthenticated. Existing page encoding retains its
16 MiB encoded ceiling and 256-row acceptance limit. These are distinct bounds,
not a complete peak-memory or transport-fanout guarantee. The implementation
must retain the current bounded decoders, immutable row ownership and export
admission; applications must separately bound queued/held page copies.

## Fresh checkpoint, rollback and pruning

Finish must newly read the current authenticated ledger and the configured
independent checkpoint. It cannot reuse the freeze witness during an outage.
The checkpoint must authenticate for the selected authority and match the
current ledger's root, signing anchor and epoch at its sequence. Existing
continuity checks and known checkpoint monotonicity remain mandatory.

Relative to this session, finish must reject a checkpoint behind the freeze
witness, replacement of the complete checkpoint at an equal sequence, or a
current ledger behind the frozen tail. Every still-available overlap between
the current ledger, frozen range and the two checkpoints must agree in root,
signing anchor and epoch. Concurrent advancement between reads may produce a
typed refusal; it does not authorize accepting inconsistent observations.

The report must expose two distinct witnesses:

- `checkpoint_at_freeze` is the independent witness actually checked against
  the frozen range. Only it defines that range's reported checkpoint coverage;
  the manifest may include a newer, uncheckpointed suffix.
- `checkpoint_at_finish` is a fresh witness checked against the live authority.
  A larger counter does not, by itself, prove protection of every archived
  suffix row or extend the frozen witness's coverage.

Lawful append or pruning does not change frozen pages. If pruning removes an
overlap needed to relate a later checkpoint to the frozen tail, no stronger
coverage may be inferred from counters. The report retains the original freeze
coverage and distinguishes the current observation. Historical keys remain
available to the authority while a session or completion holds their owning
references. Dropping those owners permits normal key retirement; verification
after historical keys are unavailable is not promised. Independent rollback
protection depends on the existing checkpoint trust/consistency contract, not
on a recipient's copy of a report.

## Expiry, cancellation and capacity ownership

The existing export lifetime remains 1–3600 whole seconds with a fixed original
expiry. Use before issuance or at/after expiry is refused; awaits and retries
must not refresh it. Finish rechecks expiry after its quorum/provider awaits,
and recipient acceptance checks the same original binding's expiry.

One existing export permit covers begin, the frozen session and successful
local completion. Failure or cancellation of begin or consuming finish drops
their owned admission. A borrowed page/receipt call returning an error does not
destroy a retained session: the application must drop poisoned or abandoned
owners. Dropping a session or completion releases its ownership without
acknowledging anything. The application must drop retained owners on disconnect
or cancelled work. Expiry refuses use but cannot reclaim an object the
application keeps alive; this proposal adds no background reaper or persistent
session registry. Already accepted native work retains the executor's existing
cancellation/join rules;
caller drop is not proof that all blocking storage allocations have drained.

A lost finish reply may be resent from the same retained local completion to
the original client/binding; client acceptance still refuses an expired binding.
Process loss does not restore either ephemeral protocol owner: recovery starts
a fresh nonce and manifest after authoritative reopen, subject to current
pruning and admission.
There is no fallback that shares signing keys or bypasses an unavailable
checkpoint to maintain availability.

## Verification is separate from acknowledgement

Begin, page receipt and finish are read-only authority operations: they do not
submit maintenance, advance a checkpoint, write an export receipt or prune
history. The genuine `VerifiedAuditExport` remains inside the authority-local
completion. The wire report has no conversion into it.

A separately authenticated and authorized authority action may use that local
capability with the existing acknowledgement API. Its expiry, recipient, exact
prefix, checkpoint advance/readback and consensus receipt checks remain
unchanged. Existing safe-pruning requirements still apply. Neither online
verification nor transport delivery establishes permission to acknowledge or
evidence of durable recipient archival.

## Compatibility and typed failure contract

Existing trusted local/offline verification remains available to callers
already entitled to hold signing material. The proposal adds bounded
request/binding/report messages and recipient APIs; it does not change existing
command, ledger, export-page, RPC or snapshot encodings, signing domains,
checkpoint semantics, key transitions, immutable authority/capacity profiles,
native WAL, Durable/Async behavior or protocol write capabilities.

Failures retain the existing value-free `AuditAuthorityError` categories.
Malformed/oversized input or an invalid lifetime is `InvalidInput`; mismatched
caller, authority, session or authenticated content is `BindingMismatch`;
expired admission is `Expired`; an old floor is `Pruned`; exhausted export
admission is `Full`; unavailable authority/checkpoint or required key material
uses `Unavailable` or `KeyUnavailable`; detected regression uses
`RollbackDetected`. Existing `RecoveryRequired` conditions are not converted to
success. No error or diagnostic should expose signing material, received
payloads, projected identities or provider details. A failure must not return a
partial proof, imply acknowledgement or silently upgrade checkpoint coverage.

## Alternatives and tradeoffs

| Alternative | Benefit | Reason not selected for this proposal |
| --- | --- | --- |
| Share the HMAC keyring with recipients | Reuses trusted local verification offline. | Grants signing authority and fails #959's custody requirement. |
| Introduce public-key archival signatures | Could support independently verifiable offline archives. | Requires a separate cryptographic format, custody/rotation and compatibility contract, with its own review and evidence. No such guarantee is claimed here. |
| Treat an export authorization grant or decoded report as proof | Small interface and no online verification state. | Neither authenticates received rows nor separates HMAC signing authority. |
| Authority-owned online verification | Reuses existing authenticated formats, historical transitions, admission and checkpoint port without exporting signing keys. | Requires trusted authority/channel availability, returns recipient bytes for verification, and retains bounded server ownership until drop. Application transport and archival policy remain necessary. |

## Acceptance and remaining evidence

Approval of this RFC would approve the boundary, not certify an implementation
or close #959. The implementation PR must reference the maintainer-approved
RFC under [GOVERNANCE](../../GOVERNANCE.md). ADR 0025 may record implementation
details but cannot substitute for that approval.

Required evidence must cover authentic complete/empty exports; tampered,
omitted, reordered, duplicate, substituted, truncated and malformed pages;
wrong caller/authority/nonce/binding and cross-session report replay; poisoned
sessions; historical transitions; lawful pruning; unavailable/wrong/behind or
conflicting equal-sequence checkpoints; coherent observed rollback; and exact
separation of frozen coverage from a later live witness. Completion must leave
ledger/checkpoint/receipt/retention state unchanged. Separate acknowledgement
and safe pruning require their existing positive and negative checks.

Ownership tests must reach the relevant begin/finish/provider or native-work
phase before cancellation, prove slot release without acknowledgement, retain
permits through live completion, and prove fixed expiry after an awaited
checkpoint read. A failure before the intended phase is not valid removal
control evidence. Production-removal controls must preserve these assertions
and deadlines; restored positive paths must execute on the final exact source.

Application-level evidence remains required for authenticated recipient and
authority selection, export authorization, channel/session routing, framing and
aggregate input limits, actual recipient-byte return, disconnect/cancellation
cleanup and bounded fanout. Real retained reopen does not alone qualify durable
disk sync, process-crash recovery, multiple voters or a deployed authenticated
endpoint. Those claims require their corresponding storage, process and
transport fixtures. No application endpoint, checkpoint service deployment,
complete memory proof or production maturity is asserted by this proposal.
