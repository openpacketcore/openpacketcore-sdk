# Pending N3IWF protocol-key custody

`protocol_key` accepts a 32-octet, zeroizing K_N3IWF handoff and permits one
attempt to compute both directional IKE_AUTH MICs. The imported key has no
public byte access, general PRF interface, callback, conversion, or serializer.
This is volatile software custody with API-level non-exportability.

## Standards and caller responsibilities

[TS 33.501 V18.12.0](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/18.12.00_60/ts_133501v181200p.pdf)
clauses 6.2.2.1 and 7.2.1 describe the AMF handoff of K_N3IWF and its use as
the IKE MSK. [TS 29.413 V18.5.0](https://www.etsi.org/deliver/etsi_ts/129400_129499/129413/18.05.00_60/ts_129413v180500p.pdf)
clause 5.3 identifies the N3IWF NGAP Security Key use;
[TS 38.413 V18.10.0](https://www.etsi.org/deliver/etsi_ts/138400_138499/138413/18.10.00_60/ts_138413v181000p.pdf)
clause 9.3.1.87 gives the 256-bit width.
[RFC 7296 sections 2.15 and 2.16](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.15)
define both peers' shared-key AUTH calculations after key-generating EAP.

The association identity, generation, increasing operation identifiers,
single pending slot, consume-once policy, and aggregate input-byte limit are
SDK contracts. They are not additional wire requirements. Operation identifiers
are local labels, not IKE message IDs.

The caller admits the AMF handoff, assigns the correct purpose, owns the real
association and its lifecycle, and supplies its exact SA_INIT transcripts,
nonces, ID bodies, negotiated profile, and established SK keys. An opaque
operation guard is authority to supply those inputs; this module cannot detect
a caller associating unrelated external transcripts or same-width SK keys with
that guard. EAP success, subscriber authentication, identity authorization,
hierarchy derivation, and permission to send AUTH remain application decisions.

## API and lifecycle

All new symbols live in `opc_proto_ikev2::protocol_key`.

1. Keep an `Ikev2ProtocolKeyAssociation` alive for the real association. Two
   owners with identical numeric labels remain different opaque associations.
2. Call `begin_ike_auth` with the exact current generation, a fresh increasing
   `NonZeroU64` operation identifier, and the negotiated profile. The returned
   `Ikev2ProtocolKeyOperation` reserves the sole pending slot.
3. Move a `Zeroizing<Vec<u8>>` into `operation.import(N3iwfMsk, bytes)`. The
   allocation moves into custody without copying its key bytes. Import checks
   purpose, width, and the existing admitted IKE PRF capability. A failed first
   import retires the attempt and clears its input. A duplicate cannot replace
   the first imported key.
4. Call `Ikev2ProtocolKeyHandle::consume_ike_auth` with that exact operation.
   Matching live authority retires the key before checking bounded inputs or
   executing crypto. Success and failure both clear it. The aggregate cap sums
   the message, nonce and ID-body lengths for both directions before transcript
   allocation. Direction, SK width, and both signed-input shapes are checked
   before the first provider call.
5. Use `Ikev2ProtocolKeyAuth::verify` to check the received method-2 AUTH and
   `authentication_data` to serialize the appropriate local AUTH. These are
   transcript-specific authentication bytes, not the MSK or its padded key.
   Do not log them. Cache the resulting AUTH or protected packet for replay;
   the MSK cannot be consumed again or re-imported into the same operation.
6. Cancel or drop the operation after its pending work ends. Call `release`
   on association release or `replace_generation(expected, successor)` on
   replacement. Replacement must increase; release is permanent. A new
   generation resets the operation counter. Exhausted counters fail closed.

Both peers need the MSK-derived AUTH calculation. One logical consumption
therefore computes both MICs and immediately destroys the MSK. This involves
six admitted PRFs, including two applications of the MSK padding PRF. Eight
simultaneous consumers still yield exactly one successful pair. A mismatched
guard cannot consume or retire another operation's key.

Handle, operation, and owner drop retire pending custody. A future that owns
the operation guard therefore cancels custody when dropped. Stale guards and
handles cannot retire their successors. Synchronous consumption and retirement
share one mutex: retirement waits for an executing provider call, and its
return guarantees that no later use of the pending key can start. Providers
must remain synchronous, bounded, and non-reentrant. Poisoned state is cleared
and never reopened.

## Existing capabilities and unsupported outcomes

Every PRF uses the existing `install_ikev2_crypto_module` admission,
`Ikev2CryptoRequirements`, negotiated PRF, live readiness and zeroization
checks. An absent, withdrawn, changed, unsupported or failing module causes
refusal; there is no fallback or caller-provided key export adapter. Ordinary
software admission does not establish validated custody or HSM residence.

`opc-key::KeyProvider` and `KeyHandle` remain purpose-bound envelope-encryption
interfaces. Their cloneable envelope handles do not become protocol handles.
`install_key_custody_module`, `admitted_key_custody`, `AdmittedKeyCustody`,
`KeyCustodyModule`, and `RemoteSealProvider` provide the existing admitted
envelope sealing seam. They currently lack atomic consumption bound to a
protocol association and operation. This implementation leaves those symbols
unchanged and offers no sealing, restore, serialization, process-restart
recovery, or unsealed key cache. It does not add a dependency from `opc-key`
to IKEv2 or widen a general byte-export surface.

`Ikev2ProtocolKeyHandle` has no `Clone`, `Copy`, equality, ordering, `Hash`,
`Default`, `Deref`, `AsRef`, `Borrow`, serialization, public constructor, or
envelope conversion. Association, operation, handle and AUTH result formatting
is fully redacted. Errors contain only bounded static classifications and
have no attached input or source values. The module emits no logs or metrics.

Zeroization covers owned live buffers and their `Zeroizing` allocations on
normal destruction and unwind. It does not claim erasure of caller/provider
copies, registers, process dumps, forgotten values, or aborted processes.
This API does not parse NGAP, drive EAP or IKE state, protect a complete
IKE_AUTH exchange, provision XFRM, or establish live peer interoperability.

## Independent evidence

The unchanged reviewed fixture subsets are:

| Subset | Source PR head / merge | Fixture tree | COMPLETION SHA-256 |
| --- | --- | --- | --- |
| protocol-key (#840) | `7276c714f801ec736dda582918de338cd1a99b7e` / `39be836e4b424c0fed2831a57f4ea1c16c6e3f0e` | `2cac62be30a7eb3403eccc4c3748e054d45e2d70` | `772475fadfbd3dfc826b4b8a3535096905890f0972d355f3838572eb1ebce06f` |
| eap5g (#830) | `b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d` / `987246c8be773b19304f059231c39baa8d54d123` | `bcd9fb5d400d661973255ce09718208dff1b09a1` | `9fefb0b2d9778bade561a6dfb15a8352af1bf311f0a1d42c136f366d44451950` |
| ngap (#839) | `b3bbf6f339d8b310a8e35ac0fe8d3f58f9e3cc91` / `2a110ecfa5445c927b6be14b0937e0c09dc5841e` | `bd7ef86ea21ead836bb2246cf1b2feab5161cfea` | `3085f3d73218c92754c0b4637615edc2e1670293ae314fe178d1b79da67b6a48` |

The protocol-key inventory contains ten legacy lifecycle labels and thirty
independent AUTH cases. The labels alone do not execute custody. The thirty
AUTH cases now also pass through the real import/consume/verify API, including
both peers and altered key, transcript, identity, nonce, direction, and MIC
inputs. Their SHA-256/AES-GCM-256/P-256 profile uses public test scalars and the
zero NGAP Security Key placeholder. Python HMAC/PRF+ and OpenSSL independently
establish the schedule and AUTH answers; no peer key is published. The original
fixture `runtime_claim=false` and `sdk_custody_validation=false` fields remain
unchanged; new custody evidence resides in these executable tests.

`src/protocol_key/tests.rs` observes zeroized live slices before deallocation,
tests lifecycle and stale authority, competing consumers, malformed inputs,
cancelled futures, poisoning and redaction. `tests/protocol_key.rs` proves
refusal without module admission in an isolated process.
`tests/crypto_module_admission.rs` counts real dispatches under concurrent use,
malformed inputs, capability withdrawal, malformed provider output and panic.
Compile-fail documentation and external API probes cover forbidden operations.
The `protocol_key` fuzz target exercises bounded synthetic imports and lifecycle
transitions; it does not establish wire interoperability.

Reproduce the focused evidence from the repository root:

```sh
cargo +1.89.0 test --locked -p opc-proto-ikev2 -p opc-key -p opc-crypto-provider -p opc-n3iwf-fixtures --all-features
python3 scripts/n3iwf_key_reference.py
cargo +stable clippy --locked -p opc-proto-ikev2 -p opc-key -p opc-crypto-provider -p opc-n3iwf-fixtures --all-targets --all-features -- -D warnings
cd crates/opc-proto-ikev2/fuzz
cargo +nightly fuzz run protocol_key -- -max_total_time=60 -max_len=4096
```

Repository-wide validation retains the required disk-backed temporary storage
and fs-verity qualification environment. Exact base/head/tree and gate results
are published in the implementation PR. The issue remains open until review
and all acceptance evidence are complete (Refs #791, tracking #795).
