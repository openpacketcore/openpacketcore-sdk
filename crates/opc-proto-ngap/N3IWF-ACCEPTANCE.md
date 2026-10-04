# N3IWF codec subset acceptance record

This record maps the original [#787](https://github.com/openpacketcore/openpacketcore-sdk/issues/787)
criteria to the implemented experimental SDK subset. Its first matrix contains
23 constructed/receive outcomes: NG Setup; Initial UE/NAS transport and
non-delivery; Initial Context Setup; PDU-resource setup, modify, release and
notify; UE release; Reset and Error Indication. The exact field ranges,
presence, criticality, cardinality, conditional and receiver-ignore rules are
in [CONFORMANCE.md](CONFORMANCE.md). A qualified outcome means its documented
subset, not every field or extension in the generated ASN.1 schema.

The separate conditional-procedure criterion requires explicit dispositions
and trigger gates. [N3IWF-PROCEDURES.md](N3IWF-PROCEDURES.md) covers all 40
applicable outcomes; the other 17 return `HandlerRequired` and keep local
triggers disabled. They are applicable but unimplemented field codecs, not
unsupported-procedure fallbacks. This record does not enable them.

## Criterion evidence

| Original criterion | Implemented evidence |
|---|---|
| Independent Release 18 bytes for each admitted outcome | The [23-outcome catalog](../opc-n3iwf-fixtures/fixtures/ngap/COMPLETION.json), complete-message constructor/receive suites, and per-field/transfer corpora in [tests/fixtures](tests/fixtures) compare external schema encodings with SDK output and semantics. Each conformance section identifies its corpus, provenance and digest. |
| Partial resources, conditional key/location, singleton/cardinality, malformed nested transfers and critical unknown IEs | [Resource setup](tests/n3iwf_resource_setup.rs), [session lists](tests/n3iwf_session_lists.rs), and the Modify, Notify, Release, Reset and tunnel suites exercise complete construction and admission, disjoint successes/failures, whole-message rejection, preallocation bounds and nested caller policies. |
| Explicit conditional-procedure dispositions and trigger gates | [Applicability tests](tests/n3iwf_applicability.rs) replay the complete routing matrix, directions, assigned criticalities and outcomes. All 17 unimplemented outcomes retain disabled triggers. |
| Preserve DecodeContext policy and redaction | [Constructed-container tests](tests/constructed.rs) distinguish canonical policy-filtered output from raw-preserving bytes and revalidate mutable metadata. Field and nested-message suites retain strict unknown-critical, duplicate, count, depth and byte rules. |
| Bounded constructed/decode fuzzing and documented subset | [decode_ngap](fuzz/fuzz_targets/decode_ngap.rs) invokes bounded shared replay and semantic reconstruction; actual ASAN/libFuzzer campaigns are recorded below. Every field section retains its explicit unsupported choices and finite SDK admission limits. |
| Original detector, guard removal, independent mutation and required gates | The linked implementation PRs retain original failures, deliberately removed runtime guards, independent malformed bytes, exact restoration, affected tests and full repository/hosted qualification. A successful round trip alone is never the oracle. |
| Exact SDK revisions, support and provenance | The public revision table below identifies the latest field increments. The conformance document and earlier accepted records in #787 identify preceding field and container increments. Each implementation PR records its qualified base/head/tree and merge evidence. |
| Value-free errors, Debug, metrics and reports | Pdu/PduKind/Message and N3IWF wrappers redact values; [field tests](tests/n3iwf_fields.rs) and NAS/context tests verify this. Error categories are static. This crate adds no packet, key, identity or peer logging/metrics. Explicit wire/value accessors remain caller-owned. |

`conditional_presence_key_custody_and_constructor_guards_are_explicit` checks
the borrowed Security Key's exact 32-byte length and original input pointer,
refusing 0/31/33-byte keys. Required receiver-ignored UE security capabilities
must still be present. Context AMBR is conditional on applicable session
content. Location fixtures cover both IP families, with/without port, and
TAI/PLMN combinations. Root QoS supports exact caller-supplied all-GBR
classification for conditional Session AMBR; the default API requires AMBR.
Classification is an input, not an inference of live session authority.

## Final field increments

The following are feature revisions, not an assertion that their root trees
include subsequent unrelated SDK changes. Their PR qualification records
distinguish the tested tree from its eventual public merge.

| PR | Feature base | Qualified feature head | Root tree |
|---|---|---|---|
| [#930 QoS](https://github.com/openpacketcore/openpacketcore-sdk/pull/930) | `4356ef8595f0e010ea49ce01b5c225c4b9f06036` | `ea5a15b15f0de5575f09ebc324cecddb2db56a5d` | `58b11cc823ca7233b33f496afe17dc39b8a7bb80` |
| [#932 Setup diagnostics](https://github.com/openpacketcore/openpacketcore-sdk/pull/932) | `ea5a15b15f0de5575f09ebc324cecddb2db56a5d` | `546f87a99fab988ed6ee921f342d9f79501dfb71` | `d3bdedbcaa0a6414ed7d1634de0819b47283b99c` |
| [#933 Setup response tunnels](https://github.com/openpacketcore/openpacketcore-sdk/pull/933) | `546f87a99fab988ed6ee921f342d9f79501dfb71` | `f93b87e0e97023d538e0301ba615f71daead76db` | `045c2a7273a7a3a22e98245830ebdd083eaef2ef` |
| [#934 Additional request/Modify tunnels](https://github.com/openpacketcore/openpacketcore-sdk/pull/934) | `f93b87e0e97023d538e0301ba615f71daead76db` | `b7beff0364224afc7d7c116e2ed078c99544324d` | `9568cb0e692117dfbe1300c65832a1a39dff0050` |

Pinned TS 38.413 V18.10.0 PDF SHA-256:
`21617ad6dd826e05a0e8356ef96f44199cf4c7bc1be65e6b915e9135e10b59e2`.
Independent reference generation uses Pycrate 0.8.1 and pypdf 6.1.0, never the
SDK's generated schema as the byte oracle. These four PRs retain real bounded
ASAN/libFuzzer campaigns: 335,830, 379,447, 344,660 and 339,531 executions,
respectively, each lasting 121 seconds with no artifacts. Corpus provenance,
fixed seeds, maximum input/RSS bounds, guard-removal counts and retained failure
history belong to the linked PR records. They establish those bounded runs,
not exhaustive parser safety or live AMF interoperability.

All per-field limits and refusal rules in the conformance document remain in
force, including unsupported ASN.1 additions and address choices. The SDK does
not install security/resources, select an AMF, correlate live requests, assign
subscriber/session ownership, decide NAS forwarding eligibility, or infer
readiness from decoded values. Those application responsibilities do not become
codec capabilities when the original issue's subset is accepted.
