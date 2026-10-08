# Historical backlog tracker handoff — 2026-10-08

[Issue #1172](https://github.com/openpacketcore/openpacketcore-sdk/issues/1172) is the current remediation tracker. It supersedes the coordination snapshot in [#960](https://github.com/openpacketcore/openpacketcore-sdk/issues/960). This dated ledger accounts for all 46 original issue rows and all six historical pull requests; it is not a live checklist.

At SDK main `4888b88392adda302b25c99da0f7c518ef322eda`, 30 original issues remain open and are carried into #1172; 16 have recorded closures. The original issue links preserve their acceptance criteria and historical evidence. Retiring #960 retires only the old coordination list. It does not close any child issue, qualify an unfinished mechanism, or change deadlines, durability, authority or resource contracts.

## Original issues

| Issue | Original scope | Disposition |
| --- | --- | --- |
| [#957](https://github.com/openpacketcore/openpacketcore-sdk/issues/957) | config consensus: support qualified bounded configurations above the 1 MiB command ceiling | Open; carried into #1172, fleet stream. |
| [#958](https://github.com/openpacketcore/openpacketcore-sdk/issues/958) | netconf: add required-audit handoff to the exact configuration effect | Open; carried into #1172, fleet stream. |
| [#959](https://github.com/openpacketcore/openpacketcore-sdk/issues/959) | audit export: support recipient verification without audit signing authority | Closed as completed on 2026-09-30; closure evidence remains in the linked issue. |
| [#868](https://github.com/openpacketcore/openpacketcore-sdk/issues/868) | test(mgmt-audit-store): investigate missing append after timed-out worker shutdown | Open; carried into #1172, flaky test stream. |
| [#724](https://github.com/openpacketcore/openpacketcore-sdk/issues/724) | config-bus survivor-leader qualification can time out under CI scheduling | Open; carried into #1172, flaky test stream. |
| [#908](https://github.com/openpacketcore/openpacketcore-sdk/issues/908) | bug(session-store): Async cannot recover a fixed quorum after a majority restarts | Open; carried into #1172, durable stream. |
| [#913](https://github.com/openpacketcore/openpacketcore-sdk/issues/913) | Investigate post-release failure in native Async held-writer shutdown test | Open; carried into #1172, flaky test stream. |
| [#811](https://github.com/openpacketcore/openpacketcore-sdk/issues/811) | fix(session-store): reconcile cancelled SQL cache validation and orderly WAL shutdown | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#819](https://github.com/openpacketcore/openpacketcore-sdk/issues/819) | fix(session): investigate stale lease renewal during mTLS recovery | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#823](https://github.com/openpacketcore/openpacketcore-sdk/issues/823) | test(session-store): investigate recovered-campaign initialization and terminal-proof failures | Open; carried into #1172, flaky test stream. |
| [#826](https://github.com/openpacketcore/openpacketcore-sdk/issues/826) | fix(session-store): attribute and bound maximum-roster verification admission | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#827](https://github.com/openpacketcore/openpacketcore-sdk/issues/827) | test(session-store): resolve snapshot cancellation replacement deadline failure | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#829](https://github.com/openpacketcore/openpacketcore-sdk/issues/829) | Current-thread SQLite committed-frontier writes strand unrelated runtime work | Open; carried into #1172, durable stream. |
| [#834](https://github.com/openpacketcore/openpacketcore-sdk/issues/834) | test(session-store): investigate snapshot fs-verity sealing refusal | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#696](https://github.com/openpacketcore/openpacketcore-sdk/issues/696) | feat(session-store): add atomic lease-fenced record transitions | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#683](https://github.com/openpacketcore/openpacketcore-sdk/issues/683) | feat(consensus): admit four-mebibyte protected session values end-to-end | Open; carried into #1172, durable stream. |
| [#657](https://github.com/openpacketcore/openpacketcore-sdk/issues/657) | feat(session-store): fence cloned fixed-voter process incarnations | Open; carried into #1172, durable stream. |
| [#741](https://github.com/openpacketcore/openpacketcore-sdk/issues/741) | perf(session-store): close the fixed two-snapshot 1,000 ops/s qualification gap | Open; carried into #1172, durable stream. |
| [#923](https://github.com/openpacketcore/openpacketcore-sdk/issues/923) | test(testkit): investigate hosted Durable batch receipt failures | Open; carried into #1172, flaky test stream. |
| [#856](https://github.com/openpacketcore/openpacketcore-sdk/issues/856) | test(session-net): investigate five-minute fenced-status compaction timeout | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#842](https://github.com/openpacketcore/openpacketcore-sdk/issues/842) | test(session-net): investigate extra connection in terminal watch conformance | Open; carried into #1172, flaky test stream. |
| [#838](https://github.com/openpacketcore/openpacketcore-sdk/issues/838) | test(session-net): investigate protected transition exceeding 100 ms budget | Open; carried into #1172, durable stream. |
| [#831](https://github.com/openpacketcore/openpacketcore-sdk/issues/831) | test(session-testkit): preserve bounded Git reads across interruptions | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#824](https://github.com/openpacketcore/openpacketcore-sdk/issues/824) | test(testkit): handle exact ambiguous outcomes in paired authority fixture | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#820](https://github.com/openpacketcore/openpacketcore-sdk/issues/820) | Investigate survivor interruption budget failure during five-process mTLS replacement readiness | Open; carried into #1172, flaky test stream. |
| [#723](https://github.com/openpacketcore/openpacketcore-sdk/issues/723) | qualification_mtls_multiprocess fixed fault-outcome bound fails on current main | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#695](https://github.com/openpacketcore/openpacketcore-sdk/issues/695) | feat(session-net): add bounded persistent least-authority consumer transport | Open; carried into #1172, durable stream. |
| [#578](https://github.com/openpacketcore/openpacketcore-sdk/issues/578) | test: replace yield_now spin-waits, two of which hang under a paused clock | Open; carried into #1172, flaky test stream. |
| [#576](https://github.com/openpacketcore/openpacketcore-sdk/issues/576) | test(session-net): lib suite flakes ~12% on a shared process-global metrics counter | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#566](https://github.com/openpacketcore/openpacketcore-sdk/issues/566) | test(session-net): mtls_backend_deadlines flakes under workspace-level runtime oversubscription | Closed as completed on 2026-10-08; closure evidence remains in the linked issue. |
| [#954](https://github.com/openpacketcore/openpacketcore-sdk/issues/954) | feat(gtpu-dataplane): authorize retained namespace replacement after control-root loss | Open; carried into #1172, other stream. |
| [#863](https://github.com/openpacketcore/openpacketcore-sdk/issues/863) | test(ipsec-lb): investigate encrypted SQLite retirement replay failure after adapter restart | Open; carried into #1172, flaky test stream. |
| [#821](https://github.com/openpacketcore/openpacketcore-sdk/issues/821) | test(gtpu-dataplane): investigate fixed one-second selector deadline miss | Open; carried into #1172, durable stream. |
| [#730](https://github.com/openpacketcore/openpacketcore-sdk/issues/730) | P0: shared-default TFT drops fragmented IMS ESP after 401 challenge | Open; carried into #1172, other stream. |
| [#720](https://github.com/openpacketcore/openpacketcore-sdk/issues/720) | feat(gtpu-dataplane): scale production traffic-proof subsystem for large pools | Open; carried into #1172, other stream. |
| [#687](https://github.com/openpacketcore/openpacketcore-sdk/issues/687) | feat(proto-gtpv2c): allow finite S2b response F-TEID receive policy | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#671](https://github.com/openpacketcore/openpacketcore-sdk/issues/671) | feat(gtpu-dataplane): publish external selector adapter stamp codec | Open; carried into #1172, other stream. |
| [#663](https://github.com/openpacketcore/openpacketcore-sdk/issues/663) | feat(gtpu-dataplane): support mixed selector provenance and same-group republish | Open; carried into #1172, other stream. |
| [#587](https://github.com/openpacketcore/openpacketcore-sdk/issues/587) | proto-gtpv2c: make malformed adopted PCO container policy explicit | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#580](https://github.com/openpacketcore/openpacketcore-sdk/issues/580) | test(ipsec-lb): redirect::transport tests are wall-clock flaky, ~50% under load | Closed as completed on 2026-10-04; closure evidence remains in the linked issue. |
| [#577](https://github.com/openpacketcore/openpacketcore-sdk/issues/577) | chore(gtpu-dataplane-ebpf): BPF object asserts GPL by omission, not by decision | Open; carried into #1172, other stream. |
| [#341](https://github.com/openpacketcore/openpacketcore-sdk/issues/341) | feat(proto-gtpu): remaining typed control procedures: IPv6 typed responses and outgoing Echo | Open; carried into #1172, IPv6 stream. |
| [#334](https://github.com/openpacketcore/openpacketcore-sdk/issues/334) | feat(crypto): add a coherent validated-provider and key-custody seam | Open; carried into #1172, other stream. |
| [#158](https://github.com/openpacketcore/openpacketcore-sdk/issues/158) | feat(session-net): support seamless certificate and trust-bundle rotation | Open; carried into #1172, durable stream. |
| [#164](https://github.com/openpacketcore/openpacketcore-sdk/issues/164) | test(session-net): qualify seamless TLS rotation for quorum fleets | Open; carried into #1172, durable stream. |
| [#143](https://github.com/openpacketcore/openpacketcore-sdk/issues/143) | test(session-store): qualify networked quorum HA for production | Open; carried into #1172, durable stream. |

## Historical pull requests

| PR | Disposition and remaining work |
| --- | --- |
| [#618](https://github.com/openpacketcore/openpacketcore-sdk/pull/618) | Merged as `a9618b4a9735b86e428c3019e7b1c6379f778b62`; #587 is closed. |
| [#622](https://github.com/openpacketcore/openpacketcore-sdk/pull/622) | [Applied through #1073](https://github.com/openpacketcore/openpacketcore-sdk/pull/622#issuecomment-5976495878) as `b85a00f8f29ec515f304d957e35d136f8861e9be`; the old PR is closed. #578 remains open for its remaining spin-wait work and is carried into #1172. |
| [#690](https://github.com/openpacketcore/openpacketcore-sdk/pull/690) | Remains open. Carry the explicit ELF-license change forward under #577, regenerate from current source, and complete artifact verification, review and current validation before landing. |
| [#692](https://github.com/openpacketcore/openpacketcore-sdk/pull/692) | [Applied through #1073](https://github.com/openpacketcore/openpacketcore-sdk/pull/692#issuecomment-5976496094) as `c1bb0f628477cc3ca376f08b6f2af86962945364`; the old PR and #576 are closed. |
| [#725](https://github.com/openpacketcore/openpacketcore-sdk/pull/725) | Remains open; tracked from #1172. Preserve the bounded-step contract; reconcile with #895, remove collection-sized cleanup under the operation lock, and obtain complete review and validation. Age alone does not establish supersession. |
| [#915](https://github.com/openpacketcore/openpacketcore-sdk/pull/915) | [Closed as superseded by #1055](https://github.com/openpacketcore/openpacketcore-sdk/pull/915#issuecomment-5959682535). |

## Continuing the backlog

#1172 owns the current issue ordering: flaky tests, other small issues, then medium issues. Large issues remain with their existing streams. Each original issue retains its full acceptance contract; configuration/audit, HA and rotation parents remain open until that full contract is proven. The two open historical PRs above retain their individual delivery and review obligations.
