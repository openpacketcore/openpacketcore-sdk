#!/usr/bin/env python3
"""Value-free Child-SA evidence references, independent of the catalog writer.

Authored obligations identify separately qualified tests. The complete-roster
state projection reuses the independent contract model, never a runtime trace.
No SDK, packet encoder, fixture writer or kernel operation is imported here.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crates/opc-n3iwf-fixtures/oracles/child-sa-profiles.json"
SCOPE = "installed-child-sa-evidence-reference"
PREFIX = "opc.n3iwf.xfrm-roster.v1.child-sa-"
SDK = dict(base="58acdfe9afc1cd0b5c7d2fc9a0d1f01bed4325d6",
           head="1c7012e6667a29f27d1100f3492dff5cc2c05d34",
           tree="1de2e42f567031052e26322d0f581b87993180b2")
NATIVE = "crates/opc-ipsec-xfrm/tests/xfrm_child_sa_roster_privileged.rs"
INSTALLED = "crates/opc-ipsec-xfrm/src/linux/tests/installed_child_sa_tests.rs"
GENERATION = "crates/opc-ipsec-xfrm/src/installed_child_sa.rs"
MOBIKE = "crates/opc-ipsec-xfrm/tests/support/mobike_roster.rs"
IKE = "crates/opc-proto-ikev2/tests/nwu_mobike.rs"
LINUX = "crates/opc-ipsec-xfrm/src/linux/tests/child_sa_relocation_tests.rs"
MODEL = "crates/opc-n3iwf-fixtures/oracles/child-sa-relocation.json"
DIGESTS = {
    NATIVE: "3f17f7d6e093efe2bffc20b0ca8088897ec257890e54dd423b6059a869146cb5",
    INSTALLED: "5ed23780ba18fde5ac5ce33d8cf1374d4b13f2ed3489fd35cb3b641536cb83d2",
    GENERATION: "96271504ffe32af5f174adda0568acc7b6f9e8819b07db36784d7ae00fbcd59d",
    MOBIKE: "15a65b8c1a62eb4247f907ab989fd20466bcd6fd057ea0e3dbc59a9c24531ec0",
    IKE: "c6a07453390b664ac74ac88d1c12d6a3c940956a786ae0554efcd5ad935108b4",
    LINUX: "2a6e01800f59f44b709d9a81e5026b523a3e8e1aa33caef5a89851a7aed493d5",
    MODEL: "f3d39a95e5fc6f4fb29e25d847d9a3901b6d300cb566ab2efefab4ce7a3994af",
}
MODEL_FAMILIES = ("complete", "mutation-before", "mutation-after", "read-before", "read-after",
                  "foreign-member", "missing-member", "mixed-members", "revoked")
RUNTIME_FAMILIES = ("installed-selection", "inbound-provenance", "publication-fencing",
                    "mobike-authority", "native-relocation", "process-recovery")
FAMILIES = tuple(sorted(RUNTIME_FAMILIES + tuple("relocation-" + name for name in MODEL_FAMILIES)))
AUTHORITY = dict(document="IETF RFC 4301, RFC 4303, RFC 4555 and bounded SDK profile",
                 release="Published RFCs",
                 clauses=["RFC 4301 4.4", "RFC 4303 3.3 and 3.4", "RFC 4555 3.3, 3.5, 4 and 5",
                          "SDK installed Child-SA and ordered relocation contracts"])


class Invalid(Exception):
    """Only bounded constant reasons cross this boundary."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def read_pinned(path):
    target = ROOT / path
    require(not target.is_symlink(), "child-sa-source-path")
    raw = target.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == DIGESTS[path], "child-sa-source-digest")
    return raw


def test_reference(path, functions):
    source = read_pinned(path).decode()
    require(all(source.count("fn " + name + "(") == 1 for name in functions), "child-sa-test-inventory")
    return dict(path=path, sha256=DIGESTS[path], functions=functions)


def obligations(family):
    cases = []
    def add(name, steps, expected, **facts):
        cases.append(dict(case=name, steps=steps.split(","), expected=expected, **facts))
    if family == "installed-selection":
        refs = [test_reference(NATIVE, ["installed_child_sa_roster_selects_exact_marked_spis_and_fences_replacement"])]
        for child in range(3):
            for flow in range(2):
                for direction in ("out", "in"):
                    add(f"{direction}-{child}-{flow}", "install-three-overlapping-children,publish,send,capture,receive",
                        "exact-child-spi-and-inner-delivery", child=child, flow=flow, direction=direction)
        add("default", "publish,select-explicit-default,send,capture,receive", "default-child-spi-and-delivery")
        add("rekey", "retain-both-incarnations,replace-outgoing-policy,publish,send,capture", "successor-selected;predecessor-receive-only")
        add("reinstall", "remove,identical-reinstall,select-old-publication", "old-publication-refused;no-counter-reuse-authority")
        add("foreign-policy", "foreign-template-write,select,restore-template,select-old-publication", "both-selections-refused")
    elif family == "inbound-provenance":
        refs = [test_reference(NATIVE, ["installed_child_sa_provenance_seals_exact_inbound_pair_and_publication"])]
        for child in range(3):
            for event in range(2):
                add(f"source-event-{child}-{event}", "register-exact-pair,independently-authenticate-esp,receive,poll",
                    "sealed-exact-pair-publication-and-source-event", child=child, event=event)
        for name, steps in (
            ("unknown-pair", "register-absent-child"),
            ("monitor-scope", "same-actor-and-publication,equal-raw-registration,other-monitor-poll"),
            ("foreign-actor", "other-actor-register,other-actor-poll"),
            ("icv", "change-authentication-octet,send,poll"),
            ("replay", "repeat-sequence,send,poll"),
            ("queued-old-publication", "queue-authenticated-event,rekey,poll-old,register-successor-on-old-monitor"),
        ):
            add(name, steps, "no-sealed-result")
        for incarnation in range(2):
            add(f"rekey-{incarnation}", "fresh-monitor,register-incarnation,authenticate,receive,poll", "exact-selected-or-receive-only-incarnation")
            add(f"teardown-{incarnation}", "teardown-registration,poll", "refused")
    elif family == "publication-fencing":
        names = [
            "whole_installed_roster_selects_signalling_two_overlapping_user_children_and_default",
            "every_policy_and_sa_readback_failure_prevents_any_prefix_publication",
            "failed_readback_retires_publication_and_cannot_revive_after_identical_reinstall",
            "stale_writer_wrong_actor_and_intervening_mutation_admit_no_reads",
            "overlap_keeps_both_sa_pairs_but_requires_one_concrete_outbound_policy",
            "malformed_rosters_and_ambiguous_outbound_policy_preferences_fail_before_io",
            "every_sa_requires_exact_transient_key_proof_and_cannot_accept_direction_substitution",
            "publication_drains_after_cancellation_at_every_read_and_requires_fresh_republication",
            "raw_linux_mock_and_unsupported_backends_report_precise_missing_profile",
        ]
        exhaustion = "exhausted_actor_generation_never_wraps_or_reissues_an_update_ticket"
        queries = ["every_individual_linux_query_failure_refuses_every_roster_prefix",
                   "relocation_readback_requires_exact_keys_direction_and_unique_target_for_every_sa"]
        refs = [test_reference(INSTALLED, names), test_reference(GENERATION, [exhaustion]), test_reference(LINUX, queries)]
        for name in names + [exhaustion] + queries:
            add(name, "construct-declared-profile,apply-test-fault,read-whole-roster", "exact-declared-outcome;no-prefix-authority")
    elif family == "mobike-authority":
        names = ["migration_permit_requires_exact_live_association_and_accepted_event_freshness",
                 "stale_migration_cannot_be_authorized_and_external_events_or_drop_revoke_permits",
                 "cross_association_authorization_and_cookie_failure_cannot_create_live_permits"]
        refs = [test_reference(IKE, names), test_reference(MOBIKE, ["live_authority_mismatch_revocation_and_caller_cancellation_never_publish"])]
        for name in names:
            add(name, "authenticated-update,cookie-proof,scope-or-event-transition,validate-permit", "exact-live-scope-only;bad-auth-and-replay-do-not-advance")
        for name in ("scope", "stale", "path", "mode", "revoked-prepared", "wrong-actor", "dropped-prepared", "cancelled-run"):
            add(name, "bind-roster,authenticate-update,apply-named-fault,attempt-move,reconcile-if-admitted", "no-delivered-publication;recovery-grants-no-live-authority")
    elif family == "native-relocation":
        refs = [test_reference(MOBIKE, ["authenticated_complete_roster_moves_preserve_replay_and_flow_selection"])]
        for profile in ("native-esp", "esp-in-udp"):
            add(profile, "independent-ike-authentication,packet-proof-before,complete-move,whole-readback,packet-proof-after,replay-and-icv-negatives",
                "seven-outgoing-flows;four-incoming-pairs;sequence-and-replay-continuity;inner-selectors-unchanged",
                packet_family="ipv4", pairs=4, outgoing_flows=7)
    else:
        require(family == "process-recovery", "child-sa-family")
        refs = [test_reference(MOBIKE, ["whole_roster_process_loss_at_every_kernel_prefix_recovers_without_publication"])]
        for profile in ("native-esp", "esp-in-udp"):
            for cut in range(16):
                add(f"{profile}-{cut}", "child-prepare,production-detector-cut,exit-without-drops,new-child,writer-refusal,wrong-intent-refusal,recover,repeat-recovery,fresh-publication",
                    "complete-exact-target;no-restored-live-authority", mutation_prefix=cut, processes=2,
                    inbound_policy_profile="shared", total_effects=15)
    return dict(kind="authored-runtime-test-obligations", references=refs, cases=cases)


def reference():
    model = json.loads(read_pinned(MODEL))
    require(model["scope"] == "complete-child-sa-roster-relocation" and len(model["cases"]) == 3364, "child-sa-model-shape")
    require({row[1] for row in model["cases"]} == set(MODEL_FAMILIES), "child-sa-model-families")
    families = {name: obligations(name) for name in RUNTIME_FAMILIES}
    for name in MODEL_FAMILIES:
        families["relocation-" + name] = dict(kind="independent-obligation-projection",
            references=[dict(path=MODEL, sha256=DIGESTS[MODEL], columns=model["columns"], corpus_cases=3364)],
            projection_columns=["source_case_index", "name", "outcome"],
            cases=[[index, row[0], row[-1]] for index, row in enumerate(model["cases"]) if row[1] == name])
    require(sum(len(v["cases"]) for v in families.values()) == 3453, "child-sa-case-inventory")
    return dict(schema_version=1, scope=SCOPE, public_sdk=SDK, execution_claim=False,
                external_interoperability=False, families={name: families[name] for name in FAMILIES})


def reference_bytes():
    return (json.dumps(reference(), separators=(",", ":")) + "\n").encode()


def wire(family):
    require(family in FAMILIES, "child-sa-family")
    return (json.dumps(dict(family=family, **reference()["families"][family]), sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(manifest, data):
    source = manifest["context"]["source_vector"]
    require(set(source) == {"path", "sha256", "case"} and source["path"] == SOURCE, "child-sa-path")
    require(source["sha256"] == hashlib.sha256(reference_bytes()).hexdigest(), "child-sa-digest")
    family = source["case"]
    require(family in FAMILIES and manifest["sdk_fixture_id"] == PREFIX + family, "child-sa-family")
    require(data == wire(family), "child-sa-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(data).hexdigest(), "child-sa-wire-digest")
    value = reference()["families"][family]
    expected = dict(source_vector=source, cases=len(value["cases"]), evidence_kind=value["kind"],
                    public_sdk=SDK, execution_claim=False, requires_separate_runtime_qualification=True,
                    grants_authority=False, external_interoperability=False)
    require(json.dumps(manifest["context"], sort_keys=True) == json.dumps(expected, sort_keys=True), "child-sa-context")
    require(manifest["encoding"] == "scenario-record" and manifest["validation_scope"] == SCOPE, "child-sa-scope")
    require(manifest["source"] == AUTHORITY, "child-sa-authority")
    require(manifest["semantic_assertions"] == ["family=" + family, "cases=" + str(len(value["cases"])),
            "execution_claim=false", "requires_separate_runtime_qualification=true", "grants_authority=false",
            "external_interoperability=false"], "child-sa-claims")
    require(manifest["direction"] == "local-backend" and manifest["role"] == "xfrm-backend", "child-sa-direction")
    provenance = manifest["provenance"]
    require(provenance["class"] == "referenced-public-vector" and provenance["synthetic"] is True
            and provenance["independent_capture"] is False and provenance["referenced_public_vector"] == SOURCE + "#" + family, "child-sa-provenance")
    require(manifest["expected_outcome"] == "constructed" and manifest["runtime_claim"] is False, "child-sa-outcome")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        target = ROOT / SOURCE
        require(not target.is_symlink(), "child-sa-path")
        if args.write:
            target.write_bytes(reference_bytes())
        else:
            require(target.read_bytes() == reference_bytes(), "child-sa-model")
            directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/xfrm-roster"
            observed = set()
            for path in directory.glob("child-sa-*.json"):
                require(not path.is_symlink(), "child-sa-path")
                manifest = json.loads(path.read_text())
                require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "child-sa-path")
                payload = directory / manifest["wire"]["path"]
                require(not payload.is_symlink(), "child-sa-path")
                validate(manifest, bytes.fromhex(payload.read_text()))
                require(manifest["sdk_fixture_id"] not in observed, "child-sa-duplicate")
                observed.add(manifest["sdk_fixture_id"])
            require(observed == {PREFIX + family for family in FAMILIES}, "child-sa-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_child_sa_profile_reference_mismatch")
        return 1
    print(f"n3iwf_child_sa_profile_reference_valid: {len(FAMILIES)} families, 3453 cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
