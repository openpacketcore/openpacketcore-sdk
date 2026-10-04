#!/usr/bin/env python3
"""Independent Release 18 PDU Resource Notify transfer and session-list vectors."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference

NOTIFY = "PDUSessionResourceNotifyTransfer"
RELEASED = "PDUSessionResourceNotifyReleasedTransfer"
NOTIFY_LIST = "PDUSessionResourceNotifyList"
RELEASED_LIST = "PDUSessionResourceReleasedListNot"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases, causes, labels = [], [], {}
    with tempfile.TemporaryDirectory(prefix="ngap-notify-reference-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        for group, typ in (
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ):
            enum = getattr(ref.schema.NGAP_IEs, typ)
            for label in enum._root:
                code = enum._cont[label]
                labels[group, code] = label
                causes.append(dict(group=group, code=code))
        states = ref.schema.NGAP_IEs.NotificationCause._root
        assert len(states) == 2

        def cause(value):
            return value["group"], labels[value["group"], value["code"]]

        def notified(model):
            value = {}
            if model["notified"]:
                value["qosFlowNotifyList"] = [
                    dict(
                        qosFlowIdentifier=v["qfi"],
                        notificationCause=states[0 if v["fulfilled"] else 1],
                    )
                    for v in model["notified"]
                ]
            if model["released"]:
                value["qosFlowReleasedList"] = [
                    dict(qosFlowIdentifier=v["qfi"], cause=cause(v["cause"]))
                    for v in model["released"]
                ]
            return value

        def value_for(kind, model):
            if kind == NOTIFY:
                return notified(model)
            if kind == RELEASED:
                return dict(cause=cause(model))
            if kind == NOTIFY_LIST:
                return [
                    dict(
                        pDUSessionID=v["id"],
                        pDUSessionResourceNotifyTransfer=(
                            NOTIFY,
                            notified(v["transfer"]),
                        ),
                    )
                    for v in model
                ]
            return [
                dict(
                    pDUSessionID=v["id"],
                    pDUSessionResourceNotifyReleasedTransfer=(
                        RELEASED,
                        dict(cause=cause(v["cause"])),
                    ),
                )
                for v in model
            ]

        transfer_cache = {}

        def transfer_wire(kind, model):
            key = kind, json.dumps(model, sort_keys=True)
            if key not in transfer_cache:
                target = getattr(ref.schema.NGAP_IEs, kind)
                value = value_for(kind, model)
                target.set_val(copy.deepcopy(value))
                wire = target.to_aper_ws()
                assert target.to_aper() == wire
                target.from_aper_ws(wire)
                assert target.get_val() == value
                transfer_cache[key] = wire.hex()
            return transfer_cache[key]

        def emit(kind, name, model, admitted=True):
            target = getattr(ref.schema.NGAP_IEs, kind)
            value = value_for(kind, model)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire, (name, "plain encoder")
            target.from_aper_ws(wire)
            assert target.get_val() == value, (name, "decoded values")
            assert target.to_aper_ws() == wire, (name, "structured encoder")
            cases.append(
                dict(
                    name=name,
                    type=kind,
                    model=model,
                    admitted=admitted,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )
            if kind in (NOTIFY_LIST, RELEASED_LIST):
                cases[-1]["transfer_wires"] = [
                    transfer_wire(
                        NOTIFY if kind == NOTIFY_LIST else RELEASED,
                        v["transfer"] if kind == NOTIFY_LIST else v["cause"],
                    )
                    for v in model
                ]

        def notification(qfi, fulfilled):
            return dict(qfi=qfi, fulfilled=fulfilled)

        def release(qfi, index):
            return dict(qfi=qfi, cause=causes[index % len(causes)])

        for count in range(1, 65):
            emit(
                NOTIFY,
                f"notified-count-{count}",
                dict(
                    notified=[notification(i, i % 2 == 0) for i in range(count)],
                    released=[],
                ),
            )
            emit(
                NOTIFY,
                f"released-flow-count-{count}",
                dict(notified=[], released=[release(i, i) for i in range(count)]),
            )
        for split in range(1, 64):
            emit(
                NOTIFY,
                f"mixed-{split}",
                dict(
                    notified=[notification(i, i % 2 == 0) for i in range(split)],
                    released=[release(i, i) for i in range(split, 64)],
                ),
            )
        for qfi in range(64):
            for fulfilled in [False, True]:
                emit(
                    NOTIFY,
                    f"state-{qfi}-{fulfilled}",
                    dict(notified=[notification(qfi, fulfilled)], released=[]),
                )
        for index, item in enumerate(causes):
            emit(RELEASED, f"session-cause-{index}", item)
            emit(
                NOTIFY,
                f"flow-cause-{index}",
                dict(notified=[], released=[release(23, index)]),
            )
        emit(NOTIFY, "empty-transfer", dict(notified=[], released=[]), False)
        emit(
            NOTIFY,
            "duplicate-notification",
            dict(notified=[notification(1, True), notification(1, False)], released=[]),
            False,
        )
        emit(
            NOTIFY,
            "duplicate-flow-release",
            dict(notified=[], released=[release(1, 0), release(1, 1)]),
            False,
        )
        emit(
            NOTIFY,
            "overlap-flow",
            dict(notified=[notification(1, True)], released=[release(1, 0)]),
            False,
        )
        variants = [
            dict(notified=[notification(7, True)], released=[]),
            dict(notified=[], released=[release(63, 0)]),
            dict(notified=[notification(0, False)], released=[release(1, 63)]),
        ]
        for count in range(1, 257):
            emit(
                NOTIFY_LIST,
                f"notified-sessions-{count}",
                [dict(id=i, transfer=variants[i % 3]) for i in range(count)],
            )
            emit(
                RELEASED_LIST,
                f"released-sessions-{count}",
                [dict(id=i, cause=causes[i % len(causes)]) for i in range(count)],
            )
        maximum = dict(notified=[], released=[release(i, 0) for i in range(64)])
        emit(NOTIFY, "maximum-cause-width", maximum)
        for count in [1, 2, 64, 256]:
            emit(
                NOTIFY_LIST,
                f"maximum-flows-{count}",
                [dict(id=i, transfer=maximum) for i in range(count)],
            )
        emit(
            NOTIFY_LIST,
            "duplicate-notified-session",
            [dict(id=7, transfer=variants[0]), dict(id=7, transfer=variants[1])],
            False,
        )
        emit(
            RELEASED_LIST,
            "duplicate-released-session",
            [dict(id=7, cause=causes[0]), dict(id=7, cause=causes[1])],
            False,
        )
        emit(
            NOTIFY_LIST,
            "empty-nested-transfer",
            [dict(id=7, transfer=dict(notified=[], released=[]))],
            False,
        )
    result = dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS, cases=cases)
    # Keep exhaustive list models compact while retaining independent nested
    # transfer bytes for generated-code probes and typed list comparisons.
    rendered = json.dumps(result, indent=2)
    for case in cases:
        model = case["model"]
        if isinstance(model, list):
            expanded = json.dumps(model, indent=2).replace("\n", "\n      ")
            rendered = rendered.replace(
                '"model": ' + expanded, '"model": ' + json.dumps(model), 1
            )
    assert json.loads(rendered) == result
    args.output.write_text(rendered + "\n")
    print(
        f"Wrote {len(cases)} field cases; {sum(v['admitted'] for v in cases)} admitted"
    )


if __name__ == "__main__":
    main()
