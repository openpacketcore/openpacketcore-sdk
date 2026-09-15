#!/usr/bin/env python3
"""Independent, deliberately narrow fixture oracles, never runtime codecs.

These checks do not import the writer. Protocol parsers stop at the published
envelope boundary. Scenario checks model caller preconditions, not cryptography,
kernel state, authenticated identity, or a completed exchange. NGAP and GTP-U
are exercised with the existing SDK codecs by tests/wire_codecs.rs instead.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/opc-n3iwf-fixtures/fixtures"


class Invalid(Exception):
    """Only constant, redaction-safe reason codes may cross this boundary."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def uint(data):
    return int.from_bytes(data, "big")


def eap(data, context):
    # TS 24.502 9.3: EAP Expanded framing, then AN TLVs and opaque NAS.
    require(len(data) >= 14, "truncated")
    require(uint(data[2:4]) == len(data), "outer-length")
    require(
        data[0] in (1, 2) and data[4:12] == bytes.fromhex("fe0028af00000003"), "vendor"
    )
    message = data[12]
    require(message in (1, 2, 3, 4), "message-id")
    if message in (1, 4):
        require(len(data) == 14, "body-length")
        return "accept"
    require(len(data) >= 16, "truncated")
    size = uint(data[14:16])
    require(size <= context["max_an_bytes"] and 16 + size <= len(data), "an-bound")
    an, offset, seen, unknown, duplicate = data[16 : 16 + size], 0, set(), False, False
    while offset < len(an):
        require(offset + 2 <= len(an), "an-bound")
        kind, length = an[offset : offset + 2]
        offset += 2
        require(offset + length <= len(an), "an-bound")
        if kind in (1, 2, 3, 4):
            duplicate |= kind in seen
            seen.add(kind)
            if kind == 2:
                require(length == 3, "plmn-length")
            if kind == 4:
                require(length == 1, "cause-length")
        else:
            unknown = True
        offset += length
    tail = data[16 + size :]
    if message == 2:
        require(len(tail) >= 2 and uint(tail[:2]) == len(tail) - 2, "nas-length")
    else:
        require(not tail, "body-length")
    return "caller-policy" if duplicate else "ignore" if unknown else "accept"


def ike(data, context):
    # RFC 7296 3.2/3.10/3.11; TS 24.502 9.2. No IKE header/SA state.
    kind, seen, duplicate = context["initial_payload_type"], set(), False
    while kind:
        require(len(data) >= 4, "truncated")
        next_kind, critical, length = data[0], data[1] & 128, uint(data[2:4])
        require(4 <= length <= len(data), "truncated")
        body, data = data[4:length], data[length:]
        if kind not in (41, 42):
            require(not critical, "unknown-critical")
        else:
            require(len(body) >= 4, "truncated")
            protocol, spi_size = body[:2]
            require(spi_size <= context["max_spi_bytes"], "spi-bound")
            if kind == 42:
                require(
                    protocol == 3
                    and spi_size == 4
                    and len(body) == 4 + 4 * uint(body[2:4]),
                    "delete",
                )
            else:
                notify = uint(body[2:4])
                duplicate |= notify in seen
                seen.add(notify)
                require(
                    (protocol, spi_size) == ((3, 4) if notify == 55508 else (0, 0)),
                    "spi-size",
                )
                payload = body[4 + spi_size :]
                require(len(body) >= 4 + spi_size, "spi-size")
                if notify in (55502, 55504, 16397):
                    require(
                        len(payload) == 4 and payload[:3] == bytes([192, 0, 2]),
                        "address",
                    )
                elif notify == 55506:
                    require(len(payload) == 2 and uint(payload) != 0, "port")
                elif notify == 55508:
                    require(not payload, "notify-data")
                elif notify == 55501:
                    require(
                        len(payload) >= 4 and payload[0] == len(payload) - 1,
                        "qos-length",
                    )
                    require(
                        len(payload) == 4 + payload[2] and 1 <= payload[1] <= 15,
                        "qos-count",
                    )
                    require(all(qfi <= 63 for qfi in payload[3:-1]), "qfi")
                else:
                    raise Invalid("notify-type")
        kind = next_kind
    require(not data, "trailing-payload")
    return "caller-policy" if duplicate else "accept"


def gre(data, context, encoding):
    if encoding == "construction-argument":
        require(len(data) == 1, "argument-size")
        require(data[0] <= context["max_qfi"], "qfi-bound")
        return "accept"
    require(len(data) >= 8, "truncated")
    # TS 24.502 9.3.3.1: spare receive bits and Protocol Type are ignored.
    require(uint(data[:2]) & 0xB007 == 0x2000, "flags")
    return "ignore" if uint(data[2:4]) else "accept"


def nas(data, context):
    # The stream stays open until explicitly finalized; NAS contents are opaque.
    while data:
        if len(data) < 2:
            require(context["stream_open"], "eof")
            return "need-more-data"
        size = uint(data[:2])
        require(
            context["min_payload_len"] <= size <= context["max_payload_len"],
            "length-bound",
        )
        if len(data) < 2 + size:
            require(context["stream_open"], "eof")
            return "need-more-data"
        data = data[2 + size :]
    return "accept"


def sctp_data(data, ppid):
    # RFC 4960 3.3.1: DATA includes nonempty user data; padding is not length.
    require(len(data) >= 17, "truncated")
    size = uint(data[2:4])
    require(data[0] == 0 and data[1] == 3 and size > 16, "data-header")
    require(len(data) == (size + 3) & ~3 and not any(data[size:]), "data-length")
    require(uint(data[12:16]) == ppid, "ppid")
    return data[16:size]


def sctp(data, context, encoding):
    if encoding == "protocol-wire":
        sctp_data(data, context["ppid"])
        return "accept"
    require(len(data) >= 6 and len(data) % 6 == 0, "tuple-length")
    tuples = []
    for offset in range(0, len(data), 6):
        item = data[offset : offset + 6]
        port, ppid = (
            (uint(item[:2]), uint(item[2:]))
            if context["layout"] == "port-ppid"
            else (uint(item[4:]), uint(item[:4]))
        )
        require(0 < port <= context["max_port"], "port-bound")
        if ppid != context["ppid"]:
            return "unsupported"
        tuples.append((port, ppid))
    return "caller-policy" if len(set(tuples)) != len(tuples) else "accept"


def dtls_record(data, context):
    # Only isolated unencrypted DTLS 1.2 ServerHelloDone, RFC 6347 4.2.2.
    require(len(data) >= 13, "truncated")
    require(data[:3] == bytes.fromhex("16fefd"), "version")
    size = uint(data[11:13])
    require(size <= context["max_record_payload"], "record-bound")
    require(len(data) == 13 + size and size >= 12, "record-length")
    message = data[13:]
    require(message[0] == 14 and uint(message[1:4]) == 0, "handshake-body")
    require(
        uint(message[6:9]) == 0 and uint(message[9:12]) == 0 and len(message) == 12,
        "fragment",
    )


def dtls(data, context, encoding, scope):
    require(context["delivery_policy"] == "reliable-ordered", "delivery-policy")
    if encoding == "protocol-wire":
        if scope == "sctp-data-chunk":
            data = sctp_data(data, context["ppid"])
        dtls_record(data, context)
    elif encoding == "metadata-record":
        require(len(data) >= 4, "truncated")
        if uint(data[:4]) != 66:
            return "unsupported"
        if len(data) == 8 and data[:4] == data[4:]:
            return "caller-policy"
        if len(data) > 4:
            dtls_record(data[4:], context)
    else:
        require(
            len(data) <= context["max_label_bytes"] and data.startswith(b"opc-n3iwf-"),
            "label",
        )
        require(context["identity_verified"], "identity")
        require(context["exporter_length"] == 64, "exporter-length")
        old = context["old_auth_key_id"]
        require(
            1 <= old <= 65535 and context["new_auth_key_id"] == old % 65535 + 1,
            "key-id",
        )
        require(
            context["switch_auth_key_before_finished"]
            and context["retire_old_key_after_ack"],
            "key-order",
        )
        if data.endswith(b"error-redacted"):
            raise Invalid("redacted-error")
    return "accept"


def key(data, context):
    require(len(data) <= context["max_label_bytes"], "label-bound")
    require(
        data.isascii() and data.startswith(b"opc-n3iwf-protocol-key-kat-v1-"), "label"
    )
    require(context["purpose"] == "K_N3IWF", "purpose")
    state = "unbound"
    for action in context["actions"]:
        if action == "bind":
            require(state == "unbound", "reuse")
            state = "bound"
        elif action == "consume":
            require(
                context["requested_generation"] == context["bound_generation"],
                "generation",
            )
            require(state == "bound", "cancelled" if state == "cancelled" else "reuse")
            state = "consumed"
        elif action in ("drop", "cancel"):
            require(state == "bound", "reuse")
            state = "zeroized" if action == "drop" else "cancelled"
        else:
            raise Invalid("action")
    require(state == context["expected_state"], "state")
    return "accept"


def roster(data, context):
    require(len(data) >= 12 and len(data) % 12 == 0, "record-length")
    generations, inbound = [], set()
    for offset in range(0, len(data), 12):
        item = data[offset : offset + 12]
        require(item[0] == 1, "version")
        generation, spi_in, spi_out = uint(item[1:4]), uint(item[4:8]), uint(item[8:12])
        require(0 < generation <= context["max_generation"], "generation-bound")
        require(spi_in and spi_out and spi_in not in inbound, "duplicate-spi")
        inbound.add(spi_in)
        generations.append(generation)
    require(context["inbound_provenance_valid"], "provenance")
    require(generations == sorted(set(generations)), "generation-order")
    if context["old_pair_retained"]:
        require(len(generations) >= 2, "overlap")
    if context["operation"] == "relocate":
        require(context["relocation_authorized"], "relocation-authority")
    return "accept"


REJECTIONS = {
    "eap5g": {
        "bounded-an-parameter-overflow": "an-bound",
        "malformed-length": "outer-length",
        "truncated-start": "truncated",
        "unknown-message-id": "message-id",
    },
    "nwu-ike": {
        "bounded-spi-size-overflow": "spi-bound",
        "malformed-spi-size": "spi-size",
        "truncated-nas-ip4": "truncated",
        "unknown-critical-payload": "unknown-critical",
    },
    "gre-qfi": {
        "bounded-qfi-overflow": "qfi-bound",
        "malformed-missing-key": "flags",
        "truncated-key": "truncated",
    },
    "nas-tcp": {
        "bounded-length-overflow": "length-bound",
        "malformed-zero-length": "length-bound",
        "eof-loss-incomplete-frame": "eof",
    },
    "n2-sctp": {
        "bounded-port-overflow": "port-bound",
        "malformed-missing-port": "tuple-length",
        "truncated-ppid": "tuple-length",
    },
    "n2-dtls": {
        "bounded-record-overflow": "record-bound",
        "malformed-tls-version": "version",
        "truncated-record": "truncated",
        "redacted-error": "redacted-error",
    },
    "protocol-key": {
        "bounded-label-overflow": "label-bound",
        "malformed-label": "label",
        "truncated-label": "label",
        "unknown-purpose": "purpose",
        "wrong-generation": "generation",
        "reuse-after-consume": "reuse",
        "cancellation": "cancelled",
    },
    "xfrm-roster": {
        "bounded-generation-overflow": "generation-bound",
        "duplicate-spi": "duplicate-spi",
        "malformed-version": "version",
        "truncated-record": "record-length",
        "unknown-inbound-spi": "provenance",
    },
}


def observe(manifest, data):
    subset, context = manifest["subset"], manifest["context"]
    try:
        if subset == "gre-qfi":
            outcome = gre(data, context, manifest["encoding"])
        elif subset == "n2-sctp":
            outcome = sctp(data, context, manifest["encoding"])
        elif subset == "n2-dtls":
            outcome = dtls(
                data, context, manifest["encoding"], manifest["validation_scope"]
            )
        else:
            outcome = {
                "eap5g": eap,
                "nwu-ike": ike,
                "nas-tcp": nas,
                "protocol-key": key,
                "xfrm-roster": roster,
            }[subset](data, context)
        return outcome, None
    except Invalid as error:
        return "reject", str(error)


def validate(manifest, data):
    name = manifest["sdk_fixture_id"].split(".v1.")[1]
    outcome, reason = observe(manifest, data)
    expected = manifest["expected_outcome"]
    require(
        outcome == ("accept" if expected in ("receive", "constructed") else expected),
        "outcome-mismatch",
    )
    require(reason == REJECTIONS[manifest["subset"]].get(name), "reason-mismatch")
    if outcome != "reject":
        verify_field_claims(manifest, data)


def verify_field_claims(manifest, data):
    """Check named wire facts as well as disposition; opaque prose is not proof."""
    claims = dict(
        item.split("=", 1) for item in manifest["semantic_assertions"] if "=" in item
    )

    def number(name, value):
        if name in claims:
            require(int(claims[name], 0) == value, "field-claim")

    def label(name, value):
        if name in claims:
            require(claims[name] == value, "field-claim")

    subset = manifest["subset"]
    if subset == "eap5g":
        number("message_id", data[12])
        number("expanded_type", data[4])
        number("vendor_id", uint(data[5:8]))
        number("vendor_type", uint(data[8:12]))
        label("eap_code", "request" if data[0] == 1 else "response")
        if data[12] in (2, 3):
            number("an_parameters_len", uint(data[14:16]))
    elif subset == "gre-qfi" and manifest["encoding"] == "protocol-wire":
        number("qfi", data[4] & 63)
        number("rqi", data[7] >> 7)
        number("protocol_type", uint(data[2:4]))
        for name, mask in (("c", 128), ("k", 32), ("s", 16)):
            number(name, int(bool(data[0] & mask)))
    elif subset == "nas-tcp" and len(data) >= 2:
        number("length", uint(data[:2]))
    elif subset == "nwu-ike":
        kind, notifies = manifest["context"]["initial_payload_type"], []
        while kind:
            size = uint(data[2:4])
            payload = data[:size]
            if kind == 41:
                notify = uint(payload[6:8])
                notifies.append(notify)
                number("spi_size", payload[5])
                if notify == 55508:
                    number("up_sa_spi_size", payload[5])
                number("protocol_id", payload[4])
                if notify == 55501:
                    number("pdu_session", payload[9])
                    number("qfi", payload[11] & 63)
                    number("dcsi", (payload[-1] >> 1) & 1)
                if notify == 55506:
                    number("port", uint(payload[8:10]))
            else:
                number("spi_count", uint(payload[6:8]))
                label("protocol", "ESP" if payload[4] == 3 else "unsupported")
            kind, data = payload[0], data[size:]
        if len(notifies) == 1:
            number("notify_type", notifies[0])
        label("notify_types", ",".join(map(str, notifies)))
    elif subset == "xfrm-roster":
        number("generation", uint(data[1:4]))
        label("overlap", "true" if len(data) > 12 else "false")
    elif subset == "n2-dtls" and manifest["validation_scope"] == "dtls-record":
        number("record_length", uint(data[11:13]))
        number("fragment_length", uint(data[22:25]))
        label(
            "handshake_type", "server_hello_done" if data[13] == 14 else "unsupported"
        )


def main():
    count = 0
    try:
        for subset in REJECTIONS:
            for path in sorted((FIXTURES / subset).glob("*.json")):
                if path.name == "COMPLETION.json":
                    continue
                manifest = json.loads(path.read_text())
                validate(
                    manifest,
                    bytes.fromhex((path.parent / manifest["wire"]["path"]).read_text()),
                )
                count += 1
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_fixture_semantic_mismatch", file=sys.stderr)
        return 1
    print(f"n3iwf_fixture_oracles_valid: {count} envelopes and scenarios")
    return 0


if __name__ == "__main__":
    sys.exit(main())
