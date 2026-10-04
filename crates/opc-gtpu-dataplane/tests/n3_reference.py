#!/usr/bin/env python3
"""Independent, synthetic N3 packet vectors; no SDK codec/catalog imports.

Wire authority: TS 29.281 V18.4.0 sections 5.1, 5.2.1, 5.2.2.7 and
TS 38.415 V18.2.0 sections 5.5.2, 5.5.3.1-7. The refusal of an empty
T-PDU is the SDK forwarding-input policy, not generic GTP-U conformance.
This authors packet bytes independently; it is not a live peer oracle.
"""

import argparse
import hashlib
from pathlib import Path

TARGET = Path(__file__).with_name("n3_reference.tsv")
PAYLOAD = bytes.fromhex("aabbcc")  # Opaque synthetic data, not an IP packet.
TEID = bytes.fromhex("11223344")


def psc(direction, qfi, rqi=False, ppi=None):
    """TS 38.415 base frames; extension lengths include length/next octets."""
    assert 0 <= qfi <= 63
    if direction == "ul":
        assert not rqi and ppi is None
        return bytes([1, 0x10, qfi, 0])
    assert direction == "dl" and (ppi is None or 0 <= ppi <= 7)
    qos = qfi + 64 * rqi + 128 * (ppi is not None)
    if ppi is None:
        return bytes([1, 0, qos, 0])
    return bytes([2, 0, qos, ppi, 0, 0, 0, 0])


def packet(extensions, payload=PAYLOAD, flags=0x34, message_type=255):
    """Encode authored extension links and the mandatory/optional headers."""
    chain = bytearray()
    for index, (_, wire) in enumerate(extensions):
        following = extensions[index + 1][0] if index + 1 < len(extensions) else 0
        chain.extend(wire[:-1] + bytes([following]))
    optional = bytes([0x12, 0x34, 0x56, extensions[0][0] if extensions else 0])
    body = optional + chain + payload
    return bytes([flags, message_type]) + len(body).to_bytes(2, "big") + TEID + body


def rows():
    result = []

    def add(name, direction, wire, accepted=False, qfi=9, rqi=False, ppi=None, payload=PAYLOAD):
        result.append((name, direction, "accept" if accepted else "reject",
                       str(qfi), str(int(rqi)), "-" if ppi is None else str(ppi),
                       payload.hex() or "-", wire.hex() or "-"))

    # All 64 QFIs, both downlink RQI values and all absent/present PPIs.
    for qfi in range(64):
        add(f"ul-{qfi}", "ul", packet([(0x85, psc("ul", qfi))]), True, qfi)
        for rqi in (False, True):
            for ppi in (None, *range(8)):
                add(f"dl-{qfi}-{int(rqi)}-{ppi}", "dl",
                    packet([(0x85, psc("dl", qfi, rqi, ppi))]), True, qfi, rqi, ppi)

    base = packet([(0x85, psc("dl", 9))])
    for flags in range(256):
        wire = bytes([flags]) + base[1:]
        # Version 1, PT=1 and E=1; S, PN and reserved are independent.
        add(f"flags-{flags}", "dl", wire, (flags & 0xF4) == 0x34)
    for message_type in range(255):
        add(f"control-{message_type}", "dl", base[:1] + bytes([message_type]) + base[2:])
    for declared in range(256):
        wire = base[:2] + declared.to_bytes(2, "big") + base[4:]
        add(f"declared-{declared}", "dl", wire, declared == len(base) - 8)

    # PSC need not be first on reception. Required unknowns are endpoint
    # refusals, even when a caller requests Preserve or Drop semantics.
    for ext_type in range(1, 256):
        if ext_type == 0x85:
            continue
        optional = (ext_type, bytes([1, 0x12, 0x34, 0]))
        qos = (0x85, psc("dl", 9))
        for position, chain in (("before", [optional, qos]), ("after", [qos, optional])):
            add(f"extension-{ext_type}-{position}", "dl", packet(chain), ext_type < 128)

    for direction in ("ul", "dl"):
        qos = psc(direction, 9)
        wire = packet([(0x85, qos)])
        add(f"direction-{direction}", "dl" if direction == "ul" else "ul", wire)
        add(f"duplicate-{direction}", direction, packet([(0x85, qos), (0x85, qos)]))
        add(f"empty-{direction}", direction, packet([(0x85, qos)], payload=b""))
        add(f"zero-teid-{direction}", direction, wire[:4] + bytes(4) + wire[8:])
        for size in range(len(wire)):
            add(f"prefix-{direction}-{size}", direction, wire[:size])
        for tail in (b"\x00", wire):
            add(f"trailing-{direction}-{len(tail)}", direction, wire + tail)
        for length in (0, 2, 255):
            add(f"psc-length-{direction}-{length}", direction,
                wire[:12] + bytes([length]) + wire[13:])
    add("missing-psc", "dl", packet([]))
    for pdu_type in range(2, 16):
        add(f"reserved-pdu-type-{pdu_type}", "dl", packet([(0x85, bytes([1, pdu_type << 4, 9, 0]))]))
    for bit in (1, 2, 3):
        add(f"dl-conditional-{bit}", "dl", packet([(0x85, bytes([1, 1 << bit, 9, 0]))]))
    for bit in range(4):
        add(f"ul-conditional-first-{bit}", "ul", packet([(0x85, bytes([1, 0x10 | (1 << bit), 9, 0]))]))
    for bit in (6, 7):
        add(f"ul-conditional-second-{bit}", "ul", packet([(0x85, bytes([1, 0x10, 9 | (1 << bit), 0]))]))
    add("ppi-missing", "dl", packet([(0x85, bytes([1, 0, 0x89, 0]))]))
    # Spare DL bits and padding are not interpreted by the receiver.
    for spare in range(32):
        wire = bytes([2, 1, 0xC9, (spare << 3) | 7, 0xA1, 0xB2, 0xC3, 0])
        add(f"dl-spares-{spare}", "dl", packet([(0x85, wire)]), True, 9, True, 7)
    assert len({row[0] for row in result}) == len(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    cases = rows()
    data = ("# case\tdirection\tresult\tqfi\trqi\tppi\tpayload_hex\twire_hex\n" +
            "".join("\t".join(row) + "\n" for row in cases)).encode()
    if args.check:
        if not TARGET.exists() or TARGET.read_bytes() != data:
            raise SystemExit("N3 reference vectors differ; regenerate and review")
    else:
        TARGET.write_bytes(data)
    accepted = sum(row[2] == "accept" for row in cases)
    print(f"{len(cases)} cases; {accepted} accepted; {len(cases) - accepted} rejected; sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
