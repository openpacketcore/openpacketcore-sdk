#!/usr/bin/env python3
"""Generate the committed seed corpus for opc-proto-diameter fuzz targets.

Every seed file produced by this script is written directly under
fuzz/corpus/<target>/ so that `cargo fuzz run <target>` seeds from it.
No seed lives only in a provenance/documentation directory.

The spec-valid fixtures are hand-authored from the wire layouts in:
  - IETF RFC 6733 section 3 (message header) and section 4 (AVP framing)
  - 3GPP TS 32.299 (Rf offline charging PS-Information vendor AVPs)
  - 3GPP TS 29.273 (SWm Diameter-EAP command and AVP codes)

The malformed fixtures exercise the hostile-input paths that the decode
surface must never panic on: truncation, invalid lengths, duplicate
mandatory AVPs, grouped depth bombs, bad padding, and reserved flag bits.
"""

import hashlib
import os
import struct


def write_corpus(directory: str, data: bytes, name: str) -> None:
    os.makedirs(directory, exist_ok=True)
    digest = hashlib.sha1(data).hexdigest()
    path = os.path.join(directory, f"{name}-{digest}")
    with open(path, "wb") as f:
        f.write(data)


def avp(code: int, flags: int, value: bytes, vendor: int | None = None) -> bytes:
    """Encode one Diameter AVP (RFC 6733 section 4).

    Octet layout (non-vendor, 8-octet header):
      0-3   AVP Code (RFC 6733 §4)
      4     AVP Flags (V/M/P/r/r/r/r/r per RFC 6733 §4)
      5-7   24-bit AVP Length including header and AVP data; padding is excluded
        from the length field and follows the AVP Data (RFC 6733 §4)
      8+    AVP Data
      tail  0-3 octets of zero padding to 4-octet boundary (RFC 6733 §4)

    Octet layout (vendor-specific, 12-octet header):
      0-3   AVP Code
      4     AVP Flags (V bit set)
      5-7   24-bit AVP Length (header + vendor-id + AVP data; padding excluded)
      8-11  Vendor-Id (RFC 6733 §4.3.2)
      12+   AVP Data + padding
    """
    has_vendor = vendor is not None
    if flags & 0x1F:
        raise ValueError("AVP reserved flag bits (0x1F) must be zero")
    v_bit_set = (flags & 0x80) != 0
    if has_vendor and not v_bit_set:
        raise ValueError("vendor provided but V bit (0x80) is not set in flags")
    if not has_vendor and v_bit_set:
        raise ValueError("V bit (0x80) set in flags but no vendor provided")
    header_len = 12 if has_vendor else 8
    length = header_len + len(value)
    body = struct.pack(">I", code)          # octets 0-3: AVP Code
    body += struct.pack("B", flags)         # octet 4: AVP Flags
    body += struct.pack(">I", length)[1:]  # octets 5-7: 24-bit length
    if vendor is not None:
        body += struct.pack(">I", vendor)   # octets 8-11: Vendor-Id
    body += value                           # AVP Data
    # Pad to 4-octet boundary (RFC 6733 §4).
    pad = (4 - (length % 4)) % 4
    body += b"\x00" * pad
    return body


def header(
    flags: int,
    command_code: int,
    application_id: int,
    hop_by_hop: int,
    end_to_end: int,
    avp_bytes: bytes,
) -> bytes:
    """Encode a Diameter message header (RFC 6733 section 3).

    Octet layout (20-octet fixed header):
      0     Version (1) (RFC 6733 §3)
      1-3   24-bit Message Length including header + AVPs (RFC 6733 §3)
      4     Command Flags (R/P/E/T/r/r/r/r per RFC 6733 §3)
      5-7   24-bit Command Code (RFC 6733 §3)
      8-11  Application-Id (RFC 6733 §3)
      12-15 Hop-by-Hop Identifier (RFC 6733 §3)
      16-19 End-to-End Identifier (RFC 6733 §3)
      20+   AVP region
    """
    length = 20 + len(avp_bytes)
    msg = b"\x01"                           # octet 0: version
    msg += struct.pack(">I", length)[1:]   # octets 1-3: 24-bit length
    msg += struct.pack("B", flags)          # octet 4: command flags
    msg += struct.pack(">I", command_code)[1:]  # octets 5-7: 24-bit command code
    msg += struct.pack(">I", application_id)    # octets 8-11: application-id
    msg += struct.pack(">I", hop_by_hop)        # octets 12-15: hop-by-hop
    msg += struct.pack(">I", end_to_end)        # octets 16-19: end-to-end
    msg += avp_bytes
    return msg


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def self_test_avp_flag_validation() -> None:
    """Assert corpus helper flag validation fails closed for reserved bits."""
    avp(264, 0x40, b"x", None)
    avp(874, 0xC0, b"x", vendor=10415)
    for flags, vendor in ((0x41, None), (0x9F, 10415)):
        try:
            avp(264, flags, b"x", vendor)
        except ValueError as exc:
            if "reserved flag bits" not in str(exc):
                raise AssertionError(
                    f"unexpected error for reserved AVP flags 0x{flags:02x}: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"reserved AVP flags 0x{flags:02x} were accepted by corpus helper"
            )


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # -------------------------------------------------------------------------
    # Seed corpus for decode_message
    # -------------------------------------------------------------------------
    msg_dir = os.path.join(base_dir, "corpus", "decode_message")

    # 1. Header-only message (no AVPs). RFC 6733 section 3.
    write_corpus(
        msg_dir,
        header(0x80, 257, 0, 0x01020304, 0xA0B0C0D0, b""),
        "header_only_cer",
    )

    # 2. Capabilities-Exchange-Request (CER) with Origin-Host, Origin-Realm,
    #    Host-IP-Address, Vendor-Id, Product-Name, Auth-Application-Id.
    #    Command code 257, request flag set. RFC 6733 section 5.3.1.
    cer_avps = b""
    # Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    cer_avps += avp(264, 0x40, b"aaa.example", None)
    # Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    cer_avps += avp(296, 0x40, b"example", None)
    # Host-IP-Address AVP (code 257, M), AddressType 1 (IPv4) + 10.0.0.1.
    # Address format: first two octets are address-family 1 for IPv4 (RFC 6733 §4.3.3),
    # followed by the four octets of the IPv4 address. RFC 6733 §5.3.5.
    cer_avps += avp(257, 0x40, b"\x00\x01" + bytes([10, 0, 0, 1]), None)
    # Vendor-Id AVP (code 266, M), 10415 = 3GPP. RFC 6733 §5.3.3.
    cer_avps += avp(266, 0x40, u32(10415), None)
    # Product-Name AVP (code 269, no M). RFC 6733 §5.3.7.
    cer_avps += avp(269, 0x00, b"opc-test", None)
    # Auth-Application-Id AVP (code 258, M), value 0x01000001. RFC 6733 §6.8.
    cer_avps += avp(258, 0x40, u32(0x01000001), None)
    write_corpus(
        msg_dir,
        header(0x80, 257, 0, 0x11111111, 0x22222222, cer_avps),
        "cer_request",
    )

    # 3. Capabilities-Exchange-Answer (CEA). Command code 257, R bit cleared.
    #    RFC 6733 section 5.3.2.
    cea_avps = b""
    # Result-Code AVP (code 268, M), DIAMETER_SUCCESS = 2001. RFC 6733 §7.1.
    cea_avps += avp(268, 0x40, u32(2001), None)
    cea_avps += avp(264, 0x40, b"hss.example", None)  # Origin-Host §6.3
    cea_avps += avp(296, 0x40, b"example", None)      # Origin-Realm §6.4
    cea_avps += avp(257, 0x40, b"\x00\x01" + bytes([10, 0, 0, 2]), None)
    cea_avps += avp(266, 0x40, u32(10415), None)       # Vendor-Id §5.3.3
    cea_avps += avp(269, 0x00, b"opc-test", None)      # Product-Name §5.3.7
    write_corpus(
        msg_dir,
        header(0x00, 257, 0, 0x11111111, 0x22222222, cea_avps),
        "cea_success",
    )

    # 4. Device-Watchdog-Request (DWR). Command code 280. RFC 6733 section 5.5.1.
    dwr_avps = b""
    dwr_avps += avp(264, 0x40, b"aaa.example", None)  # Origin-Host §6.3
    dwr_avps += avp(296, 0x40, b"example", None)      # Origin-Realm §6.4
    write_corpus(
        msg_dir,
        header(0x80, 280, 0, 0x33333333, 0x44444444, dwr_avps),
        "dwr_request",
    )

    # 5. Disconnect-Peer-Request (DPR). Command code 282. RFC 6733 section 5.4.1.
    dpr_avps = b""
    dpr_avps += avp(264, 0x40, b"aaa.example", None)  # Origin-Host §6.3
    dpr_avps += avp(296, 0x40, b"example", None)      # Origin-Realm §6.4
    # Disconnect-Cause AVP (code 273, M), REBOOTING = 0. RFC 6733 §5.4.3.
    dpr_avps += avp(273, 0x40, u32(0), None)
    write_corpus(
        msg_dir,
        header(0x80, 282, 0, 0x55555555, 0x66666666, dpr_avps),
        "dpr_request",
    )

    # 6. Rf Accounting-Request (START record). Command code 271, app id 3.
    #    RFC 6733 §9.7.1 / 3GPP TS 32.299 §5.1 offline charging.
    acr_avps = b""
    # Session-Id AVP (code 263, M). RFC 6733 §8.8.
    acr_avps += avp(263, 0x40, b"session;rf;001", None)
    acr_avps += avp(264, 0x40, b"epdg.example", None)      # Origin-Host §6.3
    acr_avps += avp(296, 0x40, b"epc.example.org", None)   # Origin-Realm §6.4
    acr_avps += avp(283, 0x40, b"epc.example.org", None)   # Destination-Realm §6.6
    # Accounting-Record-Type AVP (code 480, M), START = 2. RFC 6733 §9.8.1.
    acr_avps += avp(480, 0x40, u32(2), None)
    # Accounting-Record-Number AVP (code 485, M). RFC 6733 §9.8.2.
    acr_avps += avp(485, 0x40, u32(0), None)
    # Acct-Application-Id AVP (code 259, M), value 3. RFC 6733 §6.9.
    acr_avps += avp(259, 0x40, u32(3), None)
    # Service-Context-Id AVP (code 461, M), 3GPP TS 32.299 §7.1.12.
    acr_avps += avp(461, 0x40, b"32260@3gpp.org", None)
    write_corpus(
        msg_dir,
        header(0xC0, 271, 3, 0x77777777, 0x88888888, acr_avps),
        "rf_acr_start",
    )

    # 7. SWm Diameter-EAP-Request. Command code 268, app id 16777264.
    #    3GPP TS 29.273 §6.1 (SWm Diameter-EAP-Request).
    der_avps = b""
    der_avps += avp(263, 0x40, b"sess;swm;001", None)      # Session-Id §8.8
    # Auth-Application-Id AVP (code 258, M), SWm app id. RFC 6733 §6.8.
    der_avps += avp(258, 0x40, u32(16777264), None)
    der_avps += avp(264, 0x40, b"epdg.example", None)      # Origin-Host §6.3
    der_avps += avp(296, 0x40, b"visited.example", None)   # Origin-Realm §6.4
    der_avps += avp(283, 0x40, b"home.example", None)      # Destination-Realm §6.6
    # Auth-Request-Type AVP (code 274, M), AUTHORIZE_AUTHENTICATE = 3. RFC 6733 §8.7.
    der_avps += avp(274, 0x40, u32(3), None)
    # EAP-Payload AVP (code 462, M). RFC 4072 §4.1.
    der_avps += avp(462, 0x40, b"\x02\x17\x00\x08\x32\x01\x02\x03", None)
    write_corpus(
        msg_dir,
        header(0xC0, 268, 16777264, 0x99999999, 0xAAAAAAAA, der_avps),
        "swm_der",
    )

    # -------------------------------------------------------------------------
    # Malformed message seeds (must not panic the decode surface)
    # -------------------------------------------------------------------------

    # Message whose declared length exceeds the actual bytes. RFC 6733 §3.
    short_body = header(0x80, 257, 0, 0x11111111, 0x22222222, b"")
    claimed_too_long = bytearray(short_body)
    claimed_too_long[1] = 0x00
    claimed_too_long[2] = 0x00
    claimed_too_long[3] = 0x40  # 64 octets, only 20 present
    write_corpus(msg_dir, bytes(claimed_too_long), "malformed_message_length_truncation")

    # Message containing an AVP whose length claims more bytes than available.
    truncated_avp_region = avp(264, 0x40, b"host.example", None)
    truncated_avp_region = bytearray(truncated_avp_region)
    truncated_avp_region[7] = 0x80  # length now claims 128 octets
    write_corpus(
        msg_dir,
        header(0x80, 257, 0, 0x11111111, 0x22222222, bytes(truncated_avp_region)),
        "malformed_avp_truncated_in_message",
    )

    # Message with duplicate mandatory Origin-Host AVPs.
    dup_origin_host = avp(264, 0x40, b"host.example", None)
    write_corpus(
        msg_dir,
        header(0x80, 257, 0, 0x11111111, 0x22222222, dup_origin_host + dup_origin_host),
        "malformed_duplicate_mandatory_in_message",
    )

    # Message containing a grouped Failed-AVP depth bomb.
    leaf = avp(264, 0x40, b"nested.example", None)
    nested = leaf
    for _ in range(4):
        nested = avp(279, 0x40, nested, None)
    write_corpus(
        msg_dir,
        header(0x00, 257, 0, 0x11111111, 0x22222222, nested),
        "malformed_grouped_depth_bomb_in_message",
    )

    # Message with reserved command-flag bits set (strict-mode rejection path).
    write_corpus(
        msg_dir,
        header(0x8F, 257, 0, 0x11111111, 0x22222222, b""),
        "malformed_reserved_message_flags",
    )

    # -------------------------------------------------------------------------
    # Seed corpus for decode_avp
    # -------------------------------------------------------------------------
    avp_dir = os.path.join(base_dir, "corpus", "decode_avp")

    # Single IETF AVP. Origin-Host (code 264) is defined in RFC 6733 §6.3.
    write_corpus(avp_dir, avp(264, 0x40, b"host.example", None), "ietf_origin_host")

    # Vendor-specific AVP (3GPP vendor 10415). PS-Information code 874 is
    # defined in 3GPP TS 32.299; the vendor-specific AVP header is RFC 6733 §4.
    write_corpus(
        avp_dir,
        avp(874, 0xC0, b"\x00\x00\x00\x02\x00\x00\x00\x01", vendor=10415),
        "vendor_ps_info",
    )

    # Grouped AVP: Failed-AVP (code 279) containing an Origin-Host child.
    # Failed-AVP is defined in RFC 6733 §7.5.
    grouped = avp(264, 0x40, b"nested.example", None)
    write_corpus(avp_dir, avp(279, 0x40, grouped, None), "grouped_failed_avp")

    # Padded AVP (value length 1). Padding rules are in RFC 6733 §4.
    write_corpus(avp_dir, avp(264, 0x40, b"x", None), "padded_single_octet")

    # Arbitrary AVP tree: vendor, mandatory, padded, and empty values.
    arbitrary_tree = b""
    arbitrary_tree += avp(1, 0x40, b"u", None)
    arbitrary_tree += avp(7000, 0x80, b"vendor", vendor=10415)
    arbitrary_tree += avp(9999, 0x00, b"", None)
    write_corpus(avp_dir, arbitrary_tree, "arbitrary_avp_tree")

    # -------------------------------------------------------------------------
    # Malformed AVP-region seeds
    # -------------------------------------------------------------------------

    # AVP length shorter than the minimum header length.
    too_short = bytearray(avp(264, 0x40, b"", None))
    too_short[5] = 0
    too_short[6] = 0
    too_short[7] = 7  # 8-octet header minimum, 7 is invalid
    write_corpus(avp_dir, bytes(too_short), "malformed_avp_length_too_short")

    # AVP length claims more bytes than are present.
    truncated = bytearray(avp(264, 0x40, b"host", None))
    truncated[5] = 0
    truncated[6] = 0x01
    truncated[7] = 0x00  # claims 256 octets
    write_corpus(avp_dir, bytes(truncated), "malformed_avp_truncated")

    # Non-zero padding bytes (strict-mode rejection path). RFC 6733 §4.
    bad_padding = bytearray(12)
    bad_padding[0:4] = struct.pack(">I", 264)  # Origin-Host code
    bad_padding[4] = 0x40                      # M flag
    bad_padding[5:8] = b"\x00\x00\x09"         # length = 9 (header + 1 octet value)
    bad_padding[8] = ord("x")
    bad_padding[9:12] = b"\xFF\xFF\xFF"        # non-zero padding
    write_corpus(avp_dir, bytes(bad_padding), "malformed_avp_bad_padding")

    # Duplicate mandatory Origin-Host AVPs in a region.
    dup_region = avp(264, 0x40, b"first.example", None)
    dup_region += avp(264, 0x40, b"second.example", None)
    write_corpus(avp_dir, dup_region, "malformed_duplicate_mandatory")

    # Grouped Failed-AVP depth bomb.
    leaf_avp = avp(264, 0x40, b"nested.example", None)
    nested_avp = leaf_avp
    for _ in range(4):
        nested_avp = avp(279, 0x40, nested_avp, None)
    write_corpus(avp_dir, nested_avp, "malformed_grouped_depth_bomb")

    # Vendor-specific AVP with length shorter than the 12-octet vendor header.
    bad_vendor = bytearray(12)
    bad_vendor[0:4] = struct.pack(">I", 7000)
    bad_vendor[4] = 0x80                         # V bit set
    bad_vendor[5:8] = b"\x00\x00\x0B"            # length = 11, < 12
    bad_vendor[8:12] = struct.pack(">I", 10415)  # Vendor-Id
    write_corpus(avp_dir, bytes(bad_vendor), "malformed_vendor_header_too_short")

    print(f"Generated seed corpus in {base_dir}/corpus")


if __name__ == "__main__":
    self_test_avp_flag_validation()
    main()
