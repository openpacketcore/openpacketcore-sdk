#!/usr/bin/env python3
"""Generate the committed seed corpus for opc-proto-diameter fuzz targets.

Every seed file produced by this script is written directly under
fuzz/corpus/<target>/ so that `cargo fuzz run <target>` seeds from it.
No seed lives only in a provenance/documentation directory.

The spec-valid fixtures are hand-authored from the wire layouts in:
  - IETF RFC 6733 section 3 (message header) and section 4 (AVP framing)
  - 3GPP TS 32.299 (Rf offline charging PS-Information vendor AVPs)
  - 3GPP TS 29.273 (SWm Diameter-EAP, Session-Termination, Abort-Session,
    Re-Auth, and AA commands/AVPs)

The malformed fixtures exercise the hostile-input paths that the decode
surface must never panic on: truncation, invalid lengths, duplicate
mandatory AVPs, grouped depth bombs, bad padding, and reserved flag bits.
"""

import hashlib
import hmac
import os
import struct
import sys


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


def unauthenticated_emergency_msk(imei: bytes) -> bytes:
    """Derive the 32-octet MSK from 3GPP TS 33.402 Annex A.4."""
    return hmac.new(imei, b"\x22unauth-emer\x00\x0b", hashlib.sha256).digest()


def self_test_helpers() -> None:
    """Assert corpus helpers fail closed and retain the published KDF vector."""
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

    invalid_vendor_cases = (
        (0x40, 10415, "vendor provided but V bit"),
        (0xC0, None, "V bit (0x80) set"),
    )
    for flags, vendor, expected in invalid_vendor_cases:
        try:
            avp(264, flags, b"x", vendor)
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(
                    f"unexpected error for vendor/V-bit mismatch "
                    f"0x{flags:02x}, vendor={vendor}: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"vendor/V-bit mismatch 0x{flags:02x}, vendor={vendor} "
                "was accepted by corpus helper"
            )

    expected_msk = bytes.fromhex(
        "e0331e121cc1b8f468f08e24f4e7b8dae3c8f7a8b5e7147613aedfce21d9d6ac"
    )
    actual_msk = unauthenticated_emergency_msk(b"490154203237518")
    if not hmac.compare_digest(actual_msk, expected_msk):
        raise AssertionError("TS 33.402 Annex A.4 emergency MSK vector changed")


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
    # RFC 6733 §6.11 nested parser provenance: received VSAI without Vendor-Id,
    # and received VSAI without either Auth/Acct application child.
    write_corpus(
        msg_dir,
        header(
            0x80,
            257,
            0,
            0x11111112,
            0x22222223,
            cer_avps + avp(260, 0x40, avp(258, 0x40, u32(16777264), None), None),
        ),
        "cer_vsai_missing_vendor_id",
    )
    write_corpus(
        msg_dir,
        header(
            0x80,
            257,
            0,
            0x11111113,
            0x22222224,
            cer_avps + avp(260, 0x40, avp(266, 0x40, u32(10415), None), None),
        ),
        "cer_vsai_missing_application_id",
    )
    write_corpus(
        msg_dir,
        header(
            0x80,
            257,
            0,
            0x11111114,
            0x22222225,
            cer_avps
            + avp(
                260,
                0x40,
                avp(266, 0x40, u32(10415), None)
                + avp(258, 0x40, u32(16777264), None)
                + avp(259, 0x40, u32(3), None),
                None,
            ),
        ),
        "cer_vsai_auth_acct_conflict",
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
    write_corpus(
        msg_dir,
        header(0x80, 280, 0, 0x33333334, 0x44444445, b""),
        "dwr_missing_origin_host",
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
    write_corpus(
        msg_dir,
        header(0x80, 282, 0, 0x55555556, 0x66666667, b""),
        "dpr_missing_disconnect_cause",
    )

    # Request-bound error-answer seeds. These exercise inspection of an
    # unknown command and an unsupported application while retaining only the
    # exact Session-Id and ordered Proxy-Info routing context.
    error_routing_avps = b""
    error_routing_avps += avp(263, 0x40, b"sess;error;001", None)
    error_routing_avps += avp(283, 0x40, b"destination.example", None)
    proxy_info = avp(280, 0x40, b"proxy.example", None)
    proxy_info += avp(33, 0x40, b"opaque-state", None)
    error_routing_avps += avp(284, 0x40, proxy_info, None)
    write_corpus(
        msg_dir,
        header(0xC0, 0x00FEFE, 0, 0x12121212, 0x34343434, error_routing_avps),
        "error_unknown_command_request",
    )
    write_corpus(
        msg_dir,
        header(0xC0, 268, 9999, 0x56565656, 0x78787878, error_routing_avps),
        "error_unsupported_application_request",
    )
    write_corpus(
        msg_dir,
        header(
            0x80,
            280,
            0,
            0x90909090,
            0xA0A0A0A0,
            avp(284, 0x40, proxy_info, None),
        ),
        "error_proxy_info_resource_limits",
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
    der_common_avps = der_avps
    # EAP-Payload AVP (code 462, M). RFC 4072 §4.1.
    der_avps += avp(462, 0x40, b"\x02\x17\x00\x08\x32\x01\x02\x03", None)
    write_corpus(
        msg_dir,
        header(0xC0, 268, 16777264, 0x99999999, 0xAAAAAAAA, der_avps),
        "swm_der",
    )
    write_corpus(
        msg_dir,
        header(0xC0, 268, 16777264, 0x99999998, 0xAAAAAAA9, b""),
        "swm_der_missing_auth_application_id",
    )
    write_corpus(
        msg_dir,
        header(
            0xC0,
            268,
            16777264,
            0x99999997,
            0xAAAAAAA8,
            der_avps
            + avp(
                1401,
                0xC0,
                avp(1403, 0xC0, b"99", vendor=10415),
                vendor=10415,
            ),
        ),
        "swm_der_terminal_information_missing_imei",
    )

    # 8. SWm DER with two State AVPs. State is repeatable in the command
    #    grammar even under conservative dictionary-aware duplicate rejection.
    repeated_state_der = der_avps
    repeated_state_der += avp(24, 0x40, b"state-one", None)
    repeated_state_der += avp(24, 0x40, b"state-two", None)
    write_corpus(
        msg_dir,
        header(0xC0, 268, 16777264, 0x9999999A, 0xAAAAAAAB, repeated_state_der),
        "swm_der_repeated_state",
    )

    # 9. SWm DEA carrying the opt-in projected APN profile. The two
    #    APN-Configuration AVPs are repeatable only in that explicit profile.
    dea_avps = b""
    dea_avps += avp(263, 0x40, b"sess;swm;001", None)
    dea_avps += avp(258, 0x40, u32(16777264), None)
    dea_avps += avp(274, 0x40, u32(3), None)
    dea_avps += avp(268, 0x40, u32(2001), None)
    dea_avps += avp(264, 0x40, b"aaa.home.example", None)
    dea_avps += avp(296, 0x40, b"home.example", None)
    dea_avps += avp(462, 0x40, b"\x03\x18\x00\x04", None)
    dea_avps += avp(1423, 0xC0, u32(8), vendor=10415)
    apn_one = avp(1423, 0xC0, u32(7), vendor=10415)
    apn_one += avp(493, 0x40, b"internet.mnc001.mcc001.gprs", None)
    apn_one += avp(1456, 0xC0, u32(2), vendor=10415)
    apn_two = avp(1423, 0xC0, u32(8), vendor=10415)
    apn_two += avp(493, 0x40, b"ims.mnc001.mcc001.gprs", None)
    apn_two += avp(1456, 0xC0, u32(1), vendor=10415)
    dea_avps += avp(1430, 0xC0, apn_one, vendor=10415)
    dea_avps += avp(1430, 0xC0, apn_two, vendor=10415)
    write_corpus(
        msg_dir,
        header(0x40, 268, 16777264, 0x9999999B, 0xAAAAAAAC, dea_avps),
        "swm_dea_projected_apn_profile",
    )

    # 10. SWm emergency DER. TS 29.273 §7.2.3.4 defines Emergency-Services
    #     (code 1538) as a 3GPP vendor Unsigned32 with V=1, M=0, P=0; bit zero
    #     requests an emergency PDN connection.
    emergency_user_name = (
        b"0234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org"
    )
    emergency_eap_identity = (
        b"\x02\x17"
        + struct.pack(">H", 5 + len(emergency_user_name))
        + b"\x01"
        + emergency_user_name
    )
    emergency_der = der_common_avps
    emergency_der += avp(462, 0x40, emergency_eap_identity, None)
    emergency_der += avp(1, 0x40, emergency_user_name, None)
    emergency_der += avp(1538, 0x80, u32(1), vendor=10415)
    write_corpus(
        msg_dir,
        header(0xC0, 268, 16777264, 0x9999999C, 0xAAAAAAAD, emergency_der),
        "swm_der_emergency_indication",
    )

    # 11. TS 33.402 §13.3 identity-recovery DEA. Experimental-Result is a
    #     grouped base AVP containing 3GPP Vendor-Id 10415 and result code
    #     5001. It requests DEVICE_IDENTITY; it does not authorize access.
    identity_required_dea = b""
    identity_required_dea += avp(263, 0x40, b"sess;swm;001", None)
    identity_required_dea += avp(258, 0x40, u32(16777264), None)
    identity_required_dea += avp(274, 0x40, u32(3), None)
    experimental_result = avp(266, 0x40, u32(10415), None)
    experimental_result += avp(298, 0x40, u32(5001), None)
    identity_required_dea += avp(297, 0x40, experimental_result, None)
    identity_required_dea += avp(264, 0x40, b"aaa.home.example", None)
    identity_required_dea += avp(296, 0x40, b"home.example", None)
    write_corpus(
        msg_dir,
        header(
            0x40,
            268,
            16777264,
            0x9999999C,
            0xAAAAAAAD,
            identity_required_dea,
        ),
        "swm_dea_emergency_identity_required",
    )

    # 12. Correlated retry DER after DEVICE_IDENTITY recovery. The recovered
    #     IMEI is carried in the TS 29.272 Terminal-Information grouped AVP;
    #     the DER repeats the emergency indication.
    imei = b"490154203237518"
    emergency_nai = b"imei" + imei + b"@sos.invalid"
    terminal_information = avp(1402, 0xC0, imei, vendor=10415)
    emergency_retry_der = emergency_der
    emergency_retry_der += avp(1401, 0xC0, terminal_information, vendor=10415)
    write_corpus(
        msg_dir,
        header(
            0xC0,
            268,
            16777264,
            0x9999999E,
            0xAAAAAAAF,
            emergency_retry_der,
        ),
        "swm_der_emergency_terminal_information_retry",
    )

    # 13. Final DEA material for the correlated emergency exchange. Exact
    #     DIAMETER_SUCCESS, EAP-Success, the IMEI-derived MSK, and the same
    #     Emergency NAI are all required before ordinary method-2 IKE AUTH.
    final_emergency_dea = b""
    final_emergency_dea += avp(263, 0x40, b"sess;swm;001", None)
    final_emergency_dea += avp(258, 0x40, u32(16777264), None)
    final_emergency_dea += avp(274, 0x40, u32(3), None)
    final_emergency_dea += avp(268, 0x40, u32(2001), None)
    final_emergency_dea += avp(264, 0x40, b"aaa.home.example", None)
    final_emergency_dea += avp(296, 0x40, b"home.example", None)
    final_emergency_dea += avp(462, 0x40, b"\x03\x17\x00\x04", None)
    final_emergency_dea += avp(464, 0x00, unauthenticated_emergency_msk(imei), None)
    final_emergency_dea += avp(506, 0x40, emergency_nai, None)
    write_corpus(
        msg_dir,
        header(
            0x40,
            268,
            16777264,
            0x9999999E,
            0xAAAAAAAF,
            final_emergency_dea,
        ),
        "swm_dea_emergency_final_success_material",
    )

    # 14. SWm Session-Termination-Request, TS 29.273 §7.2.2.2.1.
    #     Proxy-Info and Route-Record exercise the RFC 6733 routing surface.
    proxy_info = avp(280, 0x40, b"proxy.example", None)
    proxy_info += avp(33, 0x40, b"opaque-proxy-state", None)
    str_avps = b""
    str_avps += avp(263, 0x40, b"sess;swm;termination", None)
    str_avps += avp(301, 0x00, u32(5), None)
    str_avps += avp(264, 0x40, b"epdg.example", None)
    str_avps += avp(296, 0x40, b"example", None)
    str_avps += avp(283, 0x40, b"aaa.example", None)
    str_avps += avp(258, 0x40, u32(16777264), None)
    str_avps += avp(295, 0x40, u32(4), None)
    str_avps += avp(1, 0x40, b"permanent-user@example", None)
    str_avps += avp(284, 0x40, proxy_info, None)
    str_avps += avp(282, 0x40, b"proxy.example", None)
    write_corpus(
        msg_dir,
        header(0xC0, 275, 16777264, 0x999999A1, 0xAAAAAAB2, str_avps),
        "swm_str_session_termination",
    )

    # 15. Correlated SWm Session-Termination-Answer with success,
    #     TS 29.273 §7.2.2.2.2. Proxy-Info is copied in wire order.
    sta_avps = b""
    sta_avps += avp(263, 0x40, b"sess;swm;termination", None)
    sta_avps += avp(268, 0x40, u32(2001), None)
    sta_avps += avp(264, 0x40, b"aaa.example", None)
    sta_avps += avp(296, 0x40, b"example", None)
    sta_avps += avp(284, 0x40, proxy_info, None)
    write_corpus(
        msg_dir,
        header(0x40, 275, 16777264, 0x999999A1, 0xAAAAAAB2, sta_avps),
        "swm_sta_session_termination_success",
    )

    # 16. STR omission seed for sealed Termination-Cause / 5005 provenance.
    str_without_termination_cause = str_avps.replace(
        avp(295, 0x40, u32(4), None), b"", 1
    )
    write_corpus(
        msg_dir,
        header(
            0xC0,
            275,
            16777264,
            0x999999A2,
            0xAAAAAAB3,
            str_without_termination_cause,
        ),
        "swm_str_missing_termination_cause",
    )

    # 17. STR omission seed for the SWm procedure-table-mandatory User-Name.
    str_without_user_name = str_avps.replace(
        avp(1, 0x40, b"permanent-user@example", None), b"", 1
    )
    write_corpus(
        msg_dir,
        header(
            0xC0,
            275,
            16777264,
            0x999999A3,
            0xAAAAAAB4,
            str_without_user_name,
        ),
        "swm_str_missing_user_name",
    )

    # 18. SWm Abort-Session-Request, TS 29.273 §7.2.2.3.1. The explicit
    #     STATE_MAINTAINED value requires the post-abort STR sequence after a
    #     successful ASA; Proxy-Info and Route-Record exercise bounded routing.
    asr_avps = b""
    asr_avps += avp(263, 0x40, b"sess;swm;abort", None)
    asr_avps += avp(301, 0x00, u32(5), None)
    asr_avps += avp(264, 0x40, b"aaa.example", None)
    asr_avps += avp(296, 0x40, b"example", None)
    asr_avps += avp(283, 0x40, b"visited.example", None)
    asr_avps += avp(293, 0x40, b"epdg.example", None)
    asr_avps += avp(258, 0x40, u32(16777264), None)
    asr_avps += avp(1, 0x40, b"subscriber@example.invalid", None)
    asr_avps += avp(277, 0x40, u32(0), None)
    asr_avps += avp(284, 0x40, proxy_info, None)
    asr_avps += avp(282, 0x40, b"proxy.example", None)
    write_corpus(
        msg_dir,
        header(0xC0, 274, 16777264, 0x999999A3, 0xAAAAAAB4, asr_avps),
        "swm_asr_abort_session",
    )

    # 19. Correlated successful SWm Abort-Session-Answer, TS 29.273
    #     §7.2.2.3.2. Proxy-Info is copied in wire order.
    asa_avps = b""
    asa_avps += avp(263, 0x40, b"sess;swm;abort", None)
    asa_avps += avp(268, 0x40, u32(2001), None)
    asa_avps += avp(264, 0x40, b"epdg.example", None)
    asa_avps += avp(296, 0x40, b"visited.example", None)
    asa_avps += avp(284, 0x40, proxy_info, None)
    write_corpus(
        msg_dir,
        header(0x40, 274, 16777264, 0x999999A3, 0xAAAAAAB4, asa_avps),
        "swm_asa_abort_session_success",
    )

    # 20. ASR omission seed for sealed Destination-Host / 5005 provenance.
    asr_without_destination_host = asr_avps.replace(
        avp(293, 0x40, b"epdg.example", None), b"", 1
    )
    write_corpus(
        msg_dir,
        header(
            0xC0,
            274,
            16777264,
            0x999999A4,
            0xAAAAAAB5,
            asr_without_destination_host,
        ),
        "swm_asr_missing_destination_host",
    )

    # 21. SWm Re-Auth-Request / Re-Auth-Answer authorization update,
    #     TS 29.273 §§7.2.2.4.1-.2. Re-Auth-Request-Type is AUTHORIZE_ONLY.
    authorization_proxy = avp(280, 0x40, b"proxy.example", None)
    authorization_proxy += avp(33, 0x40, b"opaque-authorization-state", None)
    rar_avps = b""
    rar_avps += avp(263, 0x40, b"sess;swm;authorization", None)
    rar_avps += avp(264, 0x40, b"aaa.example", None)
    rar_avps += avp(296, 0x40, b"example", None)
    rar_avps += avp(283, 0x40, b"access.example", None)
    rar_avps += avp(293, 0x40, b"epdg.example", None)
    rar_avps += avp(258, 0x40, u32(16777264), None)
    rar_avps += avp(285, 0x40, u32(0), None)
    rar_avps += avp(1, 0x40, b"subscriber@example", None)
    rar_avps += avp(284, 0x40, authorization_proxy, None)
    write_corpus(
        msg_dir,
        header(0xC0, 258, 16777264, 0x999999A5, 0xAAAAAAB6, rar_avps),
        "swm_rar_authorization_update",
    )
    raa_avps = b""
    raa_avps += avp(263, 0x40, b"sess;swm;authorization", None)
    raa_avps += avp(268, 0x40, u32(2001), None)
    raa_avps += avp(285, 0x40, u32(0), None)
    raa_avps += avp(291, 0x40, u32(600), None)
    raa_avps += avp(276, 0x40, u32(60), None)
    raa_avps += avp(264, 0x40, b"epdg.example", None)
    raa_avps += avp(296, 0x40, b"access.example", None)
    raa_avps += avp(1, 0x40, b"subscriber@example", None)
    raa_avps += avp(284, 0x40, authorization_proxy, None)
    write_corpus(
        msg_dir,
        header(0x40, 258, 16777264, 0x999999A5, 0xAAAAAAB6, raa_avps),
        "swm_raa_authorization_update_success",
    )

    # 22. Follow-up AA-Request / AA-Answer, TS 29.273 §§7.2.2.1.3-.4.
    #     AAA intentionally clears R despite the displayed ABNF editorial typo.
    aar_avps = b""
    aar_avps += avp(263, 0x40, b"sess;swm;authorization", None)
    aar_avps += avp(258, 0x40, u32(16777264), None)
    aar_avps += avp(264, 0x40, b"epdg.example", None)
    aar_avps += avp(296, 0x40, b"example", None)
    aar_avps += avp(283, 0x40, b"aaa.example", None)
    aar_avps += avp(293, 0x40, b"dra.example", None)
    aar_avps += avp(274, 0x40, u32(2), None)
    aar_avps += avp(1, 0x40, b"subscriber@example", None)
    aar_avps += avp(291, 0x40, u32(600), None)
    aar_avps += avp(276, 0x40, u32(60), None)
    aar_avps += avp(1539, 0x80, u32(1), vendor=10415)
    aar_avps += avp(2805, 0x80, b"\x00\x01" + bytes([198, 51, 100, 10]), vendor=10415)
    aar_avps += avp(1542, 0x80, u32(1), vendor=10415)
    aar_avps += avp(284, 0x40, authorization_proxy, None)
    write_corpus(
        msg_dir,
        header(0xC0, 265, 16777264, 0x999999A6, 0xAAAAAAB7, aar_avps),
        "swm_aar_authorization_update",
    )
    apn_children = b""
    apn_children += avp(1423, 0xC0, u32(7), vendor=10415)
    apn_children += avp(1456, 0xC0, u32(2), vendor=10415)
    apn_children += avp(493, 0x40, b"ims", None)
    aaa_avps = b""
    aaa_avps += avp(263, 0x40, b"sess;swm;authorization", None)
    aaa_avps += avp(258, 0x40, u32(16777264), None)
    aaa_avps += avp(274, 0x40, u32(2), None)
    aaa_avps += avp(268, 0x40, u32(2001), None)
    aaa_avps += avp(285, 0x40, u32(0), None)
    aaa_avps += avp(291, 0x40, u32(300), None)
    aaa_avps += avp(276, 0x40, u32(60), None)
    aaa_avps += avp(27, 0x40, u32(900), None)
    aaa_avps += avp(264, 0x40, b"dra.example", None)
    aaa_avps += avp(296, 0x40, b"aaa.example", None)
    aaa_avps += avp(1, 0x40, b"subscriber@example", None)
    aaa_avps += avp(1430, 0xC0, apn_children, vendor=10415)
    aaa_avps += avp(284, 0x40, authorization_proxy, None)
    write_corpus(
        msg_dir,
        header(0x40, 265, 16777264, 0x999999A6, 0xAAAAAAB7, aaa_avps),
        "swm_aaa_authorization_update_success",
    )

    # 23. Header-complete omissions exercise sealed 5005 provenance.
    write_corpus(
        msg_dir,
        header(
            0xC0,
            258,
            16777264,
            0x999999A7,
            0xAAAAAAB8,
            rar_avps.replace(avp(285, 0x40, u32(0), None), b"", 1),
        ),
        "swm_rar_missing_re_auth_request_type",
    )
    write_corpus(
        msg_dir,
        header(
            0xC0,
            265,
            16777264,
            0x999999A8,
            0xAAAAAAB9,
            aar_avps.replace(avp(274, 0x40, u32(2), None), b"", 1),
        ),
        "swm_aar_missing_auth_request_type",
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

    # SWm Emergency-Services is a DER-only singleton.
    duplicate_emergency = avp(1538, 0x80, u32(1), vendor=10415)
    write_corpus(
        msg_dir,
        header(
            0xC0,
            268,
            16777264,
            0x999999A0,
            0xAAAAAAB1,
            emergency_der + duplicate_emergency,
        ),
        "malformed_swm_duplicate_emergency_services",
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
    if len(sys.argv) > 1 and sys.argv[1] in ("self-test", "--self-test"):
        self_test_helpers()
        print("Corpus helper self-test passed")
    else:
        self_test_helpers()
        main()
