# NAS-5GS Protocol Conformance

This document defines the conformance of the `opc-proto-nas` crate against
3GPP TS 24.501.

## Specification Baseline

- **Document**: 3GPP TS 24.501 (with header formats per TS 24.007)
- **Release**: Release 18 (R18)
- **Status**: v0 — experimental, deliberately narrow

## Supported Features (v0)

### 1. Message Framing (§9.1.1)
- EPD dispatch: `0x7E` (5GMM) and `0x2E` (5GSM); all other EPDs rejected.
- Plain 5GMM header (3 octets): security header type nibble (spare nibble
  preserved; rejected non-zero in strict mode), message type, raw body.
- 5GSM header (4 octets): PDU session identity, PTI, message type, raw body.
- Security-protected envelope (security header types 1–4, §9.3.1): MAC
  (4 octets) and NAS sequence number framed; payload kept opaque.
  **No integrity verification and no deciphering** — recognition only.
- Reserved security header types (5–15) rejected.
- NAS PDUs carry no internal length framing; decode consumes the entire
  input (the transport delimits PDUs).
- All round-trips are byte-exact: spare bits and unparsed regions are
  preserved verbatim. Conformance tests include hand-authored spec-byte
  fixtures, not only this codec's own output.

### 2. 5GS Mobile Identity (§9.11.3.4)
Decodes IE *content* (caller strips IEI/length framing):
- **SUCI** (type 1): SUPI format 0 (IMSI) parsed into PLMN, routing
  indicator, protection scheme id, home network public key id, and scheme
  output; SUPI format 1 (NAI) kept raw; other formats preserved raw.
  **SUCI de-concealment is explicitly out of scope.**
- **5G-GUTI** (type 2): PLMN, AMF Region ID, AMF Set ID (10 bits),
  AMF Pointer (6 bits), 5G-TMSI; exact 11-octet length enforced.
- **IMEI (3) / IMEISV (5)**: length-checked, odd/even digit indicator
  exposed, BCD digits kept raw (not unpacked in v0).
- **5G-S-TMSI (4) / MAC (6) / EUI-64 (7) / no identity (0)**:
  length-validated, raw preservation only.
- PLMN/routing-indicator BCD digit unpacking is v1 scope; v0 exposes the
  raw octets.

### 3. Message-Type Registries (Tables 9.7.1 / 9.7.2)
- 5GMM: 29 message types, Registration Request (0x41) through DL NAS
  Transport (0x68), names and code points only.
- 5GSM: 16 message types, PDU Session Establishment Request (0xC1) through
  5GSM Status (0xD6), names and code points only.
- Unknown code points do not fail decoding; `from_u8` returns `None` and
  the raw code remains available on the header.

## Out of Scope (v0+)

- IE parsing of message bodies (Registration Request IEs, etc.) — v1.
- NAS security: integrity verification, ciphering/deciphering, key
  derivation, COUNT handling — out of scope for this crate entirely
  (a future `opc-nas-security` concern).
- SUCI de-concealment (home-network private key operations).
- BCD digit unpacking for PLMN, routing indicator, IMEI/IMEISV — v1.
- EPS (4G) NAS interworking formats.
