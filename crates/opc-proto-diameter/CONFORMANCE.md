# opc-proto-diameter Conformance Notes

Status: **experimental scaffold**.

This crate does not yet claim full RFC 6733 or 3GPP Diameter conformance. The
current scope exists so follow-up tasks can add independently authored fixtures,
broader typed AVP value decoding, app dictionaries, and fuzz coverage without
importing ePDG product policy or local-builder bytes as conformance evidence.

## Implemented scaffold

- Diameter message header decode/encode for RFC 6733 section 3.
- Raw Diameter message storage that preserves the top-level AVP byte region.
- Raw AVP header/value/padding decode/encode for RFC 6733 section 4.
- AVP-region validation for padding, per-region AVP count limits, duplicate
  AVP-key rejection policy, and dictionary-defined grouped AVP recursion capped
  by `DecodeContext::max_depth`.
- Dictionary metadata architecture for applications, commands, AVPs, data types,
  and flag requirements.
- Transport-neutral RFC 6733 base procedure builders/parsers for CER/CEA,
  DWR/DWA, and DPR/DPA, including peer capability intersection helpers. These
  helpers deliberately do not own socket management, realm routing, watchdog
  thresholds, or deployment readiness policy.
- Feature skeletons:
  - `base`: common RFC 6733 application metadata, CER/CEA, DWR/DWA, DPR/DPA,
    and selected base AVP definitions.
  - `peer`: transport-neutral procedure classification, base peer procedure
    builders/parsers, and capability helpers for the base peer commands.
  - `app-gx`, `app-rf`, `app-s6a`, `app-s6b`, `app-swm`, `app-swx`: initial
    per-application 3GPP dictionary slots.
  - `all-apps`: enables every per-application dictionary slot.

## Explicit gaps

- No fixture is counted as ADR 0015 conformance evidence yet.
- No ePDG-derived Diameter bytes are imported; source local-builder cases remain
  parity/schema seeds until a later fixture-intake task records provenance.
- Broader typed AVP value decoders are follow-up work; current typed values are
  limited to the base peer procedures above.
- Application-specific command/AVP dictionaries are follow-up work.
- Fuzz targets and fixture manifests are follow-up work.
- Transport operations, realm routing, peer topology, watchdog policy, AAA/HSS
  behavior, and charging decisions are outside this crate.

## Fixture intake rule

Future conformance fixtures must be spec-authored with octet-level comments or
captured from an independent implementation with source, license, redaction, and
capture metadata. Local builder output and same-codec round trips may be useful
regression tests, but they do not prove wire conformance by themselves.
