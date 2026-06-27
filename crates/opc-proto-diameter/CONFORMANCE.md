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
  DWR/DWA, and DPR/DPA, including optional `Origin-State-Id`, answer diagnostic
  AVPs (`Error-Message` and raw `Failed-AVP` values), protocol-error E-bit
  derivation, minimal CEA protocol-error answers, Relay Application Id aware
  peer capability intersection, and CEA result-code helpers. These helpers
  deliberately do not own socket management, realm routing, watchdog
  thresholds, or deployment readiness policy.
- Feature skeletons:
  - `base`: common RFC 6733 application metadata, CER/CEA, DWR/DWA, DPR/DPA,
    and selected base AVP definitions.
  - `peer`: transport-neutral procedure classification, base peer procedure
    builders/parsers, minimal CEA protocol-error answers, diagnostics
    preservation, and capability/result-code helpers for the base peer
    commands.
  - `app-gx`, `app-rf`, `app-s6a`, `app-s6b`, `app-swm`, `app-swx`: initial
    per-application 3GPP dictionary slots.
  - `app-rf`: Rf Accounting-Request/Answer (START, INTERIM, STOP, EVENT)
    dictionary subset plus redaction-safe typed builders/parsers.
  - `app-swm`: SWm Diameter-EAP Request/Answer dictionary subset plus
    redaction-safe typed builders/parsers.
  - `all-apps`: enables every per-application dictionary slot.

## Rf subset coverage (`app-rf`)

- Application: 3GPP Rf accounting over Diameter accounting (id 3).
- Commands: Accounting-Request / Accounting-Answer (command code 271).
- Typed message builders/parsers: `RfAccountingRequest`, `RfAccountingAnswer`.
- AVPs:
  - Base: Session-Id, Origin-Host, Origin-Realm, Destination-Realm,
    Destination-Host, User-Name, Origin-State-Id, Acct-Application-Id,
    Result-Code.
  - RFC 6733 accounting: Accounting-Record-Type, Accounting-Record-Number,
    Event-Timestamp.
  - RFC 4006 credit-control: Subscription-Id, Subscription-Id-Type,
    Subscription-Id-Data, Used-Service-Unit, CC-Time, CC-Total-Octets,
    CC-Input-Octets, CC-Output-Octets, Multiple-Services-Credit-Control,
    Rating-Group, Service-Identifier, Service-Context-Id.
  - 3GPP TS 32.299 (vendor 10415): PS-Information, 3GPP-Charging-Id,
    3GPP-PDP-Type, SGSN-Address, GGSN-Address.
- Sensitive fields use `Redacted<T>` so `Debug`/`Display` do not expose
  Session-Id, User-Name, Subscription-Id-Data, or IP addresses.

## SWm subset coverage (`app-swm`)

- Application: 3GPP SWm (id 16777264).
- Commands: Diameter-EAP-Request / Diameter-EAP-Answer (command code 268).
- Typed message builders/parsers: `SwmDiameterEapRequest`,
  `SwmDiameterEapAnswer`.
- AVPs:
  - Base: Session-Id, Auth-Application-Id, Origin-Host, Origin-Realm,
    Destination-Realm, Destination-Host, User-Name, Result-Code, Error-Message.
  - RFC 4072 / RFC 6733: EAP-Payload, EAP-Reissued-Payload,
    EAP-Master-Session-Key, Auth-Request-Type, State.
- Sensitive fields use `Redacted<T>` so `Debug`/`Display` do not expose
  Session-Id, User-Name, or EAP payloads/keys.

## Explicit gaps

- No fixture is counted as ADR 0015 conformance evidence yet.
- No ePDG-derived Diameter bytes are imported; source local-builder cases remain
  parity/schema seeds until a later fixture-intake task records provenance.
- Broader typed AVP value decoders are follow-up work; current typed values are
  limited to the base peer procedures and the Rf/SWm subsets above.
- Other 3GPP Diameter applications (`app-gx`, `app-s6a`, `app-s6b`,
  `app-swx`) remain dictionary-only slots without typed helpers.
- Fuzz targets and fixture manifests are follow-up work.
- Transport operations, realm routing, peer topology, watchdog policy, AAA/HSS
  behavior, and charging decisions are outside this crate.

## Fixture intake rule

Future conformance fixtures must be spec-authored with octet-level comments or
captured from an independent implementation with source, license, redaction, and
capture metadata. Local builder output and same-codec round trips may be useful
regression tests, but they do not prove wire conformance by themselves.
