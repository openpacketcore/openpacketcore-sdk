# ADR 0033: N1-mode wire value codecs

## Status

Accepted.

## Context

IKEv2 and GTPv2-C carry the same PDU session identity, S-NSSAI and PLMN values
in different envelopes. The SDK needs checked wire representations without
turning successful parsing into negotiation, authentication or authorization.

## Decision

Put the checked shared values in `opc_types::n1_mode`, and keep each transport's
framing in its protocol crate. PDU session identity codes 0 through 15 are
representable: zero is unassigned, not a disabled-mode flag. S-NSSAI preserves
the complete 1-, 2-, 4-, 5- and 8-octet forms including mapped HPLMN fields.
PLMN validates decimal TBCD digits and the two-digit MNC filler. Explicit
accessors expose values; `Debug` and `Display` redact them. No serde or implicit
conversion to the pre-existing textual slice/PLMN types is introduced.

IKEv2 recognizes N1_MODE_CAPABILITY (51015), N1_MODE_INFORMATION (51115) and
N1_MODE_S_NSSAI_PLMN_ID (52216). An unrelated Notify returns `Ok(None)`;
malformed recognized data returns a value-free error. Both SPI size and SPI
must be empty, and the one-octet inner length must cover the exact complete
value. Protocol ID is zero when sent and ignored on receipt for an empty SPI.
A collection accepts at most 64 Notifies, including unrelated types, and
returns no partial result if any recognized value is malformed.

The ordinary APCO request codec recognizes MS-to-network container `0x001a`;
the response codec recognizes network-to-MS `0x001b`, which combines a complete
S-NSSAI value with three associated PLMN octets. Framing is checked through the
end, including unknown units and the pinned specification's direction-specific
two-octet length fields, including TS 24.008 V20.0.0 NSSAA EAP container
`0x0061` in both directions. Unrecognized identifiers and identifiers reserved in
the selected direction do not produce N1 data. Append preserves every existing
byte. Work is bounded to 64 units and 251 ordinary PCO contents octets. Large
APCO and standalone ePCO are excluded.

Repeated recognized Notify types and repeated N1 container identifiers are
rejected, including identical duplicates. This is a local SDK ambiguity rule,
not a claim that the specifications mandate this duplicate disposition.
The S2b projection selects the first matching IE remaining in the supplied view.
Among APCOs that survive outer-IE decoding, preserving the wire's first
occurrence requires `S2bMessage::decode` with
`ValidationLevel::ProcedureAware` (which forces `DuplicateIePolicy::First`),
or explicit `First` at another validation level. `Reject` at another level
rejects duplicates before projection. The default context and `Strict` with
the default `Last` policy have already discarded earlier IEs; the projection
cannot recover them. An empty Create Session Response APCO is discarded as
malformed optional outer-IE data at every validation level, before duplicate
selection, including under `Reject`. A later populated APCO can therefore
supply N1 data. This does not skip a nonempty APCO merely because its inner N1
contents are invalid. An empty request APCO instead fails receive decoding.
These decode policies remain unchanged.
The S2b projection checks Create Session procedure, direction
and header type and reads only top-level APCO type 163 instance 0. An optional
N1 decoding error does not alter Cause or authorize whole-session rejection.

Expose the independent Indication bits 5GSIWKI, 5GCNRS and 5GCNRI by name.
Absent extension octets read clear; setting a bit extends with zeroes only as
needed, and clearing an absent bit leaves length unchanged. Preserve all other
bits and future octets.

## Consequences

The additions are value codecs with no background work, durable state, network
I/O or lifecycle effects. Consumers decide which exchanges to authenticate,
whether N1 applies, which slice is authorized, how session identities map and
how malformed optional values affect their procedure. The protocol crates
reuse `opc-types`; their error derives use the existing workspace `thiserror`
dependency. No third-party package is new to the workspace, but adding
`opc-types` expands the `opc-proto-gtpv2c` dependency graph to include `serde`,
`time`, `uuid` and their transitive dependencies, including in its standalone
fuzz lockfile. This cost is accepted to share one checked wire representation
across the protocol crates.

Independent literal vectors and existing spec-authored S2b fixtures cover wire
values, all slice forms, directional placement, malformed/absent distinctions,
duplicates, bounded work, preserved unrelated data and redacted diagnostics.
These tests do not establish peer interoperability or product readiness.

## References

- [TS 24.302 V18.7.0](https://www.etsi.org/deliver/etsi_ts/124300_124399/124302/18.07.00_60/ts_124302v180700p.pdf), §§8.2.9.15–8.2.9.17.
- [TS 24.008 V20.0.0](https://ftp.3gpp.org/Specs/archive/24_series/24.008/24008-k00.zip), §10.5.6.3 (APCO contents and directional length fields).
- [TS 24.008 V18.8.0](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/18.08.00_60/ts_124008v180800p.pdf), §10.5.5.36 (PLMN value).
- [TS 29.274 V18.8.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/18.08.00_60/ts_129274v180800p.pdf), §§7.2.1, 7.2.2, 8.12, 8.94.
- TS 24.007 §11.2.3.1b and TS 24.501 §9.11.2.8 define the shared identity and S-NSSAI values.
- [RFC 7296 §3.10](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.10), Protocol ID handling for an empty SPI.
