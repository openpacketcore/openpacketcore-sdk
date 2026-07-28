//! Offending-IE identity carried out of the GTPv2-C decode spine.
//!
//! GTPv2-C framing already knows which Information Element failed whenever a
//! complete four-octet TLIV header has been read. These tests pin which error
//! classes name an element, which honestly name none, and that a grouped
//! member's identity is never presented as a top-level one.
//!
//! Naming the offending IE is *necessary but not sufficient* to decide that a
//! TS 29.274 error response is owed; that decision belongs to
//! `Gtpv2cErrorResponsePlanner` and is pinned in `error_response_plans.rs`.

use opc_proto_gtpv2c::{
    validate_ie_region_annotated, Gtpv2cDecodeError, Gtpv2cOffendingIe, Message, RawIeIterator,
    S2bMessage, IE_TYPE_BEARER_CONTEXT, IE_TYPE_CAUSE, IE_TYPE_NODE_IDENTIFIER,
};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, UnknownIePolicy,
    ValidationLevel,
};

/// TS 29.274 clause 5.5: version 2, TEID flag set, twelve-octet header. The
/// Length field counts everything after the first four octets.
const CREATE_SESSION_REQUEST: u8 = 32;

fn message(ies: &[u8]) -> Vec<u8> {
    let body_len = u16::try_from(8 + ies.len()).expect("test message fits the Length field");
    let mut out = vec![0x48, CREATE_SESSION_REQUEST];
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    out.extend_from_slice(ies);
    out
}

fn ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("test IE value fits u16");
    let mut out = vec![ie_type];
    out.extend_from_slice(&length.to_be_bytes());
    out.push(instance & 0x0f);
    out.extend_from_slice(value);
    out
}

/// A TLIV header whose declared length does not match the octets that follow.
fn ie_with_declared_length(ie_type: u8, instance: u8, declared: u16, value: &[u8]) -> Vec<u8> {
    let mut out = vec![ie_type];
    out.extend_from_slice(&declared.to_be_bytes());
    out.push(instance & 0x0f);
    out.extend_from_slice(value);
    out
}

fn identity(ie_type: u8, instance: u8) -> Gtpv2cOffendingIe {
    Gtpv2cOffendingIe::new(ie_type, instance).expect("test instance fits four bits")
}

fn strict() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn decode_region(region: &[u8], ctx: DecodeContext) -> Gtpv2cDecodeError {
    validate_ie_region_annotated(region, ctx)
        .expect_err("the region under test must fail validation")
}

fn decode_message(region: &[u8], ctx: DecodeContext) -> Gtpv2cDecodeError {
    let wire = message(region);
    // A raw-framing failure is raised by `Message`'s own pre-validation, which
    // `S2bMessage::decode` runs first. Where both see it, they must agree.
    if let Err(via_message) = Message::decode_annotated(&wire, ctx) {
        let via_s2b = S2bMessage::decode(&wire, ctx).expect_err("the message under test must fail");
        assert_eq!(
            via_message.offending_ie(),
            via_s2b.offending_ie(),
            "Message::decode_annotated and S2bMessage::decode disagreed on identity"
        );
        assert_eq!(via_message.enclosing_ie(), via_s2b.enclosing_ie());
    }
    S2bMessage::decode(&wire, ctx).expect_err("the message under test must fail")
}

/// B1. A complete four-octet header followed by a declared length that
/// overruns the remaining input is exactly the case TS 29.274 calls an invalid
/// length, and exactly the case a responder needs an identity for. The decoder
/// holds the Type and Instance in registers at that point, so it reports them.
///
/// Asserted through every surface that can observe it, including
/// `Message::decode_annotated` and `S2bMessage::decode`: `Message`'s
/// `BorrowDecode` impl pre-validates the whole top-level IE region, so without
/// the parallel inherent entry point the annotation would be stripped before
/// any S2b caller could see it.
#[test]
fn overrun_after_a_complete_header_names_the_offending_ie() {
    let region = ie_with_declared_length(IE_TYPE_NODE_IDENTIFIER, 3, 16, &[0xaa, 0xbb]);
    let expected = identity(IE_TYPE_NODE_IDENTIFIER, 3);

    let via_region = decode_region(&region, DecodeContext::default());
    assert!(matches!(via_region.code(), DecodeErrorCode::Truncated));
    assert_eq!(via_region.offset(), 0);
    assert_eq!(via_region.offending_ie(), Some(expected));
    assert_eq!(via_region.enclosing_ie(), None);
    assert_eq!(
        via_region.top_level_offending_ie(),
        None,
        "a standalone IE region does not prove message-top-level scope"
    );

    let mut iter = RawIeIterator::new(&region, DecodeContext::default());
    let via_iterator = iter
        .next_annotated()
        .expect("the iterator yields the failure")
        .expect_err("the overrunning IE must fail");
    assert_eq!(via_iterator.offending_ie(), Some(expected));
    assert_eq!(via_iterator.top_level_offending_ie(), None);

    let wire = message(&region);
    let via_message = Message::decode_annotated(&wire, DecodeContext::default())
        .expect_err("the raw IE region pre-validation must fail");
    assert_eq!(via_message.offending_ie(), Some(expected));
    assert_eq!(via_message.enclosing_ie(), None);
    assert_eq!(via_message.top_level_offending_ie(), Some(expected));

    let via_s2b = S2bMessage::decode(&wire, DecodeContext::default())
        .expect_err("the typed S2b decode must fail");
    assert_eq!(via_s2b.offending_ie(), Some(expected));
    assert_eq!(via_s2b.top_level_offending_ie(), Some(expected));

    let via_diagnostics = S2bMessage::decode_with_diagnostics(&wire, DecodeContext::default())
        .expect_err("the diagnostic decode must fail");
    assert_eq!(via_diagnostics.offending_ie(), Some(expected));
}

/// B2. Fewer than four octets remain, so `input[0]` and `input[3]` -- the Type
/// and Instance -- are not present. Absence of identity is the honest answer,
/// not a gap: there is no element to name yet.
#[test]
fn a_partial_ie_header_names_no_offending_ie() {
    let region = [IE_TYPE_NODE_IDENTIFIER, 0x00];

    let error = decode_region(&region, DecodeContext::default());
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
    assert_eq!(error.offending_ie(), None);
    assert_eq!(error.enclosing_ie(), None);

    let via_s2b = decode_message(&region, DecodeContext::default());
    assert_eq!(via_s2b.offending_ie(), None);
    assert_eq!(via_s2b.enclosing_ie(), None);
}

/// B3. The strict spare-bit check runs after the whole header has been read,
/// so it names the element whose spare nibble is non-zero, at the offset of the
/// octet that carries it.
#[test]
fn strict_spare_bits_name_the_offending_ie() {
    let mut region = ie(IE_TYPE_NODE_IDENTIFIER, 0, &[]);
    region[3] |= 0x10;

    let error = decode_region(&region, strict());
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
    assert_eq!(error.offset(), 3);
    assert_eq!(
        error.offending_ie(),
        Some(identity(IE_TYPE_NODE_IDENTIFIER, 0))
    );
    assert_eq!(error.enclosing_ie(), None);
}

/// B4. The IE-count bound is a statement about the sequence, not about any one
/// element's octets, so it names nothing even though a complete header was
/// available. Over-reporting here would attribute a resource limit to whichever
/// IE happened to cross it.
#[test]
fn the_ie_count_bound_names_no_offending_ie() {
    let region = ie(IE_TYPE_NODE_IDENTIFIER, 0, &[]);
    let ctx = DecodeContext {
        max_ies: 0,
        ..DecodeContext::default()
    };

    let error = decode_region(&region, ctx);
    assert!(matches!(error.code(), DecodeErrorCode::IeCountExceeded));
    assert_eq!(error.offending_ie(), None);
    assert_eq!(error.enclosing_ie(), None);
}

/// B5. A value-level failure in a leaf IE names that leaf. A Cause IE needs at
/// least the Cause and flags octets, so a one-octet value fails inside the
/// typed decoder rather than during framing.
#[test]
fn a_leaf_value_error_names_the_leaf() {
    let region = ie(IE_TYPE_CAUSE, 0, &[16]);

    let error = decode_message(&region, DecodeContext::default());
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(error.enclosing_ie(), None);
}

/// B6. Inside a grouped IE, the member is named as the offending element and
/// the container is reported separately. The container is *not* the offender:
/// its own octets are well formed.
#[test]
fn a_grouped_member_value_error_names_the_member_and_its_container() {
    let member = ie(IE_TYPE_CAUSE, 0, &[16]);
    let region = ie(IE_TYPE_BEARER_CONTEXT, 1, &member);

    let error = decode_message(&region, DecodeContext::default());
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 1))
    );
    assert_eq!(
        error.top_level_offending_ie(),
        None,
        "a grouped member must not project as a top-level offender"
    );
}

/// B7. The same split for a framing error one level down: a member whose
/// declared length overruns the container's value.
#[test]
fn a_grouped_member_overrun_names_the_member_and_its_container() {
    let member = ie_with_declared_length(IE_TYPE_CAUSE, 0, 16, &[0xaa, 0xbb]);
    let region = ie(IE_TYPE_BEARER_CONTEXT, 0, &member);

    let error = decode_message(&region, DecodeContext::default());
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );
}

/// B8/B14. A grouped member header shorter than four octets identifies no
/// member, and the container must not be substituted for it. Naming IE 93 here
/// would tell a responder that the Bearer Context itself was malformed, which
/// is false: two spliced junk octets inside an otherwise valid container are
/// all a peer needs to provoke this.
#[test]
fn a_partial_grouped_member_header_names_no_member_but_names_the_container() {
    let region = ie(IE_TYPE_BEARER_CONTEXT, 0, &[IE_TYPE_CAUSE, 0x00]);

    let error = decode_message(&region, DecodeContext::default());
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
    assert_eq!(
        error.offending_ie(),
        None,
        "the container must not be reported as the offending element"
    );
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );
}

/// B9. A duplicate rejection is a statement about the repeated element's own
/// octets, so it names that element's key.
#[test]
fn a_rejected_duplicate_names_its_own_key() {
    let mut region = ie(IE_TYPE_CAUSE, 0, &[16, 0]);
    region.extend_from_slice(&ie(IE_TYPE_CAUSE, 0, &[16, 0]));
    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };

    let error = decode_message(&region, ctx);
    assert!(matches!(error.code(), DecodeErrorCode::DuplicateIe));
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(error.enclosing_ie(), None);
}

/// B10. An unknown critical IE names itself: its header was read, and the
/// rejection is about that element.
#[test]
fn an_unknown_critical_ie_names_itself() {
    let region = ie(0xfe, 2, &[0x00]);
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };

    let error = decode_message(&region, ctx);
    assert!(matches!(error.code(), DecodeErrorCode::UnknownCriticalIe));
    assert_eq!(error.offending_ie(), Some(identity(0xfe, 2)));
    assert_eq!(error.enclosing_ie(), None);
}

/// B11. The depth bound is a resource limit reached before any member header
/// is read, so it names no element -- and the container is not substituted.
#[test]
fn the_depth_bound_names_no_offending_ie() {
    let member = ie(IE_TYPE_CAUSE, 0, &[16, 0]);
    let region = ie(IE_TYPE_BEARER_CONTEXT, 0, &member);
    let ctx = DecodeContext {
        max_depth: 0,
        ..DecodeContext::default()
    };

    let error = decode_message(&region, ctx);
    assert!(matches!(error.code(), DecodeErrorCode::DepthExceeded));
    assert_eq!(error.offending_ie(), None);
    assert_eq!(error.enclosing_ie(), None);
}

/// Grouping scope is orthogonal to the failure class. The enclosing identity is
/// attached at the single exit of the scope it describes, so *every* class a
/// nested sequence can raise reports the container -- not only the grouped
/// member value and framing failures that have their own rows above.
///
/// This is the guard on the documented conversion precondition. A caller who
/// read the top-level rows as unconditional would treat the
/// `enclosing_ie().is_none()` check as dead code for these classes and emit a
/// Cause naming a member as a top-level element.
#[test]
fn every_nested_failure_class_names_its_container() {
    let cause = ie(IE_TYPE_CAUSE, 0, &[16, 0]);

    // Duplicate rejection one level down.
    let mut members = cause.clone();
    members.extend_from_slice(&cause);
    let error = decode_message(
        &ie(IE_TYPE_BEARER_CONTEXT, 0, &members),
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            ..DecodeContext::default()
        },
    );
    assert!(matches!(error.code(), DecodeErrorCode::DuplicateIe));
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0)),
        "a nested duplicate rejection must report its container"
    );

    // Unknown critical IE one level down.
    let error = decode_message(
        &ie(IE_TYPE_BEARER_CONTEXT, 0, &ie(0xfe, 2, &[0x00])),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        },
    );
    assert!(matches!(error.code(), DecodeErrorCode::UnknownCriticalIe));
    assert_eq!(error.offending_ie(), Some(identity(0xfe, 2)));
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );

    // Strict spare-bit violation one level down.
    let mut spare_member = cause.clone();
    spare_member[3] |= 0x10;
    let error = decode_message(&ie(IE_TYPE_BEARER_CONTEXT, 0, &spare_member), strict());
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
    assert_eq!(error.offending_ie(), Some(identity(IE_TYPE_CAUSE, 0)));
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );

    // A sequence bound one level down still names no member, but the container
    // is reported: the bound was reached inside that scope.
    let mut two = cause.clone();
    two.extend_from_slice(&ie(IE_TYPE_CAUSE, 1, &[16, 0]));
    let error = decode_message(
        &ie(IE_TYPE_BEARER_CONTEXT, 0, &two),
        DecodeContext {
            max_ies: 1,
            ..DecodeContext::default()
        },
    );
    assert!(matches!(error.code(), DecodeErrorCode::IeCountExceeded));
    assert_eq!(error.offending_ie(), None);
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );

    // The depth bound tripped by a nested container, rather than at top level.
    let inner = ie(IE_TYPE_BEARER_CONTEXT, 1, &cause);
    let error = decode_message(
        &ie(IE_TYPE_BEARER_CONTEXT, 0, &inner),
        DecodeContext {
            max_depth: 1,
            ..DecodeContext::default()
        },
    );
    assert!(matches!(error.code(), DecodeErrorCode::DepthExceeded));
    assert_eq!(error.offending_ie(), None);
    assert_eq!(
        error.enclosing_ie(),
        Some(identity(IE_TYPE_BEARER_CONTEXT, 0))
    );
}

/// A hand-built `RawIe` is not wire-decoded, and `RawIe::instance` is a public
/// field, so `TypedIe::decode_from_raw` can be handed an instance wider than
/// the four-bit wire field. That must stay a decode failure like any other: an
/// element identity derived from it would name a different element, and a
/// decoder reached from untrusted input must not assert on its input.
#[test]
fn a_caller_supplied_instance_wider_than_four_bits_does_not_panic() {
    use opc_proto_gtpv2c::{RawIe, TypedIe};

    let raw = RawIe {
        ie_type: IE_TYPE_NODE_IDENTIFIER,
        instance: 0xff,
        spare: 0,
        // A Node Identifier whose Node Name length octet overruns the value.
        value: &[0x09, b'a'],
    };

    let error = TypedIe::decode_from_raw(raw, DecodeContext::default(), 0, 0)
        .expect_err("a malformed Node Identifier value must fail");
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
}

/// B12/B13. `DecodeError::offset` keeps its full `usize` range: a caller-
/// supplied absolute base above `u32::MAX` is reported back exactly, neither
/// truncated nor saturated. This is the standing detector for a narrowing
/// regression in the shared error type.
///
/// The `cfg` gate is mandatory, not defensive: `(u32::MAX as usize) + 1`
/// overflows on the 32-bit lane this crate is also tested on.
#[test]
#[cfg(target_pointer_width = "64")]
fn an_offset_above_u32_max_is_reported_exactly() {
    // Imported here rather than at module scope: the whole test is gated to
    // 64-bit targets, and an unconditional import would warn on the 32-bit lane.
    use opc_proto_gtpv2c::{RawIe, TypedIe};

    let base = (u32::MAX as usize) + 1;

    let region = ie_with_declared_length(IE_TYPE_NODE_IDENTIFIER, 0, 16, &[0xaa, 0xbb]);
    let mut iter = RawIeIterator::new_at_offset(&region, DecodeContext::default(), base);
    let framing = iter
        .next_annotated()
        .expect("the iterator yields the failure")
        .expect_err("the overrunning IE must fail");
    assert_eq!(framing.offset(), base, "the framing offset was narrowed");

    let raw = RawIe {
        ie_type: IE_TYPE_NODE_IDENTIFIER,
        instance: 0,
        spare: 0,
        value: &[0x09, b'a'],
    };
    let value = TypedIe::decode_from_raw(raw, DecodeContext::default(), 0, base)
        .expect_err("a malformed Node Identifier value must fail");
    assert_eq!(
        value.offset(),
        base + 4,
        "the value offset was narrowed or saturated"
    );
}

/// Offset arithmetic is sequence-coordinate bookkeeping, not evidence that an
/// IE's received octets are malformed. A complete header is available here,
/// but computing the strict spare-bit field's absolute offset overflows, so
/// the failure must not inherit the header's identity.
#[test]
fn offset_arithmetic_overflow_names_no_offending_ie() {
    let mut region = ie(IE_TYPE_NODE_IDENTIFIER, 3, &[]);
    region[3] |= 0x10;
    let mut iter = RawIeIterator::new_at_offset(&region, strict(), usize::MAX);

    let error = iter
        .next_annotated()
        .expect("the iterator yields the arithmetic failure")
        .expect_err("the absolute spare-bit offset must overflow");
    assert!(matches!(error.code(), DecodeErrorCode::LengthOverflow));
    assert_eq!(error.offset(), usize::MAX);
    assert_eq!(error.offending_ie(), None);
    assert_eq!(error.enclosing_ie(), None);
    assert_eq!(error.top_level_offending_ie(), None);
}

/// The over-claim guard for TS 29.274 clause 8.4.
///
/// This crate's Cause encoder hardcodes the flags octet to zero (see
/// `error_response.rs` and `s2b.rs`), and a zeroed flags octet asserts that the
/// offending IE was at message top level. Feeding a grouped member's identity
/// through it would name an element that never appeared at top level -- here,
/// IE 2, when the message's top level carries only IE 93.
///
/// `top_level_offending_ie()` is the checked projection used by the response
/// planner bridge. What this test pins is that the raw diagnostic evidence
/// remains available while the disposition projection refuses the grouped
/// member, whose unguarded reading really would be false on this input.
#[test]
fn naming_the_offending_ie_does_not_name_a_top_level_ie_when_it_was_nested() {
    let member = ie_with_declared_length(IE_TYPE_CAUSE, 0, 16, &[0xaa, 0xbb]);
    let region = ie(IE_TYPE_BEARER_CONTEXT, 0, &member);
    let error = decode_message(&region, DecodeContext::default());

    assert!(error.offending_ie().is_some());
    assert!(error.enclosing_ie().is_some());

    // The checked conversion refuses, so no Cause naming a top-level IE 2 can
    // be built from the decoder evidence through the supported bridge.
    let cause_identity = error.top_level_offending_ie();
    assert_eq!(
        cause_identity, None,
        "a grouped member's identity escaped the enclosing-IE guard"
    );

    // And the unguarded conversion really would be a lie: the message's top
    // level carries no IE 2 at all.
    let wire = message(&region);
    let (_, decoded) = Message::decode_annotated(&wire, DecodeContext::default())
        .expect("the top-level IE region is well formed");
    let top_level: Vec<u8> = decoded
        .ies()
        .map(|item| item.expect("top-level framing is valid").ie_type)
        .collect();
    assert_eq!(top_level, vec![IE_TYPE_BEARER_CONTEXT]);
    assert!(!top_level.contains(&IE_TYPE_CAUSE));
}

/// B24. `Display` delegates verbatim to the shared error, so no existing log
/// or panic string changes when a decode failure gains an identity. Identity is
/// reachable through the accessors and `Debug` only.
#[test]
fn decode_error_display_is_unchanged() {
    let plain = DecodeError::new(DecodeErrorCode::Truncated, 7);
    assert_eq!(
        Gtpv2cDecodeError::new(plain.clone()).to_string(),
        plain.to_string()
    );

    let region = ie_with_declared_length(IE_TYPE_NODE_IDENTIFIER, 3, 16, &[0xaa, 0xbb]);
    let annotated = decode_region(&region, DecodeContext::default());
    assert!(annotated.offending_ie().is_some());
    assert_eq!(annotated.to_string(), annotated.error().to_string());
    assert!(!annotated.to_string().contains("176"));
}

/// B25. `?` from a rich frame into a `DecodeError`-returning frame compiles and
/// drops the identity while preserving code, offset and spec reference. The
/// downgrade is deliberate and lossy; it is what lets the shared
/// `BorrowDecode` port keep a protocol-neutral error type.
#[test]
fn downgrading_to_the_shared_error_preserves_everything_but_identity() {
    let region = ie_with_declared_length(IE_TYPE_NODE_IDENTIFIER, 3, 16, &[0xaa, 0xbb]);
    let annotated = decode_region(&region, DecodeContext::default());
    let expected = annotated.error().clone();

    let downgraded: DecodeError = annotated.into();
    assert_eq!(downgraded, expected);

    // The trait-based path is the one callers actually take.
    let wire = message(&region);
    let via_port =
        <Message<'_> as opc_protocol::BorrowDecode<'_>>::decode(&wire, DecodeContext::default())
            .expect_err("the port must still report the failure");
    assert_eq!(via_port, expected);

    // `S2bMessage`'s port impl is a one-line delegate to the inherent `decode`.
    // Nothing in the type system distinguishes that from a self-call: were the
    // inherent method removed or shadowed, `Self::decode` would bind to the
    // trait method and still compile, recursing on attacker-supplied input.
    // Exercising the port is what makes that a test failure rather than a
    // stack overflow in production.
    let via_s2b_port =
        <S2bMessage<'_> as opc_protocol::BorrowDecode<'_>>::decode(&wire, DecodeContext::default())
            .expect_err("the S2b port must still report the failure");
    assert_eq!(
        via_s2b_port,
        S2bMessage::decode(&wire, DecodeContext::default())
            .expect_err("the inherent entry point must fail identically")
            .into_error()
    );
}
