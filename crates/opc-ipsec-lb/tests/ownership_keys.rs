use std::collections::{BTreeSet, HashSet};

use opc_ipsec_lb::{
    DestinationContext, EligibleOwnershipMembers, EspEncapsulationKind, EspOwnershipKey, EspSpi,
    EstablishedIkeOwnershipKey, IkeSpi, InitialExchangeDiscriminator, InitialIkeOwnershipKey,
    IpAddress, MembershipGeneration, OuterSourceTuple, OwnershipCollision, OwnershipKeyError,
    OwnershipSelectionError, RendezvousSelector, RoutingDomainTag, SessionOwnershipKey, ShardId,
    MAX_ELIGIBLE_OWNERS, OWNERSHIP_KEY_ENCODING_VERSION, OWNERSHIP_KEY_MAX_ENCODED_BYTES,
};

fn destination(address: [u8; 4]) -> DestinationContext {
    DestinationContext::new(IpAddress::V4(address), RoutingDomainTag::new(17))
}

fn ike_spi(value: u64) -> IkeSpi {
    IkeSpi::new(value).unwrap()
}

fn esp_spi(value: u32) -> EspSpi {
    EspSpi::new(value).unwrap()
}

fn initial_key(destination: DestinationContext, initiator_spi: u64) -> InitialIkeOwnershipKey {
    InitialIkeOwnershipKey::new(
        destination,
        OuterSourceTuple::new(IpAddress::V4([203, 0, 113, 9]), 45_000),
        ike_spi(initiator_spi),
        InitialExchangeDiscriminator::IKE_SA_INIT,
    )
}

fn esp_key(destination: DestinationContext, spi: u32) -> SessionOwnershipKey {
    EspOwnershipKey::new(
        destination,
        EspEncapsulationKind::UdpEncapsulated,
        esp_spi(spi),
    )
    .into()
}

fn membership(generation: u64, members: &[u16]) -> EligibleOwnershipMembers {
    EligibleOwnershipMembers::new(
        MembershipGeneration::new(generation).unwrap(),
        members.iter().copied().map(ShardId::new).collect(),
    )
    .unwrap()
}

#[test]
fn every_key_form_round_trips_through_canonical_and_serde_encodings() {
    let destination = destination([192, 0, 2, 10]);
    let initial = initial_key(destination, 0x0102_0304_0506_0708);
    let keys = [
        SessionOwnershipKey::InitialIke(initial),
        SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
            destination,
            initial.initiator_spi(),
            ike_spi(0x1112_1314_1516_1718),
        )),
        esp_key(destination, 0x2021_2223),
    ];

    for key in keys {
        let canonical = key.to_canonical_bytes();
        assert!(canonical.len() <= OWNERSHIP_KEY_MAX_ENCODED_BYTES);
        assert_eq!(canonical[4], OWNERSHIP_KEY_ENCODING_VERSION);
        assert_eq!(
            SessionOwnershipKey::from_canonical_bytes(&canonical).unwrap(),
            key
        );

        let json = serde_json::to_vec(&key).unwrap();
        assert_eq!(
            serde_json::from_slice::<SessionOwnershipKey>(&json).unwrap(),
            key
        );
    }
}

#[test]
fn ipv6_initial_key_exactly_fits_the_documented_encoding_bound() {
    let key = SessionOwnershipKey::InitialIke(InitialIkeOwnershipKey::new(
        DestinationContext::new(
            IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            RoutingDomainTag::new(u64::MAX),
        ),
        OuterSourceTuple::new(
            IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            u16::MAX,
        ),
        ike_spi(u64::MAX),
        InitialExchangeDiscriminator::IKE_SA_INIT,
    ));

    assert_eq!(
        key.to_canonical_bytes().len(),
        OWNERSHIP_KEY_MAX_ENCODED_BYTES
    );
}

#[test]
fn canonical_decoder_fails_closed_on_every_truncation_and_trailing_input() {
    let key = esp_key(destination([192, 0, 2, 10]), 0x0102_0304);
    let canonical = key.to_canonical_bytes();

    for length in 0..canonical.len() {
        assert_eq!(
            SessionOwnershipKey::from_canonical_bytes(&canonical[..length]),
            Err(OwnershipKeyError::TruncatedEncoding)
        );
    }

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&trailing),
        Err(OwnershipKeyError::TrailingEncoding)
    );

    let oversized = vec![0; OWNERSHIP_KEY_MAX_ENCODED_BYTES + 1];
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&oversized),
        Err(OwnershipKeyError::EncodingTooLong)
    );
}

#[test]
fn canonical_decoder_rejects_unknown_fields_and_reserved_spis() {
    let key = esp_key(destination([192, 0, 2, 10]), 0x0102_0304);
    let canonical = key.to_canonical_bytes();

    let mut bad_magic = canonical.clone();
    bad_magic[0] ^= 0xff;
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&bad_magic),
        Err(OwnershipKeyError::InvalidEncodingMagic)
    );

    let mut bad_version = canonical.clone();
    bad_version[4] = OWNERSHIP_KEY_ENCODING_VERSION + 1;
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&bad_version),
        Err(OwnershipKeyError::UnsupportedEncodingVersion)
    );

    let mut bad_kind = canonical.clone();
    bad_kind[5] = 0xff;
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&bad_kind),
        Err(OwnershipKeyError::UnknownKeyKind)
    );

    let mut bad_family = canonical.clone();
    bad_family[14] = 5;
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&bad_family),
        Err(OwnershipKeyError::UnknownAddressFamily)
    );

    let mut bad_encapsulation = canonical.clone();
    let encapsulation_offset = canonical.len() - 5;
    bad_encapsulation[encapsulation_offset] = 0xff;
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&bad_encapsulation),
        Err(OwnershipKeyError::UnknownEspEncapsulation)
    );

    let mut reserved_spi = canonical;
    let spi_offset = reserved_spi.len() - 4;
    reserved_spi[spi_offset..].copy_from_slice(&255u32.to_be_bytes());
    assert_eq!(
        SessionOwnershipKey::from_canonical_bytes(&reserved_spi),
        Err(OwnershipKeyError::ReservedEspSpi)
    );
}

#[test]
fn destination_context_is_structural_for_ordering_and_hashing() {
    let first = esp_key(destination([192, 0, 2, 10]), 0x0102_0304);
    let second = esp_key(destination([198, 51, 100, 10]), 0x0102_0304);
    let other_domain = esp_key(
        DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(18)),
        0x0102_0304,
    );

    assert_ne!(first, second);
    assert_ne!(first, other_domain);
    assert_eq!(BTreeSet::from([first, second, other_domain]).len(), 3);
    assert_eq!(HashSet::from([first, second, other_domain]).len(), 3);
}

#[test]
fn debug_and_display_redact_destination_source_and_spi_values() {
    let key = SessionOwnershipKey::InitialIke(initial_key(
        destination([192, 0, 2, 10]),
        0x0102_0304_0506_0708,
    ));

    for rendered in [format!("{key:?}"), key.to_string()] {
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("192.0.2.10"));
        assert!(!rendered.contains("203.0.113.9"));
        assert!(!rendered.contains("0102030405060708"));
        assert!(!rendered.contains("45000"));
    }
}

#[test]
fn independently_constructed_memberships_select_identical_owners() {
    let first = membership(9, &[4, 2, 0, 3, 1]);
    let second = membership(9, &[0, 1, 2, 3, 4]);
    let selector_a = RendezvousSelector;
    let selector_b = RendezvousSelector;

    for spi in 256..=16_384 {
        let key = esp_key(destination([192, 0, 2, 10]), spi);
        assert_eq!(
            selector_a.select_owner(&first, &key).unwrap().owner(),
            selector_b.select_owner(&second, &key).unwrap().owner()
        );
    }
}

#[test]
fn initial_ike_retransmission_reuses_the_same_tentative_owner() {
    let first_view = membership(9, &[2, 0, 1]);
    let second_view = membership(9, &[0, 1, 2]);
    let first_selector = RendezvousSelector;
    let second_selector = RendezvousSelector;
    let retransmitted = SessionOwnershipKey::InitialIke(initial_key(
        destination([192, 0, 2, 10]),
        0x0102_0304_0506_0708,
    ));

    let first = first_selector
        .select_owner(&first_view, &retransmitted)
        .unwrap();
    let retry = second_selector
        .select_owner(&second_view, &retransmitted)
        .unwrap();
    assert_eq!(first.owner(), retry.owner());
    assert_eq!(first.membership_generation(), retry.membership_generation());
}

#[test]
fn removing_one_member_moves_only_that_members_keys_with_a_measured_bound() {
    let before = membership(10, &[0, 1, 2, 3, 4]);
    let after = membership(11, &[0, 1, 3, 4]);
    let selector = RendezvousSelector;
    let mut moved = 0usize;
    let total = 65_536usize;

    for index in 0..total {
        let key = esp_key(
            destination([192, 0, 2, 10]),
            u32::try_from(index).unwrap() + 256,
        );
        let old_owner = selector.select_owner(&before, &key).unwrap().owner();
        let new_owner = selector.select_owner(&after, &key).unwrap().owner();
        if old_owner != new_owner {
            moved += 1;
            assert_eq!(old_owner, ShardId::new(2));
        }
    }

    assert!(moved > 0);
    assert!(moved <= total / 4, "moved={moved} total={total}");
}

#[test]
fn membership_generation_is_reported_and_enforced_without_forcing_remap() {
    let first = membership(40, &[0, 1, 2]);
    let advanced = membership(41, &[0, 1, 2]);
    let selector = RendezvousSelector;
    let key = esp_key(destination([192, 0, 2, 10]), 0x0102_0304);

    let selection = selector.select_owner(&first, &key).unwrap();
    let advanced_selection = selector.select_owner(&advanced, &key).unwrap();
    assert_eq!(selection.owner(), advanced_selection.owner());
    assert_eq!(selection.membership_generation(), first.generation());
    assert_eq!(
        selection.owner_for_generation(advanced.generation()),
        Err(OwnershipSelectionError::MembershipGenerationMismatch)
    );
    assert_eq!(
        selection.owner_for_generation(first.generation()).unwrap(),
        selection.owner()
    );
}

#[test]
fn member_views_reject_zero_empty_duplicate_and_oversized_inputs() {
    assert_eq!(
        MembershipGeneration::new(0),
        Err(OwnershipSelectionError::ZeroMembershipGeneration)
    );
    let generation = MembershipGeneration::new(1).unwrap();
    assert_eq!(
        EligibleOwnershipMembers::new(generation, Vec::new()),
        Err(OwnershipSelectionError::EmptyMembership)
    );
    assert_eq!(
        EligibleOwnershipMembers::new(generation, vec![ShardId::new(7), ShardId::new(7)]),
        Err(OwnershipSelectionError::DuplicateMember)
    );
    assert_eq!(
        EligibleOwnershipMembers::new(
            generation,
            (0..=MAX_ELIGIBLE_OWNERS)
                .map(|index| ShardId::new(u16::try_from(index).unwrap()))
                .collect(),
        ),
        Err(OwnershipSelectionError::TooManyMembers)
    );
    assert!(serde_json::from_str::<MembershipGeneration>("0").is_err());
}

#[test]
fn same_esp_spi_under_two_destinations_can_resolve_to_distinct_owners() {
    let members = membership(3, &[0, 1, 2, 3, 4]);
    let selector = RendezvousSelector;
    let mut witnessed_distinct_owner = false;

    for spi in 256..=4_096 {
        let first = esp_key(destination([192, 0, 2, 10]), spi);
        let second = esp_key(destination([198, 51, 100, 10]), spi);
        assert_ne!(first, second);
        if selector.select_owner(&members, &first).unwrap().owner()
            != selector.select_owner(&members, &second).unwrap().owner()
        {
            witnessed_distinct_owner = true;
            break;
        }
    }

    assert!(witnessed_distinct_owner);
}

#[test]
fn initial_promotion_retains_complete_continuity_and_never_moves_owner() {
    let members = membership(7, &[0, 1, 2, 3, 4]);
    let selector = RendezvousSelector;
    let initial = initial_key(destination([192, 0, 2, 10]), 0x0102_0304_0506_0708);
    let initial_enum = SessionOwnershipKey::InitialIke(initial);
    let selected = selector.select_owner(&members, &initial_enum).unwrap();
    let promotion = initial.promote(ike_spi(0x1112_1314_1516_1718));
    let established_enum = SessionOwnershipKey::EstablishedIke(promotion.established());
    let carried = selected.carry_forward(promotion).unwrap();

    assert_eq!(promotion.initial(), initial);
    assert_eq!(promotion.established().destination(), initial.destination());
    assert_eq!(
        promotion.established().initiator_spi(),
        initial.initiator_spi()
    );
    assert_eq!(carried.owner(), selected.owner());
    assert_eq!(
        carried.membership_generation(),
        selected.membership_generation()
    );
    assert!(carried.is_for(&established_enum));
    assert!(!carried.is_for(&initial_enum));

    let unrelated = initial_key(destination([192, 0, 2, 11]), 0x2222);
    assert_eq!(
        selected.carry_forward(unrelated.promote(ike_spi(0x3333))),
        Err(OwnershipSelectionError::SelectionKeyMismatch)
    );
}

#[test]
fn collision_surface_distinguishes_exact_protocol_and_destination_scope() {
    let first_destination = destination([192, 0, 2, 10]);
    let second_destination = destination([198, 51, 100, 10]);
    let first = SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
        first_destination,
        ike_spi(1),
        ike_spi(9),
    ));
    let same_responder = SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
        first_destination,
        ike_spi(2),
        ike_spi(9),
    ));
    let other_destination = SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
        second_destination,
        ike_spi(2),
        ike_spi(9),
    ));

    assert_eq!(first.collision_with(first), OwnershipCollision::ExactKey);
    assert_eq!(
        first.collision_with(same_responder),
        OwnershipCollision::EstablishedIkeResponderSpi
    );
    assert_eq!(
        first.collision_with(other_destination),
        OwnershipCollision::None
    );

    let native = SessionOwnershipKey::Esp(EspOwnershipKey::new(
        first_destination,
        EspEncapsulationKind::Native,
        esp_spi(0x1020_3040),
    ));
    let udp = SessionOwnershipKey::Esp(EspOwnershipKey::new(
        first_destination,
        EspEncapsulationKind::UdpEncapsulated,
        esp_spi(0x1020_3040),
    ));
    assert_eq!(
        native.collision_with(udp),
        OwnershipCollision::EspInboundSpi
    );
}
