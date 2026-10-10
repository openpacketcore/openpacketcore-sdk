use super::{notice::*, wire::*};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    let (pairs, remainder) = value.as_str().unwrap().as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn bind_snapshot(pages: &mut [NoticePage]) {
    let first = &pages[0];
    let mut commitment =
        NoticeCommitment::new(&first.boot, first.generation, &first.authority, first.total)
            .unwrap();
    for page in pages.iter() {
        commitment.append(&page.entries).unwrap();
    }
    let id = commitment.finish().unwrap();
    for page in pages {
        page.notice_id = id;
    }
}

#[test]
fn ticket_notice_matches_normative_bytes_and_is_only_complete_for_the_own_boot() {
    let v = vectors();
    let encoded = bytes(&v["ticket_notice"]["page_hex"]);
    let page = NoticePage::decode(&encoded).unwrap();
    assert_eq!(page.encode().unwrap(), encoded);
    assert_eq!(page.generation, 128);
    assert_eq!(page.entries.len(), 1);
    let mut rebuilt = [page.clone()];
    bind_snapshot(&mut rebuilt);
    assert_eq!(
        rebuilt[0].notice_id, page.notice_id,
        "notice ID must commit the normative ordered evidence set"
    );
    let input = bytes(&v["ticket_notice"]["id_input_hex"]);
    assert_eq!(
        hash(&input).as_slice(),
        bytes(&v["ticket_notice"]["id_digest_hex"])
    );
    assert_eq!(page.notice_id.as_slice(), &hash(&input)[..16]);
    let mut receiver = NoticeSequence::new(page.boot.clone());
    let entries = receiver.accept_page(page.clone()).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(receiver.is_complete());
    assert_eq!(receiver.ticket().unwrap().generation, 128);
    assert!(
        receiver.accept_page(page.clone()).is_err(),
        "a page cannot be consumed twice"
    );
    let mut other = page.boot.clone();
    other.process[0] ^= 1;
    assert!(NoticeSequence::new(other).accept_page(page).is_err());
}

#[test]
fn notice_identity_commits_every_predecessor_evidence_field() {
    let v = vectors();
    let page = NoticePage::decode(&bytes(&v["ticket_notice"]["page_hex"])).unwrap();
    for change in 0..5 {
        let mut altered = page.clone();
        let entry = &mut altered.entries[0];
        match change {
            0 => entry.digest[0] ^= 1,
            1 => *entry.predecessor.last_mut().unwrap() ^= 1,
            2 => entry.record.as_mut().unwrap().record_uid[0] ^= 1,
            3 => entry.record.as_mut().unwrap().revision[0] ^= 1,
            _ => {
                entry.kind = 2;
                entry.record = None;
            }
        }
        // All changes remain structurally valid and keep the entry count.
        let altered = NoticePage::decode(&altered.encode().unwrap()).unwrap();
        let mut receiver = NoticeSequence::new(page.boot.clone());
        assert!(
            receiver.accept_page(altered).is_err(),
            "notice identity must bind evidence field {change}"
        );
        assert!(receiver.ticket().is_none());
    }
}

#[test]
fn refreshed_notice_replaces_only_a_complete_content_bound_snapshot_for_the_same_ticket() {
    let v = vectors();
    let page = NoticePage::decode(&bytes(&v["ticket_notice"]["page_hex"])).unwrap();
    for fixture in v["ticket_notice_refreshes"].as_array().unwrap() {
        let snapshot = NoticePage::decode(&bytes(&fixture["page_hex"])).unwrap();
        assert_eq!(
            snapshot.notice_id.as_slice(),
            &hash(&bytes(&fixture["id_input_hex"]))[..16]
        );
        let mut checked = NoticeSequence::new(page.boot.clone());
        checked.accept_page(snapshot).unwrap();
        assert!(checked.is_complete());
    }
    let mut empty = page.clone();
    empty.total = 0;
    empty.entries.clear();
    bind_snapshot(std::slice::from_mut(&mut empty));
    let mut first = NoticeSequence::new(page.boot.clone());
    first.accept_page(empty.clone()).unwrap();
    let old = first.ticket().unwrap().clone();

    // A predecessor becomes visible after ticket issuance. A new authenticated
    // exchange can deliver it while preserving the exact issuance and boot.
    let mut refreshed = NoticeSequence::new(page.boot.clone());
    refreshed.accept_page(page.clone()).unwrap();
    let later = refreshed.ticket().unwrap();
    assert_ne!(old.notice_id, later.notice_id);
    assert!(old.boot == later.boot);
    assert_eq!(old.generation, later.generation);
    assert!(old.authority == later.authority);
    let mut repeated = NoticeSequence::new(page.boot.clone());
    repeated.accept_page(page.clone()).unwrap();
    assert_eq!(later.notice_id, repeated.ticket().unwrap().notice_id);

    // Equal entry counts do not identify a snapshot: evidence can change too.
    let mut changed = page.clone();
    changed.entries[0].digest[0] ^= 1;
    bind_snapshot(std::slice::from_mut(&mut changed));
    assert_ne!(page.notice_id, changed.notice_id);
    let mut next = NoticeSequence::new(changed.boot.clone());
    next.accept_page(changed).unwrap();
    assert!(next.is_complete());
}

#[test]
fn delivered_closure_hints_expose_the_typed_evidence_and_opaque_record_reference() {
    use opc_session_store::scope_authority::{ScopeAuthorityStamp, ScopeClosureKind};
    let v = vectors();
    let page = NoticePage::decode(&bytes(&v["ticket_notice"]["page_hex"])).unwrap();
    let final_hint = page.entries[0].clone();
    let record = final_hint.record.clone().unwrap();
    let notice = super::ClosureNotice { hint: final_hint };
    ScopeAuthorityStamp::decode_canonical(notice.predecessor_bytes()).unwrap();
    let evidence = notice
        .evidence()
        .expect("the delivery API exposes the exact closure kind");
    assert_eq!(evidence.kind(), ScopeClosureKind::FinalTermination);
    assert_eq!(evidence.digest(), notice.evidence_digest());
    assert_eq!(
        notice.record_reference(),
        Some((record.record_uid.as_slice(), record.revision.as_slice()))
    );

    let mut closed = page;
    closed.entries[0].kind = 2;
    closed.entries[0].record = None;
    let decoded = NoticePage::decode(&closed.encode().unwrap()).unwrap();
    let notice = super::ClosureNotice {
        hint: decoded.entries[0].clone(),
    };
    assert_eq!(
        notice.evidence().unwrap().kind(),
        ScopeClosureKind::CommittedClose
    );
    assert_eq!(notice.record_reference(), None);
}

#[test]
fn paged_notice_is_bounded_sorted_contiguous_and_restarts_after_a_lost_connection() {
    let v = vectors();
    let mut page = NoticePage::decode(&bytes(&v["ticket_notice"]["page_hex"])).unwrap();
    let entry = page.entries[0].clone();
    page.total = 9;
    page.entries = (1..=8)
        .map(|index| {
            let mut value = entry.clone();
            *value.predecessor.last_mut().unwrap() = index;
            value
        })
        .collect();
    let mut last = page.clone();
    last.first = 8;
    last.entries = vec![entry];
    *last.entries[0].predecessor.last_mut().unwrap() = 9;
    let mut pages = [page, last];
    bind_snapshot(&mut pages);
    let [page, last] = pages;
    let mut receiver = NoticeSequence::new(page.boot.clone());
    receiver.accept_page(page.clone()).unwrap();
    assert!(!receiver.is_complete());
    assert!(receiver.ticket().is_none());
    let mut restarted = NoticeSequence::new(page.boot.clone());
    assert!(
        restarted.accept_page(last.clone()).is_err(),
        "new connection begins at page zero"
    );
    let mut duplicate = page.clone();
    duplicate.entries[1] = duplicate.entries[0].clone();
    assert!(duplicate.encode().is_err());
    let mut mixed = last.clone();
    mixed.notice_id[0] ^= 1;
    assert!(receiver.accept_page(mixed).is_err());
    // A bad page poisons this attempt; a fresh exchange replays the complete set.
    assert!(receiver.accept_page(last.clone()).is_err());
    let mut changed = last.clone();
    changed.entries[0].digest[0] ^= 1;
    let mut inconsistent = NoticeSequence::new(page.boot.clone());
    inconsistent.accept_page(page.clone()).unwrap();
    assert!(
        inconsistent.accept_page(changed).is_err(),
        "all pages contribute to the content commitment"
    );
    assert!(inconsistent.ticket().is_none());
    let mut fresh = NoticeSequence::new(page.boot.clone());
    fresh.accept_page(page).unwrap();
    fresh.accept_page(last).unwrap();
    assert!(fresh.is_complete());
}

#[test]
fn notice_rejects_duplicate_or_descending_predecessors_across_pages() {
    let v = vectors();
    let template = NoticePage::decode(&bytes(&v["ticket_notice"]["page_hex"])).unwrap();
    for boundary in [7, 8, 9] {
        let mut first = template.clone();
        first.total = 9;
        first.entries = (1..=8)
            .map(|index| {
                let mut entry = template.entries[0].clone();
                *entry.predecessor.last_mut().unwrap() = index;
                entry
            })
            .collect();
        let mut last = template.clone();
        last.total = 9;
        last.first = 8;
        *last.entries[0].predecessor.last_mut().unwrap() = boundary;

        // Compute the full content ID without NoticeCommitment::append: a bad
        // ID must not hide removal of the cross-page ordering check.
        let mut input = b"openpacketcore/scope/ticket-notice-id/v1\0".to_vec();
        input.extend_from_slice(&first.boot.scope.encode());
        input.extend_from_slice(&first.boot.workload);
        input.extend_from_slice(&first.boot.process);
        input.extend_from_slice(&first.boot.key);
        input.extend_from_slice(&first.generation.to_be_bytes());
        first.authority.write(&mut input).unwrap();
        input.extend_from_slice(&first.total.to_be_bytes());
        for entry in first.entries.iter().chain(&last.entries) {
            put_lp32(&mut input, &entry.predecessor).unwrap();
            input.push(entry.kind);
            input.extend_from_slice(&entry.digest);
            entry.record.as_ref().unwrap().write(&mut input).unwrap();
        }
        let id: [u8; 16] = hash(&input)[..16].try_into().unwrap();
        first.notice_id = id;
        last.notice_id = id;
        // Each page is independently well formed and sorted, even when its
        // boundary duplicates or precedes the previous page's final entry.
        let first = NoticePage::decode(&first.encode().unwrap()).unwrap();
        let last = NoticePage::decode(&last.encode().unwrap()).unwrap();
        let mut commitment =
            NoticeCommitment::new(&first.boot, first.generation, &first.authority, first.total)
                .unwrap();
        commitment.append(&first.entries).unwrap();
        let mut receiver = NoticeSequence::new(first.boot.clone());
        receiver.accept_page(first).unwrap();
        assert!(receiver.ticket().is_none());
        if boundary <= 8 {
            assert_eq!(
                commitment.append(&last.entries),
                Err(WireError),
                "notice commitment must reject cross-page predecessor {boundary} after 8"
            );
            assert!(receiver.accept_page(last).is_err());
            assert!(!receiver.is_complete());
            assert!(receiver.ticket().is_none());
        } else {
            commitment.append(&last.entries).unwrap();
            assert_eq!(commitment.finish().unwrap(), id);
            receiver.accept_page(last).unwrap();
            assert!(receiver.is_complete());
            assert_eq!(receiver.ticket().unwrap().notice_id, id);
        }
    }
}

#[test]
fn notice_does_not_accept_unbounded_or_ambiguous_claims() {
    let v = vectors();
    let encoded = bytes(&v["ticket_notice"]["page_hex"]);
    let page = NoticePage::decode(&encoded).unwrap();
    for length in 0..encoded.len() {
        assert!(NoticePage::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NoticePage::decode(&trailing).is_err());
    for generation in [0, u64::MAX] {
        let mut bad = page.clone();
        bad.generation = generation;
        assert!(bad.encode().is_err());
    }
    let mut local = page.clone();
    local.entries[0].kind = 0;
    assert!(local.encode().is_err());
    let mut missing = page.clone();
    missing.entries[0].record = None;
    assert!(missing.encode().is_err());
    let mut oversized = page.clone();
    oversized.entries[0].predecessor = vec![1; 4097];
    assert!(oversized.encode().is_err());
    assert!(AuthorityReference::new(vec![], vec![1]).is_err());
    assert!(AuthorityReference::new(vec![1], vec![2; 257]).is_err());
}
