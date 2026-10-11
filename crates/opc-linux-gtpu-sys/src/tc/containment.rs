use super::*;

pub(super) fn check_owner(
    spec: LocalHookSpec,
    cookie: [u8; 16],
    dump: &TcFilterDump,
) -> Result<(), ScopeError> {
    for bank in spec.banks {
        for slot in [bank.arp, bank.drop] {
            if dump
                .find(slot)
                .and_then(TcFilterIdentity::gact)
                .is_some_and(|action| action.cookie != cookie)
            {
                return Err(ScopeError::OwnerCookieMismatch);
            }
        }
    }
    Ok(())
}

pub(super) fn matches_role(
    dump: &TcFilterDump,
    slot: TcSlot,
    cookie: [u8; 16],
    verdict: TcVerdict,
) -> bool {
    dump.find(slot)
        .and_then(TcFilterIdentity::gact)
        .is_some_and(|action| action.cookie == cookie && action.verdict == verdict)
}

pub(super) fn bank_complete(bank: ContainmentBank, cookie: [u8; 16], dump: &TcFilterDump) -> bool {
    matches_role(dump, bank.arp, cookie, TcVerdict::Pass)
        && matches_role(dump, bank.drop, cookie, TcVerdict::Drop)
}

pub(super) fn software_only(entry: &TcFilterIdentity) -> bool {
    entry.entry.known_summary()
        || entry.gact().is_some()
        || entry
            .bpf()
            .is_some_and(|bpf| matches!(bpf.classifier_flags, 1 | 8 | 9))
}

pub(super) fn eligible_path(
    spec: LocalHookSpec,
    topology: &topology::Topology,
) -> Result<(), ScopeError> {
    if topology.ifindex != spec.ifindex()
        || topology.shared
        || topology.hardware
        || topology.tcx_count != 0
        || (spec.hook() == TcHook::Ingress && !topology.xdp_absent)
    {
        return Err(ScopeError::Coverage);
    }
    Ok(())
}

pub(super) fn inspect(
    spec: LocalHookSpec,
    cookie: [u8; 16],
    data_slots: &[TcSlot],
    dump: &TcFilterDump,
    topology: &topology::Topology,
) -> Result<TcScopeInspection, ScopeError> {
    check_owner(spec, cookie, dump)?;
    eligible_path(spec, topology)?;
    if dump.entries().iter().any(|entry| {
        entry.slot().ifindex != spec.ifindex()
            || entry.slot().hook != spec.hook()
            || !software_only(entry)
            || !topology.clsact
    }) {
        return Err(ScopeError::Coverage);
    }
    let mut occupied = [0; 2];
    for (index, bank) in spec.banks.iter().enumerate() {
        for (slot, verdict) in [(bank.arp, TcVerdict::Pass), (bank.drop, TcVerdict::Drop)] {
            if dump.find(slot).is_some() {
                if !matches_role(dump, slot, cookie, verdict) {
                    return Err(ScopeError::Conflict);
                }
                occupied[index] += 1;
            }
        }
    }
    let last_drop = spec.banks[0].drop.priority.max(spec.banks[1].drop.priority);
    let mut other_filters_present = false;
    let mut foreign_filters_present = false;
    for entry in dump.entries().iter().filter(|entry| !entry.is_summary()) {
        let slot = entry.slot();
        if !spec
            .banks
            .iter()
            .any(|bank| slot == bank.arp || slot == bank.drop)
        {
            // A partial bank is tolerable only when every present component
            // is owned and no other classifier can precede either bank.
            if slot.chain == 0 && slot.priority <= last_drop {
                return Err(ScopeError::Coverage);
            }
            other_filters_present = true;
            foreign_filters_present |= !data_slots.contains(&slot);
        }
    }
    let containment = if occupied == [0, 0] {
        ContainmentInspection::Absent
    } else if occupied.contains(&1) {
        ContainmentInspection::OwnedPartial
    } else {
        coverage(spec, cookie, dump, topology)?;
        ContainmentInspection::OwnedAndContained
    };
    Ok(TcScopeInspection {
        containment,
        other_filters_present,
        foreign_filters_present,
    })
}

pub(super) fn can_install(
    spec: LocalHookSpec,
    cookie: [u8; 16],
    index: usize,
    dump: &TcFilterDump,
) -> bool {
    let bank = spec.banks[index];
    for (slot, verdict) in [(bank.arp, TcVerdict::Pass), (bank.drop, TcVerdict::Drop)] {
        if dump.find(slot).is_some() && !matches_role(dump, slot, cookie, verdict) {
            return false;
        }
    }
    let complete = spec.banks.map(|other| bank_complete(other, cookie, dump));
    dump.entries().iter().all(|entry| {
        if !software_only(entry) {
            return false;
        }
        let slot = entry.slot();
        entry.is_summary()
            || slot == bank.arp
            || slot == bank.drop
            || spec
                .banks
                .iter()
                .zip(complete)
                .any(|(other, valid)| valid && (slot == other.arp || slot == other.drop))
            || slot.chain != 0
            || slot.priority > bank.drop.priority
    })
}

pub(super) fn coverage(
    spec: LocalHookSpec,
    cookie: [u8; 16],
    dump: &TcFilterDump,
    topology: &topology::Topology,
) -> Result<[bool; 2], ScopeError> {
    check_owner(spec, cookie, dump)?;
    eligible_path(spec, topology)?;
    if !topology.clsact
        || dump.entries.iter().any(|entry| {
            entry.slot().ifindex != spec.ifindex()
                || entry.slot().hook != spec.hook()
                || !software_only(entry)
        })
    {
        return Err(ScopeError::Coverage);
    }
    let complete = spec.banks.map(|bank| bank_complete(bank, cookie, dump));
    let covered = std::array::from_fn(|index| {
        let bank = spec.banks[index];
        complete[index]
            && dump
                .entries()
                .iter()
                .filter(|entry| !entry.is_summary())
                .all(|entry| {
                    let slot = entry.slot();
                    let verified_containment =
                        spec.banks.iter().zip(complete).any(|(other, verified)| {
                            verified && (slot == other.arp || slot == other.drop)
                        });
                    verified_containment || slot.chain != 0 || slot.priority > bank.drop.priority
                })
    });
    if covered == [false, false] {
        return Err(ScopeError::Coverage);
    }
    Ok(covered)
}
