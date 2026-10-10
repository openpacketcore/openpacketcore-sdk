use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

fn identity(id: u32) -> ProgramIdentity {
    ProgramIdentity {
        id,
        program_type: 3,
        tag: [2; 8],
        name: *b"owned\0\0\0\0\0\0\0\0\0\0\0",
        load_time_ns: 17,
        map_ids: vec![7],
        ifindex: 0,
    }
}
fn error(call: InspectionCall, errno: i32) -> InspectionError {
    InspectionError::new(call, io::Error::from_raw_os_error(errno))
}
struct Handle {
    id: u32,
    held: Rc<Cell<usize>>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.held.set(self.held.get() - 1);
    }
}
struct Port {
    ids: BTreeMap<u32, Result<ProgramIdentity, InspectionError>>,
    held: Rc<Cell<usize>>,
    fail_info: Option<InspectionError>,
    expected_held: usize,
    opened: Vec<u32>,
}
impl Inspection for Port {
    type Program = Handle;
    fn open_program(&mut self, id: u32) -> Result<Handle, InspectionError> {
        self.opened.push(id);
        self.ids
            .get(&id)
            .ok_or_else(|| error(InspectionCall::OpenProgram, 2))?
            .as_ref()
            .map_err(|error| *error)?;
        self.held.set(self.held.get() + 1);
        Ok(Handle {
            id,
            held: Rc::clone(&self.held),
        })
    }
    fn program_info(&mut self, handle: &Handle) -> Result<ProgramIdentity, InspectionError> {
        assert!(self.held.get() >= self.expected_held);
        if let Some(error) = self.fail_info {
            return Err(error);
        }
        self.ids[&handle.id].clone()
    }
}
fn port(ids: BTreeMap<u32, Result<ProgramIdentity, InspectionError>>) -> Port {
    Port {
        ids,
        held: Rc::new(Cell::new(0)),
        fail_info: None,
        expected_held: 1,
        opened: Vec::new(),
    }
}

#[test]
fn only_program_reopen_enoent_means_retirement() {
    for call in [
        InspectionCall::OpenProgram,
        InspectionCall::ProgramInfo,
        InspectionCall::OpenMap,
        InspectionCall::MapInfo,
    ] {
        for errno in [2, 1, 5, 13] {
            assert_eq!(
                error(call, errno).program_retired(),
                call == InspectionCall::OpenProgram && errno == 2
            );
        }
    }
}

#[test]
fn inventory_skips_retired_unrelated_id_and_keeps_all_live_descriptors() {
    let mut port = port(BTreeMap::from([
        (1, Ok(identity(1))),
        (2, Err(error(InspectionCall::OpenProgram, 2))),
        (3, Ok(identity(3))),
    ]));
    let observed = inventory(&mut port, &[1, 2, 3]).expect("retired local ID must be skipped");
    assert_eq!(
        observed.iter().map(|(_, info)| info.id).collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(port.held.get(), 2);
    drop(observed);
    assert_eq!(port.held.get(), 0);
}

#[test]
fn inventory_refuses_wrong_syscall_enoent_and_other_inspection_errors() {
    for (call, errno) in [
        (InspectionCall::OpenProgram, 1),
        (InspectionCall::OpenProgram, 5),
        (InspectionCall::ProgramInfo, 2),
        (InspectionCall::OpenMap, 2),
    ] {
        let mut port = port(BTreeMap::from([(1, Err(error(call, errno)))]));
        assert!(inventory(&mut port, &[1]).is_err());
    }
    let mut port = port(BTreeMap::from([(1, Ok(identity(1)))]));
    port.fail_info = Some(error(InspectionCall::ProgramInfo, 2));
    assert!(inventory(&mut port, &[1]).is_err());
    assert_eq!(port.held.get(), 0);
}

#[test]
fn only_explicit_local_programs_are_opened_regardless_of_node_population() {
    // The shared-node review probe exercises more than the old 4096-object
    // limit while observing only the caller's explicit IDs.
    let mut port = port((1..=10_000).map(|id| (id, Ok(identity(id)))).collect());
    let observed = inventory(&mut port, &[1, 9000, 1]).unwrap();
    assert_eq!(port.opened, [1, 9000]);
    assert_eq!(port.held.get(), 2);
    assert_eq!(observed.len(), 2);
    drop(observed);
    assert_eq!(port.held.get(), 0);
}

#[test]
fn global_release_distinguishes_retained_identity_from_id_reuse() {
    let old = identity(7);
    let mut empty = port(BTreeMap::new());
    assert_eq!(
        program_release(&mut empty, &old),
        GlobalObjectDisposition::GoneObserved
    );
    let mut retained = port(BTreeMap::from([(7, Ok(old.clone()))]));
    assert_eq!(
        program_release(&mut retained, &old),
        GlobalObjectDisposition::StillReferencedOrUnproven
    );
    let mut replacement = old.clone();
    replacement.load_time_ns += 1;
    let mut reused = port(BTreeMap::from([(7, Ok(replacement))]));
    assert_eq!(
        program_release(&mut reused, &old),
        GlobalObjectDisposition::GoneObserved
    );
    reused.fail_info = Some(error(InspectionCall::ProgramInfo, 2));
    assert_eq!(
        program_release(&mut reused, &old),
        GlobalObjectDisposition::StillReferencedOrUnproven
    );
}

#[cfg(any(not(target_os = "linux"), opc_linux_gtpu_sys_force_unsupported))]
#[test]
fn unsupported_inspection_never_proves_release() {
    assert_eq!(
        programs(&[1]).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        ProgramHandle::open(1).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        MapHandle::open(1).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        observe_global_release(&[identity(1)], &[]),
        GlobalObjectDisposition::StillReferencedOrUnproven
    );
}
