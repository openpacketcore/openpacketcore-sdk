use super::*;
use opc_local_kernel_lifecycle::{LocalGraphBinding, LocalScopeResetReceipt};
use std::os::fd::AsFd;

pub(super) async fn exercise(binding: &LocalGraphBinding, reset: &LocalScopeResetReceipt) {
    for partial in [false, true] {
        let guard = binding.begin_rebuild(reset).await.unwrap();
        if partial {
            let directory = guard.pin_directory().unwrap();
            let path = directory.descriptor_path().unwrap();
            let mut ebpf = EbpfLoader::new()
                .default_map_pin_directory(&path)
                .load(DATAPATH_OBJECT)
                .unwrap();
            load_program(&mut ebpf, PROG_UPLINK).unwrap();
            let loaded: &mut SchedClassifier =
                ebpf.program_mut(PROG_UPLINK).unwrap().try_into().unwrap();
            let program = sys::bpf::ProgramHandle::from_fd(loaded.fd().unwrap().as_fd()).unwrap();
            loaded.pin(path.join(PROG_UPLINK)).unwrap();
            let slot = binding
                .artifact()
                .slots()
                .find(|slot| slot.hook() == TcHook::Egress)
                .unwrap();
            guard.attach_program(slot, &program, PROG_UPLINK).unwrap();
            assert!(binding
                .local_scope()
                .inventory()
                .unwrap()
                .iter()
                .any(|dump| dump.find(slot).is_some()));
        }
        drop(guard);
        loop {
            if let Ok(next) = binding.begin_rebuild(reset).await {
                // An available rebuild claim implies exact local absence;
                // complete this empty claim without abandoning it again.
                next.retire_partial().unwrap();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
