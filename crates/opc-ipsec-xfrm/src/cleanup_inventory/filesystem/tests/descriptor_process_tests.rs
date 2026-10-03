use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::net::UnixStream},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use super::*;

struct OwnedChild(std::process::Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

#[test]
fn child_process_drop_cannot_unlock_the_parent_descriptor_sent_with_scm_rights() {
    let format = crate::cleanup_inventory::tests::proposed_format();
    if let Some(path) = std::env::var_os("OPC_INVENTORY_DESCRIPTOR_PATH") {
        let process = std::env::var("OPC_INVENTORY_DESCRIPTOR_OWNER")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(process, std::process::id());
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let mut marker = [0];
        let message = recvmsg(
            std::io::stdin(),
            &mut [IoSliceMut::new(&mut marker)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert_eq!(message.bytes, 1);
        let mut descriptors = Vec::new();
        for message in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                descriptors.extend(received);
            }
        }
        assert_eq!(descriptors.len(), 1);
        let descriptor = descriptors.pop().unwrap();
        let metadata = fstat(&descriptor).unwrap();
        let child = DirectoryIo {
            root: descriptor,
            path: PathBuf::from(path),
            device: metadata.st_dev.identity().unwrap(),
            inode: metadata.st_ino.identity().unwrap(),
            owner: metadata.st_uid,
            process,
            limits: limits(),
            format,
            temporary: None,
        };
        let path = child.path.clone();
        assert!(matches!(
            child.check_binding(),
            Err(InventoryError::WrongBinding)
        ));
        drop(child);
        assert!(matches!(
            DirectoryIo::open(&path, OpenMode::Reopen, limits(), format),
            Err(InventoryError::StoreBusy)
        ));
        return;
    }

    let root = TemporaryDirectory::new();
    let parent = DirectoryIo::open(&root.store(), OpenMode::CreateNew, limits(), format).unwrap();
    let (socket, child_socket) = UnixStream::pair().unwrap();
    let mut child = OwnedChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cleanup_inventory::filesystem::tests::descriptor_process_tests::child_process_drop_cannot_unlock_the_parent_descriptor_sent_with_scm_rights"])
        .env("OPC_INVENTORY_DESCRIPTOR_PATH", root.store())
        .env("OPC_INVENTORY_DESCRIPTOR_OWNER", std::process::id().to_string())
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let descriptors = [parent.root.as_fd()];
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            &socket,
            &[IoSlice::new(&[1])],
            &mut ancillary,
            SendFlags::empty()
        )
        .unwrap(),
        1
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let success = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status.success();
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(child);
    assert!(success, "owned descriptor recipient failed or did not exit");
    parent.check_binding().unwrap();
    assert!(matches!(
        DirectoryIo::open(&root.store(), OpenMode::Reopen, limits(), format),
        Err(InventoryError::StoreBusy)
    ));
}
