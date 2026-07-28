use std::fmt::{Debug, Display};

use opc_gtpu_dataplane::{
    EbpfGtpuDataplaneBackend, EbpfManagedDeviceIdentity, EbpfManagedDeviceInventory,
    EbpfManagedDeviceInventoryCompleteness, GtpDevice, MAX_EBPF_MANAGED_DEVICE_IDENTITIES,
};

const _: () = assert!(MAX_EBPF_MANAGED_DEVICE_IDENTITIES > 0);

fn assert_diagnostic_value<T: Clone + Debug + Display + Send + Sync>() {}

fn assert_inventory_accessors(
    identity: &EbpfManagedDeviceIdentity,
    inventory: &EbpfManagedDeviceInventory,
    device: &GtpDevice,
) {
    let _: &str = identity.name();
    let _: u32 = identity.ifindex();
    let _: bool = identity.matches_device(device);
    let _: &[EbpfManagedDeviceIdentity] = inventory.identities();
    let _: EbpfManagedDeviceInventoryCompleteness = inventory.completeness();
    let _: bool = inventory.contains_device(device);
    let _: bool = inventory.is_truncated();
    let _: usize = inventory.len();
    let _: bool = inventory.is_empty();
}

#[test]
fn managed_device_inventory_surface_is_public_and_bounded() {
    assert_diagnostic_value::<EbpfManagedDeviceIdentity>();
    assert_diagnostic_value::<EbpfManagedDeviceInventory>();
    assert_diagnostic_value::<EbpfManagedDeviceInventoryCompleteness>();

    let _public_inventory_method = EbpfGtpuDataplaneBackend::managed_device_inventory;
    let _public_inventory_accessors: fn(
        &EbpfManagedDeviceIdentity,
        &EbpfManagedDeviceInventory,
        &GtpDevice,
    ) = assert_inventory_accessors;
}
