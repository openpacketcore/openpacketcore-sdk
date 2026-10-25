//! Test-only global-allocator probe for security-key zeroization.
//!
//! The SDK crates forbid `unsafe`. This publish=false crate is the single
//! exception: an allocator wrapper is the only portable way to observe whether
//! a dropped heap buffer still contains a known key octet pattern before the
//! allocator releases it. It records only a hit count, never allocation
//! contents.
//!
//! Usage:
//! 1. [`arm`] resets and enables the probe.
//! 2. Exercise the receive/decode/drop path under test.
//! 3. [`hits`] must stay `0` if every SDK-owned copy was zeroized before free.
//!
//! A positive control must show that dropping an uncleared buffer while armed
//! increments the counter; otherwise the probe proves nothing.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Distinctive 32-octet marker used by the probe tests.
pub const KEY_MARKER: [u8; 32] = [
    0x5a, 0xa5, 0x3c, 0xc3, 0x69, 0x96, 0x0f, 0xf0, 0x17, 0x71, 0x2b, 0xb2, 0x4d, 0xd4, 0x8e, 0xe8,
    0x1c, 0xc1, 0x95, 0x59, 0x6a, 0xa6, 0x73, 0x37, 0xbe, 0xeb, 0x40, 0x04, 0x88, 0x8b, 0x2e, 0xe2,
];

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);

/// Enable hit counting after resetting it.
pub fn arm() {
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
}

/// Disable hit counting.
pub fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
}

/// Number of freed blocks observed containing [`KEY_MARKER`] since [`arm`].
#[must_use]
pub fn hits() -> usize {
    HITS.load(Ordering::SeqCst)
}

/// Global allocator shim that inspects blocks before they are released.
struct KeyMarkerProbe;

// SAFETY: every function forwards to `System`; the wrapper only reads the
// allocated block before forwarding, never after and never beyond its layout.
unsafe impl GlobalAlloc for KeyMarkerProbe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller contract of `GlobalAlloc::alloc` is forwarded
        // unchanged to `System`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && block_contains_key_marker(ptr, layout.size()) {
            HITS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: the caller contract of `GlobalAlloc::dealloc` is forwarded
        // unchanged to `System`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::SeqCst) && block_contains_key_marker(ptr, layout.size()) {
            HITS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: the caller contract of `GlobalAlloc::realloc` is forwarded
        // unchanged to `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Search one live allocation for the marker pattern.
fn block_contains_key_marker(ptr: *mut u8, len: usize) -> bool {
    if ptr.is_null() || len < KEY_MARKER.len() {
        return false;
    }
    // SAFETY: the allocator contract guarantees `ptr..ptr+len` is one live
    // allocation owned by the caller of `dealloc`/`realloc`.
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    block
        .windows(KEY_MARKER.len())
        .any(|window| window == KEY_MARKER)
}

#[global_allocator]
static GLOBAL: KeyMarkerProbe = KeyMarkerProbe;
