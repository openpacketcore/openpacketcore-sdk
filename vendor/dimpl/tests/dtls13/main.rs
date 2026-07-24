#[cfg(not(windows))]
#[path = "../wolfssl/mod.rs"]
mod wolfssl_helper;

mod common;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod conformance;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod data;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod edge;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod fragmentation;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod handshake;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod key_update;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod reorder;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod retransmit;

#[cfg(not(windows))]
mod wolfssl;
