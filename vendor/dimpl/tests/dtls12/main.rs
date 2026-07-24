#[path = "../ossl/mod.rs"]
mod ossl_helper;

mod common;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod crypto;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod data;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod edge;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod fragmentation;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod handshake;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod ossl;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod psk;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod reorder;
mod retransmit;
#[cfg_attr(not(feature = "rcgen"), allow(unused))]
mod rfc6083;
