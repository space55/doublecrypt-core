//! doublecrypt-core: Encrypted filesystem core library.
//!
//! This crate implements a minimal encrypted object-backed filesystem.
//! All filesystem logic runs on the client side; the backend block store
//! sees only opaque encrypted blocks.
//!
//! # Architecture
//!
//! - [`block_store`] – Block store trait and local implementations
//! - [`cached_store`] – Write-back LRU cache for any `BlockStore`
//! - [`proto`] – Shared protobuf types for the block-store wire protocol
//! - [`network_store`] – mTLS network-backed block store *(feature: `network`)*
//! - [`allocator`] – Slot/block allocator
//! - [`crypto`] – AEAD encryption engine (ChaCha20-Poly1305)
//! - [`codec`] – Object serialization/encryption helpers
//! - [`model`] – Core data types (Inode, DirectoryPage, ExtentMap, etc.)
//! - [`transaction`] – Copy-on-write commit and root pointer management
//! - [`fs`] – High-level filesystem operations
//! - [`ffi`] – C ABI for Swift interop
//! - [`error`] – Error types

pub mod allocator;
pub mod block_store;
pub mod cached_store;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod ffi;
pub mod fs;
pub mod model;
pub mod transaction;

#[cfg(feature = "network")]
pub mod network_store;
pub mod proto;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod edge_tests;

#[cfg(test)]
mod bench_tests;
