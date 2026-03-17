//! doublecrypt-core: Encrypted filesystem core library.
//!
//! This crate implements a minimal encrypted object-backed filesystem.
//! All filesystem logic runs on the client side; the backend block store
//! sees only opaque encrypted blocks.
//!
//! # Architecture
//!
//! - [`block_store`] – Block store trait and in-memory implementation
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
pub mod codec;
pub mod crypto;
pub mod error;
pub mod ffi;
pub mod fs;
pub mod model;
pub mod transaction;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod edge_tests;
