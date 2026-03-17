use crate::allocator::SlotAllocator;
use crate::block_store::BlockStore;
use crate::codec::{write_encrypted_object, ObjectCodec, PostcardCodec};
use crate::crypto::CryptoEngine;
use crate::error::FsResult;
use crate::model::*;

/// Manages copy-on-write commits and root pointer alternation.
///
/// Workflow:
/// 1. Filesystem operations allocate new blocks and write objects.
/// 2. When ready to commit, call `commit()` with the new superblock.
/// 3. TransactionManager writes the superblock to a fresh block,
///    then updates the next root pointer slot (A or B).
/// 4. Old blocks can then be freed (deferred GC - not yet implemented).
pub struct TransactionManager {
    /// Current generation counter.
    generation: u64,
    /// Which root pointer slot to write next: false = A (block 1), true = B (block 2).
    next_is_b: bool,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            generation: 0,
            next_is_b: false,
        }
    }

    /// Initialize from recovered state.
    pub fn from_recovered(generation: u64, last_was_b: bool) -> Self {
        Self {
            generation,
            next_is_b: !last_was_b,
        }
    }

    /// Current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Commit a new superblock.
    ///
    /// 1. Allocate a block for the superblock.
    /// 2. Write the encrypted superblock to that block.
    /// 3. Write the root pointer to the next slot (A or B), unencrypted
    ///    (root pointers are integrity-checked via BLAKE3 but not encrypted
    ///    so we can read them without the key to find the superblock).
    ///
    /// Note: root pointers are written unencrypted but with a checksum.
    /// The superblock itself is encrypted.
    pub fn commit(
        &mut self,
        store: &dyn BlockStore,
        crypto: &dyn CryptoEngine,
        codec: &PostcardCodec,
        allocator: &dyn SlotAllocator,
        superblock: &Superblock,
    ) -> FsResult<()> {
        self.generation += 1;

        // 1. Allocate a block for the superblock object.
        let sb_block = allocator.allocate()?;

        // 2. Write encrypted superblock.
        write_encrypted_object(store, crypto, codec, sb_block, ObjectKind::Superblock, superblock)?;

        // 3. Build root pointer with checksum.
        let sb_bytes = codec.serialize_object(superblock)?;
        let checksum = blake3::hash(&sb_bytes);

        let root_ptr = RootPointer {
            generation: self.generation,
            superblock_ref: ObjectRef::new(sb_block),
            checksum: *checksum.as_bytes(),
        };

        // 4. Write root pointer (unencrypted, just serialized + padded).
        let rp_bytes = codec.serialize_object(&root_ptr)?;
        let block_size = store.block_size();
        let mut block = vec![0u8; block_size];
        let len = rp_bytes.len() as u32;
        block[..4].copy_from_slice(&len.to_le_bytes());
        block[4..4 + rp_bytes.len()].copy_from_slice(&rp_bytes);

        let slot = if self.next_is_b {
            BLOCK_ROOT_POINTER_B
        } else {
            BLOCK_ROOT_POINTER_A
        };
        store.write_block(slot, &block)?;

        self.next_is_b = !self.next_is_b;
        Ok(())
    }

    /// Try to read a root pointer from a slot. Returns None if the slot is empty/invalid.
    pub fn read_root_pointer(
        store: &dyn BlockStore,
        codec: &PostcardCodec,
        slot: u64,
    ) -> FsResult<Option<RootPointer>> {
        let block = store.read_block(slot)?;
        if block.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
        if len == 0 || 4 + len > block.len() {
            return Ok(None);
        }
        let rp_bytes = &block[4..4 + len];
        match codec.deserialize_object::<RootPointer>(rp_bytes) {
            Ok(rp) => Ok(Some(rp)),
            Err(_) => Ok(None),
        }
    }

    /// Recover the latest valid root pointer by reading both slots.
    /// Returns (RootPointer, was_slot_b).
    pub fn recover_latest(
        store: &dyn BlockStore,
        codec: &PostcardCodec,
    ) -> FsResult<Option<(RootPointer, bool)>> {
        let rp_a = Self::read_root_pointer(store, codec, BLOCK_ROOT_POINTER_A)?;
        let rp_b = Self::read_root_pointer(store, codec, BLOCK_ROOT_POINTER_B)?;

        match (rp_a, rp_b) {
            (Some(a), Some(b)) => {
                if b.generation >= a.generation {
                    Ok(Some((b, true)))
                } else {
                    Ok(Some((a, false)))
                }
            }
            (Some(a), None) => Ok(Some((a, false))),
            (None, Some(b)) => Ok(Some((b, true))),
            (None, None) => Ok(None),
        }
    }
}
