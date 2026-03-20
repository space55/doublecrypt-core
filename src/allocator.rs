use crate::error::{FsError, FsResult};
use crate::model::FIRST_DATA_BLOCK;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Trait for allocating and freeing block slots.
pub trait SlotAllocator: Send + Sync {
    /// Allocate a free block and return its ID.
    fn allocate(&self) -> FsResult<u64>;

    /// Return a block to the free pool.
    fn free(&self, block_id: u64) -> FsResult<()>;

    /// Check if a block is currently allocated.
    fn is_allocated(&self, block_id: u64) -> bool;
}

/// Simple bitmap-style allocator backed by a BTreeSet of free block IDs.
pub struct BitmapAllocator {
    total_blocks: u64,
    state: Mutex<AllocatorState>,
}

struct AllocatorState {
    /// Set of free block IDs.
    free_set: BTreeSet<u64>,
    /// Set of allocated block IDs.
    allocated: BTreeSet<u64>,
}

impl BitmapAllocator {
    /// Create a new allocator for `total_blocks` blocks.
    /// Blocks 0..FIRST_DATA_BLOCK are reserved and never allocatable.
    pub fn new(total_blocks: u64) -> Self {
        let mut free_set = BTreeSet::new();
        for id in FIRST_DATA_BLOCK..total_blocks {
            free_set.insert(id);
        }
        Self {
            total_blocks,
            state: Mutex::new(AllocatorState {
                free_set,
                allocated: BTreeSet::new(),
            }),
        }
    }

    /// Mark a block as already allocated (used during mount/recovery).
    pub fn mark_allocated(&self, block_id: u64) -> FsResult<()> {
        let mut state = self.state.lock().map_err(|e| FsError::Internal(e.to_string()))?;
        state.free_set.remove(&block_id);
        state.allocated.insert(block_id);
        Ok(())
    }

    /// Return the number of free blocks.
    pub fn free_count(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.free_set.len() as u64
    }

    /// Return all free block IDs.
    pub fn free_block_ids(&self) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        state.free_set.iter().copied().collect()
    }
}

impl SlotAllocator for BitmapAllocator {
    fn allocate(&self) -> FsResult<u64> {
        let mut state = self.state.lock().map_err(|e| FsError::Internal(e.to_string()))?;
        let block_id = *state.free_set.iter().next().ok_or(FsError::NoFreeBlocks)?;
        state.free_set.remove(&block_id);
        state.allocated.insert(block_id);
        Ok(block_id)
    }

    fn free(&self, block_id: u64) -> FsResult<()> {
        if block_id >= self.total_blocks || block_id < FIRST_DATA_BLOCK {
            return Err(FsError::BlockOutOfRange(block_id));
        }
        let mut state = self.state.lock().map_err(|e| FsError::Internal(e.to_string()))?;
        state.allocated.remove(&block_id);
        state.free_set.insert(block_id);
        Ok(())
    }

    fn is_allocated(&self, block_id: u64) -> bool {
        let state = self.state.lock().unwrap();
        state.allocated.contains(&block_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_free() {
        let alloc = BitmapAllocator::new(10);
        let id = alloc.allocate().unwrap();
        assert!(id >= FIRST_DATA_BLOCK);
        assert!(alloc.is_allocated(id));
        alloc.free(id).unwrap();
        assert!(!alloc.is_allocated(id));
    }

    #[test]
    fn test_exhaustion() {
        // Only FIRST_DATA_BLOCK..4 are allocatable => 1 block (block 3).
        let alloc = BitmapAllocator::new(4);
        let _id = alloc.allocate().unwrap();
        assert!(alloc.allocate().is_err());
    }
}
