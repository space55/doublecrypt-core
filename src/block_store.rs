use crate::error::{FsError, FsResult};
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for a fixed-size block store backend.
/// All blocks are the same size. Block IDs are u64.
pub trait BlockStore: Send + Sync {
    /// Block size in bytes.
    fn block_size(&self) -> usize;

    /// Total number of blocks in the store.
    fn total_blocks(&self) -> u64;

    /// Read a full block. Returns exactly `block_size()` bytes.
    fn read_block(&self, block_id: u64) -> FsResult<Vec<u8>>;

    /// Write a full block. `data` must be exactly `block_size()` bytes.
    fn write_block(&self, block_id: u64, data: &[u8]) -> FsResult<()>;

    /// Sync / flush all writes. No-op for in-memory stores.
    fn sync(&self) -> FsResult<()> {
        Ok(())
    }
}

/// Simple in-memory block store for testing and development.
pub struct MemoryBlockStore {
    block_size: usize,
    total_blocks: u64,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemoryBlockStore {
    pub fn new(block_size: usize, total_blocks: u64) -> Self {
        Self {
            block_size,
            total_blocks,
            blocks: Mutex::new(HashMap::new()),
        }
    }
}

impl BlockStore for MemoryBlockStore {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    fn read_block(&self, block_id: u64) -> FsResult<Vec<u8>> {
        if block_id >= self.total_blocks {
            return Err(FsError::BlockOutOfRange(block_id));
        }
        let blocks = self.blocks.lock().map_err(|e| FsError::Internal(e.to_string()))?;
        match blocks.get(&block_id) {
            Some(data) => Ok(data.clone()),
            None => {
                // Unwritten blocks return zeroes.
                Ok(vec![0u8; self.block_size])
            }
        }
    }

    fn write_block(&self, block_id: u64, data: &[u8]) -> FsResult<()> {
        if block_id >= self.total_blocks {
            return Err(FsError::BlockOutOfRange(block_id));
        }
        if data.len() != self.block_size {
            return Err(FsError::BlockSizeMismatch {
                expected: self.block_size,
                got: data.len(),
            });
        }
        let mut blocks = self.blocks.lock().map_err(|e| FsError::Internal(e.to_string()))?;
        blocks.insert(block_id, data.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_block_store_roundtrip() {
        let store = MemoryBlockStore::new(64, 10);
        let data = vec![0xAB; 64];
        store.write_block(0, &data).unwrap();
        let read = store.read_block(0).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_unwritten_block_returns_zeroes() {
        let store = MemoryBlockStore::new(64, 10);
        let read = store.read_block(5).unwrap();
        assert_eq!(read, vec![0u8; 64]);
    }

    #[test]
    fn test_out_of_range_read() {
        let store = MemoryBlockStore::new(64, 10);
        assert!(store.read_block(10).is_err());
    }

    #[test]
    fn test_block_size_mismatch() {
        let store = MemoryBlockStore::new(64, 10);
        assert!(store.write_block(0, &[0u8; 32]).is_err());
    }
}
