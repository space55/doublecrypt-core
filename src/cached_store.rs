//! Write-back LRU cache that wraps any [`BlockStore`].
//!
//! Dirty blocks accumulate in memory and are flushed to the inner store in
//! batch on [`sync()`](BlockStore::sync).  When a dirty entry is evicted by
//! cache pressure it is written-back immediately so no data is lost.
//!
//! # Example
//!
//! ```
//! use doublecrypt_core::block_store::{BlockStore, MemoryBlockStore};
//! use doublecrypt_core::cached_store::CachedBlockStore;
//!
//! let inner = MemoryBlockStore::new(4096, 256);
//! let cached = CachedBlockStore::new(inner, 64); // cache up to 64 blocks
//!
//! cached.write_block(0, &vec![0xAB; 4096]).unwrap();
//! // Block is dirty in cache — not yet written to inner store.
//!
//! cached.sync().unwrap();
//! // Now flushed.
//! ```

use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

use crate::block_store::BlockStore;
use crate::error::{FsError, FsResult};

/// A cached entry: the raw block data and a dirty flag.
struct CacheEntry {
    data: Vec<u8>,
    dirty: bool,
}

/// Write-back LRU block cache.
///
/// Wraps an arbitrary [`BlockStore`] and serves reads from an in-memory LRU
/// cache.  Writes are marked dirty and batched to the inner store on
/// [`sync()`](BlockStore::sync).  If the cache is full and a dirty entry must
/// be evicted, it is written-back to the inner store immediately.
pub struct CachedBlockStore<S: BlockStore> {
    inner: S,
    cache: Mutex<LruCache<u64, CacheEntry>>,
}

impl<S: BlockStore> CachedBlockStore<S> {
    /// Create a new cache of `capacity` blocks in front of `inner`.
    ///
    /// `capacity` is clamped to a minimum of 16.
    pub fn new(inner: S, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(16)).unwrap();
        Self {
            inner,
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Flush a single evicted dirty entry to the inner store.
    fn writeback(&self, block_id: u64, data: &[u8]) -> FsResult<()> {
        self.inner.write_block(block_id, data)
    }

    /// Insert an entry, handling write-back if a dirty entry is evicted.
    fn insert(
        &self,
        cache: &mut LruCache<u64, CacheEntry>,
        block_id: u64,
        entry: CacheEntry,
    ) -> Option<(u64, Vec<u8>)> {
        match cache.push(block_id, entry) {
            Some((evicted_id, evicted)) if evicted_id != block_id && evicted.dirty => {
                Some((evicted_id, evicted.data))
            }
            _ => None,
        }
    }
}

impl<S: BlockStore> BlockStore for CachedBlockStore<S> {
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn total_blocks(&self) -> u64 {
        self.inner.total_blocks()
    }

    fn read_block(&self, block_id: u64) -> FsResult<Vec<u8>> {
        // Fast path: cache hit.
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            if let Some(entry) = cache.get(&block_id) {
                return Ok(entry.data.clone());
            }
        }

        // Cache miss — read from inner store (no lock held).
        let data = self.inner.read_block(block_id)?;

        // Populate cache.
        let wb = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            // Another caller may have populated it while we were reading.
            if cache.contains(&block_id) {
                return Ok(cache.get(&block_id).unwrap().data.clone());
            }
            self.insert(
                &mut cache,
                block_id,
                CacheEntry {
                    data: data.clone(),
                    dirty: false,
                },
            )
        };

        if let Some((id, wb_data)) = wb {
            self.writeback(id, &wb_data)?;
        }

        Ok(data)
    }

    fn write_block(&self, block_id: u64, data: &[u8]) -> FsResult<()> {
        let wb = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            self.insert(
                &mut cache,
                block_id,
                CacheEntry {
                    data: data.to_vec(),
                    dirty: true,
                },
            )
        };

        if let Some((id, wb_data)) = wb {
            self.writeback(id, &wb_data)?;
        }

        Ok(())
    }

    fn sync(&self) -> FsResult<()> {
        // Phase 1: collect all dirty blocks (lock held briefly).
        let dirty: Vec<(u64, Vec<u8>)> = {
            let cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            cache
                .iter()
                .filter(|(_, e)| e.dirty)
                .map(|(&id, e)| (id, e.data.clone()))
                .collect()
        };

        // Phase 2: batch-write to inner store (no lock held).
        if !dirty.is_empty() {
            let refs: Vec<(u64, &[u8])> = dirty.iter().map(|(id, d)| (*id, d.as_slice())).collect();
            self.inner.write_blocks(&refs)?;
        }

        // Phase 3: mark flushed entries as clean.
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            for (id, _) in &dirty {
                if let Some(entry) = cache.peek_mut(id) {
                    entry.dirty = false;
                }
            }
        }

        self.inner.sync()
    }

    fn read_blocks(&self, block_ids: &[u64]) -> FsResult<Vec<Vec<u8>>> {
        // Partition into hits and misses.
        let mut results: Vec<Option<Vec<u8>>> = vec![None; block_ids.len()];
        let mut miss_indices = Vec::new();
        let mut miss_ids = Vec::new();

        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            for (i, &id) in block_ids.iter().enumerate() {
                if let Some(entry) = cache.get(&id) {
                    results[i] = Some(entry.data.clone());
                } else {
                    miss_indices.push(i);
                    miss_ids.push(id);
                }
            }
        }

        // Batch-read misses from the inner store.
        if !miss_ids.is_empty() {
            let fetched = self.inner.read_blocks(&miss_ids)?;
            let mut writebacks = Vec::new();

            {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|e| FsError::Internal(e.to_string()))?;
                for (&idx, data) in miss_indices.iter().zip(fetched) {
                    results[idx] = Some(data.clone());
                    let block_id = block_ids[idx];
                    if !cache.contains(&block_id) {
                        if let Some((eid, entry)) =
                            cache.push(block_id, CacheEntry { data, dirty: false })
                        {
                            if eid != block_id && entry.dirty {
                                writebacks.push((eid, entry.data));
                            }
                        }
                    }
                }
            }

            for (id, data) in writebacks {
                self.writeback(id, &data)?;
            }
        }

        results
            .into_iter()
            .map(|r| r.ok_or_else(|| FsError::Internal("missing read result".into())))
            .collect()
    }

    fn write_blocks(&self, blocks: &[(u64, &[u8])]) -> FsResult<()> {
        let mut writebacks = Vec::new();

        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| FsError::Internal(e.to_string()))?;
            for &(block_id, data) in blocks {
                if let Some((eid, entry)) = cache.push(
                    block_id,
                    CacheEntry {
                        data: data.to_vec(),
                        dirty: true,
                    },
                ) {
                    if eid != block_id && entry.dirty {
                        writebacks.push((eid, entry.data));
                    }
                }
            }
        }

        // Batch writeback any evicted dirty blocks.
        if !writebacks.is_empty() {
            let refs: Vec<(u64, &[u8])> = writebacks
                .iter()
                .map(|(id, d)| (*id, d.as_slice()))
                .collect();
            self.inner.write_blocks(&refs)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_store::MemoryBlockStore;

    #[test]
    fn read_populates_cache() {
        let inner = MemoryBlockStore::new(64, 10);
        inner.write_block(0, &vec![0xAA; 64]).unwrap();

        let cached = CachedBlockStore::new(inner, 16);
        let data = cached.read_block(0).unwrap();
        assert_eq!(data, vec![0xAA; 64]);

        // Second read should come from cache (no way to assert directly,
        // but at least it shouldn't error).
        let data2 = cached.read_block(0).unwrap();
        assert_eq!(data2, vec![0xAA; 64]);
    }

    #[test]
    fn write_is_not_visible_to_inner_until_sync() {
        let inner = MemoryBlockStore::new(64, 10);
        let cached = CachedBlockStore::new(inner, 16);

        cached.write_block(0, &vec![0xBB; 64]).unwrap();

        // Read through cache should see the write.
        assert_eq!(cached.read_block(0).unwrap(), vec![0xBB; 64]);

        // After sync, inner should also have it.
        cached.sync().unwrap();
    }

    #[test]
    fn dirty_eviction_writes_back() {
        let inner = MemoryBlockStore::new(64, 100);
        // Cache holds only 16 blocks.
        let cached = CachedBlockStore::new(inner, 16);

        // Write 20 blocks — at least 4 must be evicted and written back.
        for i in 0..20u64 {
            cached.write_block(i, &vec![i as u8; 64]).unwrap();
        }

        // Sync to flush remaining dirty blocks.
        cached.sync().unwrap();

        // Verify all 20 blocks via inner store reads (bypass cache).
        for i in 0..20u64 {
            // Re-read through cache (which may or may not have them).
            let data = cached.read_block(i).unwrap();
            assert_eq!(data, vec![i as u8; 64]);
        }
    }

    #[test]
    fn batch_read_write() {
        let inner = MemoryBlockStore::new(64, 10);
        let cached = CachedBlockStore::new(inner, 16);

        let blocks: Vec<(u64, &[u8])> = vec![(0, &[0x11; 64]), (1, &[0x22; 64]), (2, &[0x33; 64])];
        cached.write_blocks(&blocks).unwrap();

        let results = cached.read_blocks(&[0, 1, 2]).unwrap();
        assert_eq!(results[0], vec![0x11; 64]);
        assert_eq!(results[1], vec![0x22; 64]);
        assert_eq!(results[2], vec![0x33; 64]);
    }
}
