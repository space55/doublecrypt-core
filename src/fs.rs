use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lru::LruCache;
use rand::RngCore;

use crate::allocator::{BitmapAllocator, SlotAllocator};
use crate::block_store::BlockStore;
use crate::codec::{
    decrypt_block_to_plaintext, prepare_encrypted_block, read_encrypted_object, read_encrypted_raw,
    write_encrypted_object, ObjectCodec, PostcardCodec,
};
use crate::crypto::CryptoEngine;
use crate::error::{FsError, FsResult};
use crate::model::*;
use crate::transaction::TransactionManager;

/// The main filesystem core. Owns the block store, crypto, codec, allocator,
/// and transaction manager. Provides high-level filesystem operations.
///
/// All path-accepting methods use `/`-separated paths.  An empty string or
/// `"/"` refers to the root directory.  Parent directories must already exist;
/// only `create_file` and `create_directory` create the leaf entry.
pub struct FilesystemCore {
    store: Arc<dyn BlockStore>,
    crypto: Arc<dyn CryptoEngine>,
    codec: PostcardCodec,
    allocator: BitmapAllocator,
    txn: TransactionManager,
    /// Cached current superblock.
    superblock: Option<Superblock>,
    /// Next inode ID to allocate.
    next_inode_id: InodeId,
    /// Write buffer: dirty file chunks held in memory until flush.
    write_buffer: HashMap<String, DirtyFile>,
    /// Block ID of the most recently committed superblock object.
    /// Freed when superseded by a new commit.
    last_superblock_block: Option<u64>,
    /// LRU cache of decrypted metadata objects (inodes, dir pages, extent maps)
    /// keyed by block ID.  Avoids repeated decrypt + deserialize on every op.
    obj_cache: RefCell<LruCache<u64, Vec<u8>>>,
}

/// Tracks one ancestor directory during path resolution, used by
/// `commit_cow_chain` to propagate CoW writes back to the root.
struct AncestorEntry {
    inode: Inode,
    dir_page: DirectoryPage,
    child_index: usize,
}

/// Tracks in-memory buffered writes for a single file.
///
/// All dirty chunks are held in memory until `sync()` (or the next
/// metadata-mutating operation) flushes them to the block store.
/// This keeps `write_file()` purely in-memory for smooth throughput.
struct DirtyFile {
    /// In-memory chunk data keyed by chunk index (only partial chunks).
    dirty_chunks: HashMap<u64, Vec<u8>>,
    /// The file's inode at the time buffering started.
    base_inode: Inode,
    /// The file's extent map (updated in-place when chunks are eagerly flushed).
    extent_map: ExtentMap,
    /// Current logical file size (updated on every write).
    size: u64,
    /// Set to `true` when any data has been written (even if eagerly flushed).
    metadata_dirty: bool,
}

/// Maximum payload size for a single file data chunk.
/// Computed conservatively: block_size minus overhead for envelope framing.
/// We'll compute this dynamically based on block size.
fn max_chunk_payload(block_size: usize) -> usize {
    // Rough overhead: 4 bytes length prefix, ~60 bytes envelope metadata,
    // 16 bytes Poly1305 tag, some postcard framing. Be conservative.
    if block_size > 200 {
        block_size - 200
    } else {
        0
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl FilesystemCore {
    /// Create a new FilesystemCore backed by the given store and crypto engine.
    pub fn new(store: Arc<dyn BlockStore>, crypto: Arc<dyn CryptoEngine>) -> Self {
        let total_blocks = store.total_blocks();
        Self {
            store,
            crypto,
            codec: PostcardCodec,
            allocator: BitmapAllocator::new(total_blocks),
            txn: TransactionManager::new(),
            superblock: None,
            next_inode_id: 1,
            write_buffer: HashMap::new(),
            last_superblock_block: None,
            obj_cache: RefCell::new(LruCache::new(NonZeroUsize::new(256).unwrap())),
        }
    }

    // ── Initialization ──

    /// Initialize a brand-new filesystem on the block store.
    /// Writes the storage header, creates the root directory, and commits.
    pub fn init_filesystem(&mut self) -> FsResult<()> {
        let block_size = self.store.block_size() as u32;
        let total_blocks = self.store.total_blocks();

        // Write storage header to block 0 (unencrypted).
        let header = StorageHeader::new(block_size, total_blocks);
        let header_bytes = self.codec.serialize_object(&header)?;
        let bs = self.store.block_size();
        let mut block = vec![0u8; bs];
        rand::thread_rng().fill_bytes(&mut block);
        let len = header_bytes.len() as u32;
        block[..4].copy_from_slice(&len.to_le_bytes());
        block[4..4 + header_bytes.len()].copy_from_slice(&header_bytes);
        self.store.write_block(BLOCK_STORAGE_HEADER, &block)?;

        // Create root directory inode.
        let root_inode_id = self.alloc_inode_id();
        let dir_page = DirectoryPage::new();
        let dir_page_block = self.allocator.allocate()?;
        write_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            dir_page_block,
            ObjectKind::DirectoryPage,
            &dir_page,
        )?;

        let ts = now_secs();
        let root_inode = Inode {
            id: root_inode_id,
            kind: InodeKind::Directory,
            size: 0,
            directory_page_ref: ObjectRef::new(dir_page_block),
            extent_map_ref: ObjectRef::null(),
            created_at: ts,
            modified_at: ts,
        };
        let root_inode_block = self.allocator.allocate()?;
        write_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            root_inode_block,
            ObjectKind::Inode,
            &root_inode,
        )?;

        // Create superblock.
        let sb = Superblock {
            generation: 1,
            root_inode_ref: ObjectRef::new(root_inode_block),
        };
        self.superblock = Some(sb.clone());

        // Commit.
        self.txn.commit(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            &self.allocator,
            &sb,
        )?;

        Ok(())
    }

    /// Open / mount an existing filesystem by recovering the latest root pointer.
    pub fn open(&mut self) -> FsResult<()> {
        // Verify storage header.
        let header = self.read_storage_header()?;
        if !header.is_valid() {
            return Err(FsError::InvalidSuperblock);
        }

        // Recover latest root pointer.
        let (rp, was_b) = TransactionManager::recover_latest(self.store.as_ref(), &self.codec)?
            .ok_or(FsError::InvalidRootPointer)?;

        // Read superblock.
        let sb: Superblock = read_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            rp.superblock_ref.block_id,
        )?;

        // Verify checksum.
        let sb_bytes = self.codec.serialize_object(&sb)?;
        let checksum = blake3::hash(&sb_bytes);
        if *checksum.as_bytes() != rp.checksum {
            return Err(FsError::InvalidSuperblock);
        }

        self.txn = TransactionManager::from_recovered(rp.generation, was_b);
        self.superblock = Some(sb.clone());
        self.last_superblock_block = Some(rp.superblock_ref.block_id);

        // Rebuild allocator knowledge by walking the metadata tree.
        self.rebuild_allocator(&sb)?;

        Ok(())
    }

    // ── File operations ──

    // ── Path helpers ──────────────────────────────────────────

    /// Split a path into its directory components and the leaf name.
    /// Returns `(["a","b"], "c")` for `"a/b/c"`, or `([], "c")` for `"c"`.
    fn split_path(path: &str) -> FsResult<(Vec<&str>, &str)> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(FsError::Internal("empty path".into()));
        }
        let parts: Vec<&str> = trimmed.split('/').collect();
        let (dirs, leaf) = parts.split_at(parts.len() - 1);
        Ok((dirs.to_vec(), leaf[0]))
    }

    /// Parse a directory path (may be empty / "/" for root) into components.
    fn split_dir_path(path: &str) -> Vec<&str> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Vec::new();
        }
        trimmed.split('/').collect()
    }

    /// Resolve a sequence of directory components starting from the root inode,
    /// returning the ancestor chain needed for CoW commit propagation.
    ///
    /// Returns `(ancestors, target_inode, target_dir_page)` where `ancestors`
    /// is a list of `(Inode, DirectoryPage, entry_index_in_parent)` from root
    /// down to (but not including) the final resolved directory.
    fn resolve_dir_chain(
        &self,
        components: &[&str],
        root_inode: &Inode,
    ) -> FsResult<(Vec<AncestorEntry>, Inode, DirectoryPage)> {
        let mut ancestors: Vec<AncestorEntry> = Vec::new();
        let mut current_inode = root_inode.clone();
        let mut current_dir_page: DirectoryPage =
            self.read_obj(current_inode.directory_page_ref.block_id)?;

        for component in components {
            let idx = current_dir_page
                .entries
                .iter()
                .position(|e| e.name == *component)
                .ok_or_else(|| FsError::DirectoryNotFound(component.to_string()))?;

            let entry = &current_dir_page.entries[idx];
            if entry.kind != InodeKind::Directory {
                return Err(FsError::NotADirectory(component.to_string()));
            }

            let child_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
            let child_dir_page: DirectoryPage =
                self.read_obj(child_inode.directory_page_ref.block_id)?;

            ancestors.push(AncestorEntry {
                inode: current_inode,
                dir_page: current_dir_page,
                child_index: idx,
            });

            current_inode = child_inode;
            current_dir_page = child_dir_page;
        }

        Ok((ancestors, current_inode, current_dir_page))
    }

    /// After mutating a directory's page, propagate CoW changes up through
    /// the ancestor chain to the root, then commit a new superblock.
    ///
    /// `new_dir_page` is the already-modified DirectoryPage of the target dir.
    /// `target_inode` is the inode of the directory that owns `new_dir_page`.
    /// `ancestors` is the chain from root down to (but not including) target.
    fn commit_cow_chain(
        &mut self,
        sb: &Superblock,
        ancestors: &[AncestorEntry],
        target_inode: &Inode,
        new_dir_page: &DirectoryPage,
    ) -> FsResult<()> {
        // Collect old block IDs replaced by CoW.  Freed after commit succeeds.
        let mut stale_blocks: Vec<u64> = Vec::new();

        // Target directory: old dir page block.
        stale_blocks.push(target_inode.directory_page_ref.block_id);
        // Target inode block (its block ID is derived from the chain):
        if ancestors.is_empty() {
            // target IS the root inode.
            stale_blocks.push(sb.root_inode_ref.block_id);
        } else {
            let last = ancestors.last().unwrap();
            stale_blocks.push(last.dir_page.entries[last.child_index].inode_ref.block_id);
        }

        // Write the modified directory page.
        let mut new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, new_dir_page)?;

        // Write the modified directory inode.
        let mut new_inode = target_inode.clone();
        new_inode.directory_page_ref = ObjectRef::new(new_dp_block);
        new_inode.modified_at = now_secs();
        let mut new_inode_block = self.allocator.allocate()?;
        self.write_obj(new_inode_block, ObjectKind::Inode, &new_inode)?;

        // Propagate upward through ancestors (bottom to top).
        for (i, ancestor) in ancestors.iter().rev().enumerate() {
            // Old ancestor dir page block.
            stale_blocks.push(ancestor.inode.directory_page_ref.block_id);
            // Old ancestor inode block.
            let rev_idx = ancestors.len() - 1 - i;
            if rev_idx == 0 {
                // This is the root — its block is in the superblock.
                stale_blocks.push(sb.root_inode_ref.block_id);
            } else {
                let parent = &ancestors[rev_idx - 1];
                stale_blocks.push(
                    parent.dir_page.entries[parent.child_index]
                        .inode_ref
                        .block_id,
                );
            }

            let mut parent_dp = ancestor.dir_page.clone();
            parent_dp.entries[ancestor.child_index].inode_ref = ObjectRef::new(new_inode_block);

            new_dp_block = self.allocator.allocate()?;
            self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &parent_dp)?;

            let mut parent_inode = ancestor.inode.clone();
            parent_inode.directory_page_ref = ObjectRef::new(new_dp_block);
            parent_inode.modified_at = now_secs();
            new_inode_block = self.allocator.allocate()?;
            self.write_obj(new_inode_block, ObjectKind::Inode, &parent_inode)?;
        }

        // new_inode_block is now the new root inode block.
        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_inode_block),
        };
        self.commit_superblock(new_sb)?;

        // Free stale blocks after the commit has succeeded.
        for block_id in stale_blocks {
            let _ = self.allocator.free(block_id);
        }

        Ok(())
    }

    /// CoW-propagate a modified directory page upward through a sub-chain of
    /// ancestors, stopping before the common ancestor level.
    ///
    /// Returns the new top-level inode block ID.  The caller must update the
    /// common ancestor's dir-page entry to point to this block.
    ///
    /// `stale_blocks` collects old blocks replaced by CoW.  The old inode
    /// block of the topmost node (referenced by the common ancestor's
    /// directory entry) is **not** added — the caller handles that.
    fn cow_subchain(
        &mut self,
        sub_ancestors: &[AncestorEntry],
        target_inode: &Inode,
        new_dir_page: &DirectoryPage,
        stale_blocks: &mut Vec<u64>,
    ) -> FsResult<u64> {
        // Write the modified directory page.
        stale_blocks.push(target_inode.directory_page_ref.block_id);
        let mut new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, new_dir_page)?;

        // Write the updated target inode.
        let mut new_inode = target_inode.clone();
        new_inode.directory_page_ref = ObjectRef::new(new_dp_block);
        new_inode.modified_at = now_secs();
        let mut new_inode_block = self.allocator.allocate()?;
        self.write_obj(new_inode_block, ObjectKind::Inode, &new_inode)?;

        // Propagate upward through sub-ancestors (bottom to top).
        for ancestor in sub_ancestors.iter().rev() {
            // Old child inode block (the one we just replaced).
            stale_blocks.push(
                ancestor.dir_page.entries[ancestor.child_index]
                    .inode_ref
                    .block_id,
            );
            // Old ancestor dir page block.
            stale_blocks.push(ancestor.inode.directory_page_ref.block_id);

            let mut parent_dp = ancestor.dir_page.clone();
            parent_dp.entries[ancestor.child_index].inode_ref = ObjectRef::new(new_inode_block);

            new_dp_block = self.allocator.allocate()?;
            self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &parent_dp)?;

            let mut parent_inode = ancestor.inode.clone();
            parent_inode.directory_page_ref = ObjectRef::new(new_dp_block);
            parent_inode.modified_at = now_secs();
            new_inode_block = self.allocator.allocate()?;
            self.write_obj(new_inode_block, ObjectKind::Inode, &parent_inode)?;
        }

        Ok(new_inode_block)
    }

    // ── Public operations ─────────────────────────────────────

    /// Create a new empty file at the given path.
    ///
    /// Parent directories must already exist.  The leaf name is created in
    /// the innermost directory.
    pub fn create_file(&mut self, path: &str) -> FsResult<()> {
        let (dir_parts, leaf) = Self::split_path(path)?;
        self.validate_name(leaf)?;
        self.flush_all()?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();

        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (ancestors, target_inode, mut dir_page) =
            self.resolve_dir_chain(&dir_parts, &root_inode)?;

        if dir_page.entries.iter().any(|e| e.name == leaf) {
            return Err(FsError::FileAlreadyExists(leaf.to_string()));
        }

        // Create empty extent map.
        let extent_map = ExtentMap::new();
        let em_block = self.allocator.allocate()?;
        self.write_obj(em_block, ObjectKind::ExtentMap, &extent_map)?;

        // Create file inode.
        let inode_id = self.alloc_inode_id();
        let ts = now_secs();
        let file_inode = Inode {
            id: inode_id,
            kind: InodeKind::File,
            size: 0,
            directory_page_ref: ObjectRef::null(),
            extent_map_ref: ObjectRef::new(em_block),
            created_at: ts,
            modified_at: ts,
        };
        let inode_block = self.allocator.allocate()?;
        self.write_obj(inode_block, ObjectKind::Inode, &file_inode)?;

        dir_page.entries.push(DirectoryEntry {
            name: leaf.to_string(),
            inode_ref: ObjectRef::new(inode_block),
            inode_id,
            kind: InodeKind::File,
        });

        self.commit_cow_chain(&sb, &ancestors, &target_inode, &dir_page)?;
        Ok(())
    }

    /// Write data to a file at the given path.
    ///
    /// Writes are buffered in memory and only flushed to the block store on
    /// `sync()` or when another metadata-mutating operation occurs.
    /// This keeps every `write_file` call purely in-memory for smooth
    /// throughput.  Call `sync()` periodically to bound memory usage.
    pub fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) -> FsResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let chunk_size = max_chunk_payload(self.store.block_size());
        if chunk_size == 0 {
            return Err(FsError::DataTooLarge(data.len()));
        }

        let path_key = path.trim_matches('/').to_string();

        // Take the dirty entry out of the map so `self` is free for other
        // borrows (disk reads, etc.).  We'll put it back at the end.
        let mut dirty = match self.write_buffer.remove(&path_key) {
            Some(d) => d,
            None => {
                // First buffered write — load metadata from disk.
                let (dir_parts, leaf) = Self::split_path(path)?;
                let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
                let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
                let (_, _, dir_page) = self.resolve_dir_chain(&dir_parts, &root_inode)?;
                let entry = dir_page
                    .entries
                    .iter()
                    .find(|e| e.name == leaf)
                    .ok_or_else(|| FsError::FileNotFound(leaf.to_string()))?;
                if entry.kind != InodeKind::File {
                    return Err(FsError::NotAFile(leaf.to_string()));
                }
                let file_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
                let mut extent_map: ExtentMap =
                    self.read_obj(file_inode.extent_map_ref.block_id)?;
                extent_map.entries.sort_by_key(|e| e.chunk_index);
                DirtyFile {
                    dirty_chunks: HashMap::new(),
                    base_inode: file_inode.clone(),
                    extent_map,
                    size: file_inode.size,
                    metadata_dirty: false,
                }
            }
        };

        let old_size = dirty.size as usize;
        let write_start = offset as usize;
        let write_end = write_start + data.len();
        let new_size = std::cmp::max(old_size, write_end);

        let first_chunk = if write_start >= old_size {
            old_size / chunk_size
        } else {
            write_start / chunk_size
        };
        let last_chunk = (new_size - 1) / chunk_size;

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_file_start = chunk_idx * chunk_size;
            let chunk_file_end = std::cmp::min(chunk_file_start + chunk_size, new_size);
            let chunk_len = chunk_file_end - chunk_file_start;
            let chunk_idx_u64 = chunk_idx as u64;

            // If this chunk isn't buffered yet, load its on-disk content (or zeros).
            if !dirty.dirty_chunks.contains_key(&chunk_idx_u64) {
                let mut buf = vec![0u8; chunk_len];
                if chunk_file_start < old_size {
                    if let Ok(pos) = dirty
                        .extent_map
                        .entries
                        .binary_search_by_key(&chunk_idx_u64, |e| e.chunk_index)
                    {
                        let existing = &dirty.extent_map.entries[pos];
                        let raw = read_encrypted_raw(
                            self.store.as_ref(),
                            self.crypto.as_ref(),
                            &self.codec,
                            existing.data_ref.block_id,
                        )?;
                        let copy_len = std::cmp::min(existing.plaintext_len as usize, chunk_len);
                        let src_len = std::cmp::min(copy_len, raw.len());
                        buf[..src_len].copy_from_slice(&raw[..src_len]);
                    }
                }
                dirty.dirty_chunks.insert(chunk_idx_u64, buf);
            }

            let chunk_buf = dirty.dirty_chunks.get_mut(&chunk_idx_u64).unwrap();
            if chunk_buf.len() < chunk_len {
                chunk_buf.resize(chunk_len, 0);
            }

            // Overlay the write data onto the chunk.
            let overlap_start = std::cmp::max(chunk_file_start, write_start);
            let overlap_end = std::cmp::min(chunk_file_end, write_end);
            if overlap_start < overlap_end {
                let data_off = overlap_start - write_start;
                let chunk_off = overlap_start - chunk_file_start;
                let len = overlap_end - overlap_start;
                chunk_buf[chunk_off..chunk_off + len]
                    .copy_from_slice(&data[data_off..data_off + len]);
            }
        }

        dirty.size = new_size as u64;
        dirty.metadata_dirty = true;

        self.write_buffer.insert(path_key, dirty);
        Ok(())
    }

    /// Read file data at the given path. Returns the requested slice.
    ///
    /// If the file has buffered (unflushed) writes, reads are served from the
    /// in-memory buffer merged with on-disk data.
    pub fn read_file(&self, path: &str, offset: u64, len: usize) -> FsResult<Vec<u8>> {
        let path_key = path.trim_matches('/');

        if let Some(dirty) = self.write_buffer.get(path_key) {
            return self.read_file_buffered(dirty, offset, len);
        }

        let (dir_parts, leaf) = Self::split_path(path)?;
        let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (_, _, dir_page) = self.resolve_dir_chain(&dir_parts, &root_inode)?;

        let entry = dir_page
            .entries
            .iter()
            .find(|e| e.name == leaf)
            .ok_or_else(|| FsError::FileNotFound(leaf.to_string()))?;

        if entry.kind != InodeKind::File {
            return Err(FsError::NotAFile(leaf.to_string()));
        }

        let file_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;

        if len == 0 || offset >= file_inode.size {
            return Ok(Vec::new());
        }

        let extent_map: ExtentMap = self.read_obj(file_inode.extent_map_ref.block_id)?;
        self.read_chunk_range(&extent_map, file_inode.size, offset, len)
    }

    /// List entries in a directory at the given path.
    ///
    /// Pass `""` or `"/"` to list the root directory.
    pub fn list_directory(&self, path: &str) -> FsResult<Vec<DirListEntry>> {
        let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;

        let components = Self::split_dir_path(path);
        let (_, _, dir_page) = self.resolve_dir_chain(&components, &root_inode)?;

        let dir_prefix = {
            let trimmed = path.trim_matches('/');
            if trimmed.is_empty() {
                String::new()
            } else {
                format!("{}/", trimmed)
            }
        };

        let mut result = Vec::new();
        for entry in &dir_page.entries {
            let inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
            // Use buffered size if this file has pending writes.
            let size = if entry.kind == InodeKind::File {
                let full_path = format!("{}{}", dir_prefix, entry.name);
                if let Some(dirty) = self.write_buffer.get(&full_path) {
                    dirty.size
                } else {
                    inode.size
                }
            } else {
                inode.size
            };
            result.push(DirListEntry {
                name: entry.name.clone(),
                kind: entry.kind,
                size,
                inode_id: entry.inode_id,
            });
        }
        Ok(result)
    }

    /// Create a subdirectory at the given path.
    ///
    /// Parent directories must already exist; only the leaf is created.
    pub fn create_directory(&mut self, path: &str) -> FsResult<()> {
        let (dir_parts, leaf) = Self::split_path(path)?;
        self.validate_name(leaf)?;
        self.flush_all()?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (ancestors, target_inode, mut dir_page) =
            self.resolve_dir_chain(&dir_parts, &root_inode)?;

        if dir_page.entries.iter().any(|e| e.name == leaf) {
            return Err(FsError::DirectoryAlreadyExists(leaf.to_string()));
        }

        // Create empty directory page for the new subdirectory.
        let sub_dp = DirectoryPage::new();
        let sub_dp_block = self.allocator.allocate()?;
        self.write_obj(sub_dp_block, ObjectKind::DirectoryPage, &sub_dp)?;

        let inode_id = self.alloc_inode_id();
        let ts = now_secs();
        let dir_inode = Inode {
            id: inode_id,
            kind: InodeKind::Directory,
            size: 0,
            directory_page_ref: ObjectRef::new(sub_dp_block),
            extent_map_ref: ObjectRef::null(),
            created_at: ts,
            modified_at: ts,
        };
        let inode_block = self.allocator.allocate()?;
        self.write_obj(inode_block, ObjectKind::Inode, &dir_inode)?;

        dir_page.entries.push(DirectoryEntry {
            name: leaf.to_string(),
            inode_ref: ObjectRef::new(inode_block),
            inode_id,
            kind: InodeKind::Directory,
        });

        self.commit_cow_chain(&sb, &ancestors, &target_inode, &dir_page)?;
        Ok(())
    }

    /// Remove a file or empty directory at the given path.
    pub fn remove_file(&mut self, path: &str) -> FsResult<()> {
        let path_key = path.trim_matches('/').to_string();
        self.write_buffer.remove(&path_key);
        self.flush_all()?;
        let (dir_parts, leaf) = Self::split_path(path)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (ancestors, target_inode, mut dir_page) =
            self.resolve_dir_chain(&dir_parts, &root_inode)?;

        let idx = dir_page
            .entries
            .iter()
            .position(|e| e.name == leaf)
            .ok_or_else(|| FsError::FileNotFound(leaf.to_string()))?;

        // Collect all blocks owned by the removed entry so we can free them.
        let removed_entry = &dir_page.entries[idx];
        let mut stale_blocks: Vec<u64> = Vec::new();
        stale_blocks.push(removed_entry.inode_ref.block_id);
        let removed_inode: Inode = self.read_obj(removed_entry.inode_ref.block_id)?;

        match removed_entry.kind {
            InodeKind::Directory => {
                let sub_page: DirectoryPage =
                    self.read_obj(removed_inode.directory_page_ref.block_id)?;
                if !sub_page.entries.is_empty() {
                    return Err(FsError::DirectoryNotEmpty(leaf.to_string()));
                }
                stale_blocks.push(removed_inode.directory_page_ref.block_id);
            }
            InodeKind::File => {
                if !removed_inode.extent_map_ref.is_null() {
                    stale_blocks.push(removed_inode.extent_map_ref.block_id);
                    let extent_map: ExtentMap =
                        self.read_obj(removed_inode.extent_map_ref.block_id)?;
                    for ext in &extent_map.entries {
                        stale_blocks.push(ext.data_ref.block_id);
                    }
                }
            }
        }

        dir_page.entries.remove(idx);
        // commit_cow_chain frees its own stale CoW blocks.
        self.commit_cow_chain(&sb, &ancestors, &target_inode, &dir_page)?;

        // Free blocks that belonged to the removed entry.
        for block_id in stale_blocks {
            let _ = self.allocator.free(block_id);
        }

        Ok(())
    }

    /// Rename or move a file or directory.  Supports both same-directory
    /// renames and cross-directory moves.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> FsResult<()> {
        let (old_dir, old_leaf) = Self::split_path(old_path)?;
        let (new_dir, new_leaf) = Self::split_path(new_path)?;
        self.validate_name(new_leaf)?;
        self.flush_all()?;

        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;

        if old_dir == new_dir {
            // ── Same-directory rename: just change the name in-place. ──
            let (ancestors, target_inode, mut dir_page) =
                self.resolve_dir_chain(&old_dir, &root_inode)?;

            if dir_page.entries.iter().any(|e| e.name == new_leaf) {
                return Err(FsError::FileAlreadyExists(new_leaf.to_string()));
            }

            let entry = dir_page
                .entries
                .iter_mut()
                .find(|e| e.name == old_leaf)
                .ok_or_else(|| FsError::FileNotFound(old_leaf.to_string()))?;

            entry.name = new_leaf.to_string();
            self.commit_cow_chain(&sb, &ancestors, &target_inode, &dir_page)?;
        } else {
            // ── Cross-directory rename / move. ──

            // Prevent moving a directory into its own subtree.
            let src_full: Vec<&str> = old_dir
                .iter()
                .copied()
                .chain(std::iter::once(old_leaf))
                .collect();
            if new_dir.len() >= src_full.len() && new_dir[..src_full.len()] == src_full[..] {
                return Err(FsError::Internal(
                    "cannot move a directory into itself".into(),
                ));
            }

            // Find the Least Common Ancestor (LCA) of the two parent dirs.
            let common_len = old_dir
                .iter()
                .zip(new_dir.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let common_parts = &old_dir[..common_len];
            let src_remaining = &old_dir[common_len..];
            let dst_remaining = &new_dir[common_len..];

            // Resolve the common ancestor chain from root.
            let (common_ancestors, common_inode, common_dir_page) =
                self.resolve_dir_chain(common_parts, &root_inode)?;

            // Resolve source sub-chain below the common ancestor.
            let (full_src_ancestors, src_inode, src_dir_page) = if src_remaining.is_empty() {
                (Vec::new(), common_inode.clone(), common_dir_page.clone())
            } else {
                self.resolve_dir_chain(src_remaining, &common_inode)?
            };

            // Resolve destination sub-chain below the common ancestor.
            let (full_dst_ancestors, dst_inode, dst_dir_page) = if dst_remaining.is_empty() {
                (Vec::new(), common_inode.clone(), common_dir_page.clone())
            } else {
                self.resolve_dir_chain(dst_remaining, &common_inode)?
            };

            // Validate: source must exist, destination name must not.
            if dst_dir_page.entries.iter().any(|e| e.name == new_leaf) {
                return Err(FsError::FileAlreadyExists(new_leaf.to_string()));
            }
            let src_idx = src_dir_page
                .entries
                .iter()
                .position(|e| e.name == old_leaf)
                .ok_or_else(|| FsError::FileNotFound(old_leaf.to_string()))?;

            // Build the moved entry with its new name.
            let mut moved_entry = src_dir_page.entries[src_idx].clone();
            moved_entry.name = new_leaf.to_string();

            let mut stale_blocks: Vec<u64> = Vec::new();

            // Start with the common ancestor's dir page; both sides
            // accumulate updates into this copy.
            let mut merged_common_dp = common_dir_page.clone();

            // ── Source side ──
            if src_remaining.is_empty() {
                // Source dir IS the common ancestor — remove directly.
                let idx = merged_common_dp
                    .entries
                    .iter()
                    .position(|e| e.name == old_leaf)
                    .ok_or_else(|| FsError::FileNotFound(old_leaf.to_string()))?;
                merged_common_dp.entries.remove(idx);
            } else {
                // CoW the source sub-chain with the entry removed.
                // full_src_ancestors[0] is the common ancestor itself;
                // pass only the levels below it.
                let src_sub = &full_src_ancestors[1..];
                let mut new_src_dp = src_dir_page.clone();
                new_src_dp.entries.remove(src_idx);

                let new_src_child =
                    self.cow_subchain(src_sub, &src_inode, &new_src_dp, &mut stale_blocks)?;

                // Update the common ancestor's entry for the source branch.
                let src_child_name = src_remaining[0];
                let ci = merged_common_dp
                    .entries
                    .iter()
                    .position(|e| e.name == src_child_name)
                    .ok_or_else(|| FsError::DirectoryNotFound(src_child_name.to_string()))?;
                stale_blocks.push(merged_common_dp.entries[ci].inode_ref.block_id);
                merged_common_dp.entries[ci].inode_ref = ObjectRef::new(new_src_child);
            }

            // ── Destination side ──
            if dst_remaining.is_empty() {
                // Destination dir IS the common ancestor — add directly.
                merged_common_dp.entries.push(moved_entry);
            } else {
                // CoW the destination sub-chain with the entry added.
                let dst_sub = &full_dst_ancestors[1..];
                let mut new_dst_dp = dst_dir_page.clone();
                new_dst_dp.entries.push(moved_entry);

                let new_dst_child =
                    self.cow_subchain(dst_sub, &dst_inode, &new_dst_dp, &mut stale_blocks)?;

                // Update the common ancestor's entry for the dest branch.
                let dst_child_name = dst_remaining[0];
                let ci = merged_common_dp
                    .entries
                    .iter()
                    .position(|e| e.name == dst_child_name)
                    .ok_or_else(|| FsError::DirectoryNotFound(dst_child_name.to_string()))?;
                stale_blocks.push(merged_common_dp.entries[ci].inode_ref.block_id);
                merged_common_dp.entries[ci].inode_ref = ObjectRef::new(new_dst_child);
            }

            // CoW from the common ancestor up to root and commit.
            self.commit_cow_chain(&sb, &common_ancestors, &common_inode, &merged_common_dp)?;

            // Free sub-chain stale blocks (commit_cow_chain frees its own).
            for block_id in stale_blocks {
                let _ = self.allocator.free(block_id);
            }
        }

        Ok(())
    }

    /// Sync / flush. Writes all buffered data to blocks and calls through
    /// to the block store sync.
    pub fn sync(&mut self) -> FsResult<()> {
        self.flush_all()?;
        self.store.sync()
    }

    /// Returns the number of free blocks in the allocator.
    #[cfg(test)]
    pub fn free_block_count(&self) -> u64 {
        self.allocator.free_count()
    }

    /// Fill every unallocated block with cryptographically random data.
    ///
    /// This makes free space indistinguishable from encrypted ciphertext,
    /// preventing an observer from determining which blocks contain real
    /// data.  Call after `init_filesystem()` or `open()` when provisioning
    /// a new store, or periodically as a scrub operation.
    ///
    /// Uses batch writes when the block store supports them.
    pub fn scrub_free_blocks(&mut self) -> FsResult<()> {
        self.flush_all()?;

        let free_ids = self.allocator.free_block_ids();
        if free_ids.is_empty() {
            return Ok(());
        }

        let bs = self.store.block_size();
        let mut rng = rand::thread_rng();

        // Write in batches to amortise call overhead and enable pipelined I/O.
        const BATCH: usize = 64;
        for chunk in free_ids.chunks(BATCH) {
            let mut pairs: Vec<(u64, Vec<u8>)> = Vec::with_capacity(chunk.len());
            for &id in chunk {
                let mut buf = vec![0u8; bs];
                rng.fill_bytes(&mut buf);
                pairs.push((id, buf));
            }
            let refs: Vec<(u64, &[u8])> = pairs.iter().map(|(id, d)| (*id, d.as_slice())).collect();
            self.store.write_blocks(&refs)?;
        }

        self.store.sync()
    }

    // ── Internal helpers ──

    /// Flush a single file's buffered writes to the block store.
    fn flush_file(&mut self, path_key: &str) -> FsResult<()> {
        let dirty = match self.write_buffer.remove(path_key) {
            Some(d) => d,
            None => return Ok(()),
        };

        if !dirty.metadata_dirty {
            return Ok(());
        }

        // Re-resolve path from the current superblock.
        let (dir_parts, leaf) = Self::split_path(path_key)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (ancestors, target_inode, dir_page) =
            self.resolve_dir_chain(&dir_parts, &root_inode)?;

        let mut extent_map = dirty.extent_map;

        // Collect stale data chunk blocks being overwritten.
        let mut stale_blocks: Vec<u64> = Vec::new();

        // Write each dirty chunk to a new block.
        // Pre-encrypt all dirty chunks and allocate blocks, then batch-write.
        let block_size = self.store.block_size();
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::with_capacity(dirty.dirty_chunks.len());

        for (&chunk_idx, chunk_data) in &dirty.dirty_chunks {
            // If this chunk already existed, the old data block is stale.
            if let Some(existing) = extent_map
                .entries
                .iter()
                .find(|e| e.chunk_index == chunk_idx)
            {
                stale_blocks.push(existing.data_ref.block_id);
            }

            let data_block = self.allocator.allocate()?;
            let encrypted_block = prepare_encrypted_block(
                block_size,
                self.crypto.as_ref(),
                &self.codec,
                ObjectKind::FileDataChunk,
                chunk_data,
            )?;
            batch.push((data_block, encrypted_block));

            if let Some(entry) = extent_map
                .entries
                .iter_mut()
                .find(|e| e.chunk_index == chunk_idx)
            {
                entry.data_ref = ObjectRef::new(data_block);
                entry.plaintext_len = chunk_data.len() as u32;
            } else {
                extent_map.entries.push(ExtentEntry {
                    chunk_index: chunk_idx,
                    data_ref: ObjectRef::new(data_block),
                    plaintext_len: chunk_data.len() as u32,
                });
            }
        }

        // Single batched write for all dirty chunks.
        {
            let mut cache = self.obj_cache.borrow_mut();
            for &(id, _) in &batch {
                cache.pop(&id);
            }
            drop(cache);
            let refs: Vec<(u64, &[u8])> = batch
                .iter()
                .map(|(id, data)| (*id, data.as_slice()))
                .collect();
            self.store.write_blocks(&refs)?;
        }

        extent_map.entries.sort_by_key(|e| e.chunk_index);

        // Old extent map block is stale.
        if !dirty.base_inode.extent_map_ref.is_null() {
            stale_blocks.push(dirty.base_inode.extent_map_ref.block_id);
        }

        // Write extent map.
        let new_em_block = self.allocator.allocate()?;
        self.write_obj(new_em_block, ObjectKind::ExtentMap, &extent_map)?;

        // Old file inode block is stale — find it from the dir entry.
        let old_inode_block = dir_page
            .entries
            .iter()
            .find(|e| e.name == leaf)
            .map(|e| e.inode_ref.block_id);
        if let Some(blk) = old_inode_block {
            stale_blocks.push(blk);
        }

        // Write inode.
        let mut new_inode = dirty.base_inode;
        new_inode.size = dirty.size;
        new_inode.extent_map_ref = ObjectRef::new(new_em_block);
        new_inode.modified_at = now_secs();
        let new_inode_block = self.allocator.allocate()?;
        self.write_obj(new_inode_block, ObjectKind::Inode, &new_inode)?;

        // Update dir entry.
        let mut new_dir_page = dir_page.clone();
        for e in &mut new_dir_page.entries {
            if e.name == leaf {
                e.inode_ref = ObjectRef::new(new_inode_block);
            }
        }

        // commit_cow_chain frees its own stale blocks (dir pages, ancestor inodes).
        self.commit_cow_chain(&sb, &ancestors, &target_inode, &new_dir_page)?;

        // Free file-level stale blocks (data chunks, old extent map, old inode).
        for block_id in stale_blocks {
            let _ = self.allocator.free(block_id);
        }

        Ok(())
    }

    /// Flush all buffered file writes to the block store.
    fn flush_all(&mut self) -> FsResult<()> {
        let keys: Vec<String> = self.write_buffer.keys().cloned().collect();
        for key in keys {
            self.flush_file(&key)?;
        }
        Ok(())
    }

    /// Read from a file that has dirty (buffered) chunks, merging in-memory
    /// data with on-disk data.
    fn read_file_buffered(&self, dirty: &DirtyFile, offset: u64, len: usize) -> FsResult<Vec<u8>> {
        let chunk_size = max_chunk_payload(self.store.block_size());
        let file_size = dirty.size as usize;
        let start = offset as usize;
        if start >= file_size || len == 0 {
            return Ok(Vec::new());
        }
        let end = std::cmp::min(start + len, file_size);
        let mut result = Vec::with_capacity(end - start);

        let first_chunk = start / chunk_size;
        let last_chunk = (end - 1) / chunk_size;

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_file_start = chunk_idx * chunk_size;
            let chunk_file_end = std::cmp::min(chunk_file_start + chunk_size, file_size);
            let chunk_idx_u64 = chunk_idx as u64;

            // Get chunk data from buffer or disk.
            let chunk_data: Vec<u8> = if let Some(buf) = dirty.dirty_chunks.get(&chunk_idx_u64) {
                buf.clone()
            } else if let Ok(pos) = dirty
                .extent_map
                .entries
                .binary_search_by_key(&chunk_idx_u64, |e| e.chunk_index)
            {
                let entry = &dirty.extent_map.entries[pos];
                let raw = read_encrypted_raw(
                    self.store.as_ref(),
                    self.crypto.as_ref(),
                    &self.codec,
                    entry.data_ref.block_id,
                )?;
                let plain_len = std::cmp::min(entry.plaintext_len as usize, raw.len());
                raw[..plain_len].to_vec()
            } else {
                vec![0u8; chunk_file_end - chunk_file_start]
            };

            // Slice to the requested range within this chunk.
            let read_start = if chunk_idx == first_chunk {
                start - chunk_file_start
            } else {
                0
            };
            let read_end = if chunk_idx == last_chunk {
                end - chunk_file_start
            } else {
                chunk_data.len()
            };
            let read_end = std::cmp::min(read_end, chunk_data.len());

            if read_start < read_end {
                result.extend_from_slice(&chunk_data[read_start..read_end]);
            }
        }

        Ok(result)
    }

    fn alloc_inode_id(&mut self) -> InodeId {
        let id = self.next_inode_id;
        self.next_inode_id += 1;
        id
    }

    fn validate_name(&self, name: &str) -> FsResult<()> {
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return Err(FsError::Internal("invalid name".into()));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(FsError::NameTooLong(name.len(), MAX_NAME_LEN));
        }
        Ok(())
    }

    fn read_obj<T: serde::de::DeserializeOwned>(&self, block_id: u64) -> FsResult<T> {
        let mut cache = self.obj_cache.borrow_mut();
        if let Some(plaintext) = cache.get(&block_id) {
            return self.codec.deserialize_object(plaintext);
        }
        let plaintext = decrypt_block_to_plaintext(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            block_id,
        )?;
        let result = self.codec.deserialize_object(&plaintext);
        cache.put(block_id, plaintext);
        result
    }

    fn write_obj<T: serde::Serialize>(
        &self,
        block_id: u64,
        kind: ObjectKind,
        obj: &T,
    ) -> FsResult<()> {
        // Invalidate any cached plaintext for this block (freed blocks may be
        // reallocated and written with different content).
        self.obj_cache.borrow_mut().pop(&block_id);
        write_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            block_id,
            kind,
            obj,
        )
    }

    /// Read only the chunks that overlap `[offset, offset+len)` from the
    /// extent map, avoiding the cost of decrypting the entire file.
    fn read_chunk_range(
        &self,
        extent_map: &ExtentMap,
        file_size: u64,
        offset: u64,
        len: usize,
    ) -> FsResult<Vec<u8>> {
        let chunk_size = max_chunk_payload(self.store.block_size());
        let end = std::cmp::min(offset as usize + len, file_size as usize);
        let start = offset as usize;
        if start >= end || chunk_size == 0 {
            return Ok(Vec::new());
        }

        let first_chunk = (start / chunk_size) as u64;
        let last_chunk = ((end - 1) / chunk_size) as u64;
        let mut result = Vec::with_capacity(end - start);

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_file_start = chunk_idx as usize * chunk_size;

            // Find the extent entry for this chunk via binary search.
            let chunk_data = if let Ok(pos) = extent_map
                .entries
                .binary_search_by_key(&chunk_idx, |e| e.chunk_index)
            {
                let entry = &extent_map.entries[pos];
                let raw = read_encrypted_raw(
                    self.store.as_ref(),
                    self.crypto.as_ref(),
                    &self.codec,
                    entry.data_ref.block_id,
                )?;
                let plain_len = std::cmp::min(entry.plaintext_len as usize, raw.len());
                raw[..plain_len].to_vec()
            } else {
                // Sparse hole: return zeros up to chunk boundary or file end.
                let hole_end = std::cmp::min(chunk_file_start + chunk_size, file_size as usize);
                vec![0u8; hole_end - chunk_file_start]
            };

            // Slice to the requested range within this chunk.
            let read_start = if chunk_idx == first_chunk {
                start - chunk_file_start
            } else {
                0
            };
            let read_end = if chunk_idx == last_chunk {
                end - chunk_file_start
            } else {
                chunk_data.len()
            };
            let read_end = std::cmp::min(read_end, chunk_data.len());

            if read_start < read_end {
                result.extend_from_slice(&chunk_data[read_start..read_end]);
            }
        }

        Ok(result)
    }

    fn read_storage_header(&self) -> FsResult<StorageHeader> {
        let block = self.store.read_block(BLOCK_STORAGE_HEADER)?;
        if block.len() < 4 {
            return Err(FsError::InvalidSuperblock);
        }
        let len = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
        if len == 0 || 4 + len > block.len() {
            return Err(FsError::InvalidSuperblock);
        }
        self.codec
            .deserialize_object::<StorageHeader>(&block[4..4 + len])
    }

    fn commit_superblock(&mut self, sb: Superblock) -> FsResult<()> {
        let new_sb_block = self.txn.commit(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            &self.allocator,
            &sb,
        )?;
        // Free the previous superblock block now that the new one is committed.
        if let Some(old) = self.last_superblock_block {
            let _ = self.allocator.free(old);
        }
        self.last_superblock_block = Some(new_sb_block);
        self.superblock = Some(sb);
        Ok(())
    }

    /// Walk the metadata tree from the superblock and mark all referenced blocks
    /// as allocated in the allocator. Used during open/mount.
    fn rebuild_allocator(&mut self, sb: &Superblock) -> FsResult<()> {
        // Mark superblock block.
        // The superblock_ref's block was allocated by the transaction manager.
        // We also need to mark root pointer blocks, but those are reserved (0,1,2).

        // We need to find which block the superblock is stored in.
        // The root pointer tells us.
        let (rp, _) = TransactionManager::recover_latest(self.store.as_ref(), &self.codec)?
            .ok_or(FsError::InvalidRootPointer)?;
        self.allocator.mark_allocated(rp.superblock_ref.block_id)?;

        // Walk root inode.
        self.mark_inode_tree(sb.root_inode_ref.block_id)?;

        // Set next_inode_id to be higher than any seen inode.
        // (We updated it during the walk.)

        Ok(())
    }

    fn mark_inode_tree(&mut self, inode_block: u64) -> FsResult<()> {
        self.allocator.mark_allocated(inode_block)?;
        let inode: Inode = self.read_obj(inode_block)?;

        if inode.id >= self.next_inode_id {
            self.next_inode_id = inode.id + 1;
        }

        match inode.kind {
            InodeKind::Directory => {
                if !inode.directory_page_ref.is_null() {
                    self.allocator
                        .mark_allocated(inode.directory_page_ref.block_id)?;
                    let dir_page: DirectoryPage =
                        self.read_obj(inode.directory_page_ref.block_id)?;
                    for entry in &dir_page.entries {
                        self.mark_inode_tree(entry.inode_ref.block_id)?;
                    }
                }
            }
            InodeKind::File => {
                if !inode.extent_map_ref.is_null() {
                    self.allocator
                        .mark_allocated(inode.extent_map_ref.block_id)?;
                    let extent_map: ExtentMap = self.read_obj(inode.extent_map_ref.block_id)?;
                    for entry in &extent_map.entries {
                        self.allocator.mark_allocated(entry.data_ref.block_id)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Return type for directory listings (used by FFI and public API).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirListEntry {
    pub name: String,
    pub kind: InodeKind,
    pub size: u64,
    pub inode_id: InodeId,
}
