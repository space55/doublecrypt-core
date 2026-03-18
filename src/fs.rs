use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::allocator::{BitmapAllocator, SlotAllocator};
use crate::block_store::BlockStore;
use crate::codec::{
    read_encrypted_object, read_encrypted_raw, write_encrypted_object, write_encrypted_raw,
    ObjectCodec, PostcardCodec,
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
}

/// Tracks one ancestor directory during path resolution, used by
/// `commit_cow_chain` to propagate CoW writes back to the root.
struct AncestorEntry {
    inode: Inode,
    dir_page: DirectoryPage,
    child_index: usize,
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
        for ancestor in ancestors.iter().rev() {
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
        Ok(())
    }

    // ── Public operations ─────────────────────────────────────

    /// Create a new empty file at the given path.
    ///
    /// Parent directories must already exist.  The leaf name is created in
    /// the innermost directory.
    pub fn create_file(&mut self, path: &str) -> FsResult<()> {
        let (dir_parts, leaf) = Self::split_path(path)?;
        self.validate_name(leaf)?;
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
    pub fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) -> FsResult<()> {
        let (dir_parts, leaf) = Self::split_path(path)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let (ancestors, target_inode, dir_page) =
            self.resolve_dir_chain(&dir_parts, &root_inode)?;

        let entry = dir_page
            .entries
            .iter()
            .find(|e| e.name == leaf)
            .ok_or_else(|| FsError::FileNotFound(leaf.to_string()))?;

        if entry.kind != InodeKind::File {
            return Err(FsError::NotAFile(leaf.to_string()));
        }

        let file_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
        let mut extent_map: ExtentMap = self.read_obj(file_inode.extent_map_ref.block_id)?;

        // V1: support write-at-offset by building a full buffer.
        // Read existing data (if any) and splice in the new data.
        let mut buf = self.read_all_chunks(&extent_map)?;

        let end = offset as usize + data.len();
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[offset as usize..end].copy_from_slice(data);

        let total_size = buf.len();

        // Re-chunk the data. Each chunk must fit in max_chunk_payload.
        let chunk_size = max_chunk_payload(self.store.block_size());
        if chunk_size == 0 {
            return Err(FsError::DataTooLarge(total_size));
        }

        let mut new_entries = Vec::new();
        for (i, chunk_data) in buf.chunks(chunk_size).enumerate() {
            let data_block = self.allocator.allocate()?;
            write_encrypted_raw(
                self.store.as_ref(),
                self.crypto.as_ref(),
                &self.codec,
                data_block,
                ObjectKind::FileDataChunk,
                chunk_data,
            )?;
            new_entries.push(ExtentEntry {
                chunk_index: i as u64,
                data_ref: ObjectRef::new(data_block),
                plaintext_len: chunk_data.len() as u32,
            });
        }

        // TODO: free old data blocks (deferred GC).
        extent_map.entries = new_entries;

        // Write updated extent map (CoW).
        let new_em_block = self.allocator.allocate()?;
        self.write_obj(new_em_block, ObjectKind::ExtentMap, &extent_map)?;

        // Write updated file inode.
        let mut new_file_inode = file_inode.clone();
        new_file_inode.size = total_size as u64;
        new_file_inode.extent_map_ref = ObjectRef::new(new_em_block);
        new_file_inode.modified_at = now_secs();
        let new_inode_block = self.allocator.allocate()?;
        self.write_obj(new_inode_block, ObjectKind::Inode, &new_file_inode)?;

        // Update directory entry to point to new inode block.
        let mut new_dir_page = dir_page.clone();
        for e in &mut new_dir_page.entries {
            if e.name == leaf {
                e.inode_ref = ObjectRef::new(new_inode_block);
            }
        }

        self.commit_cow_chain(&sb, &ancestors, &target_inode, &new_dir_page)?;
        Ok(())
    }

    /// Read file data at the given path. Returns the requested slice.
    pub fn read_file(&self, path: &str, offset: u64, len: usize) -> FsResult<Vec<u8>> {
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
        let extent_map: ExtentMap = self.read_obj(file_inode.extent_map_ref.block_id)?;

        let full_data = self.read_all_chunks(&extent_map)?;

        let start = offset as usize;
        if start >= full_data.len() {
            return Ok(Vec::new());
        }
        let end = std::cmp::min(start + len, full_data.len());
        Ok(full_data[start..end].to_vec())
    }

    /// List entries in a directory at the given path.
    ///
    /// Pass `""` or `"/"` to list the root directory.
    pub fn list_directory(&self, path: &str) -> FsResult<Vec<DirListEntry>> {
        let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;

        let components = Self::split_dir_path(path);
        let (_, _, dir_page) = self.resolve_dir_chain(&components, &root_inode)?;

        let mut result = Vec::new();
        for entry in &dir_page.entries {
            let inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
            result.push(DirListEntry {
                name: entry.name.clone(),
                kind: entry.kind,
                size: inode.size,
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

        let entry = &dir_page.entries[idx];
        if entry.kind == InodeKind::Directory {
            let dir_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
            let sub_page: DirectoryPage = self.read_obj(dir_inode.directory_page_ref.block_id)?;
            if !sub_page.entries.is_empty() {
                return Err(FsError::DirectoryNotEmpty(leaf.to_string()));
            }
        }

        dir_page.entries.remove(idx);
        self.commit_cow_chain(&sb, &ancestors, &target_inode, &dir_page)?;
        Ok(())
    }

    /// Rename a file or directory.  Both `old_path` and `new_path` must share
    /// the same parent directory (move across directories is not supported yet).
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> FsResult<()> {
        let (old_dir, old_leaf) = Self::split_path(old_path)?;
        let (new_dir, new_leaf) = Self::split_path(new_path)?;
        self.validate_name(new_leaf)?;

        if old_dir != new_dir {
            return Err(FsError::Internal(
                "rename across directories is not supported".into(),
            ));
        }

        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
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
        Ok(())
    }

    /// Sync / flush. Calls through to the block store sync.
    pub fn sync(&self) -> FsResult<()> {
        self.store.sync()
    }

    // ── Internal helpers ──

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
        read_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            block_id,
        )
    }

    fn write_obj<T: serde::Serialize>(
        &self,
        block_id: u64,
        kind: ObjectKind,
        obj: &T,
    ) -> FsResult<()> {
        write_encrypted_object(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            block_id,
            kind,
            obj,
        )
    }

    fn read_all_chunks(&self, extent_map: &ExtentMap) -> FsResult<Vec<u8>> {
        let mut entries = extent_map.entries.clone();
        entries.sort_by_key(|e| e.chunk_index);

        let mut buf = Vec::new();
        for entry in &entries {
            let chunk = read_encrypted_raw(
                self.store.as_ref(),
                self.crypto.as_ref(),
                &self.codec,
                entry.data_ref.block_id,
            )?;
            // Only take plaintext_len bytes (chunk may have been decrypted from padded block).
            let len = entry.plaintext_len as usize;
            if len <= chunk.len() {
                buf.extend_from_slice(&chunk[..len]);
            } else {
                buf.extend_from_slice(&chunk);
            }
        }
        Ok(buf)
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
        self.txn.commit(
            self.store.as_ref(),
            self.crypto.as_ref(),
            &self.codec,
            &self.allocator,
            &sb,
        )?;
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
