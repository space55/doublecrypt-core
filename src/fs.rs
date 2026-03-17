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

    /// Create a new empty file in the given directory (by inode ref).
    /// For V1, only root directory is supported.
    pub fn create_file(&mut self, name: &str) -> FsResult<()> {
        self.validate_name(name)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();

        // Load root inode and its directory page.
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let mut dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        // Check for duplicate.
        if dir_page.entries.iter().any(|e| e.name == name) {
            return Err(FsError::FileAlreadyExists(name.to_string()));
        }

        // Create empty extent map for the file.
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

        // Add directory entry.
        dir_page.entries.push(DirectoryEntry {
            name: name.to_string(),
            inode_ref: ObjectRef::new(inode_block),
            inode_id,
            kind: InodeKind::File,
        });

        // Write updated directory page (CoW: new block).
        let new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &dir_page)?;

        // Write updated root inode (CoW).
        let mut new_root = root_inode.clone();
        new_root.directory_page_ref = ObjectRef::new(new_dp_block);
        new_root.modified_at = now_secs();
        let new_root_block = self.allocator.allocate()?;
        self.write_obj(new_root_block, ObjectKind::Inode, &new_root)?;

        // Update and commit superblock.
        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_root_block),
        };
        self.commit_superblock(new_sb)?;

        Ok(())
    }

    /// Write data to a file. For V1, this replaces the entire file content
    /// (single chunk only if it fits in one block).
    pub fn write_file(&mut self, name: &str, offset: u64, data: &[u8]) -> FsResult<()> {
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        let entry = dir_page
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| FsError::FileNotFound(name.to_string()))?;

        if entry.kind != InodeKind::File {
            return Err(FsError::NotAFile(name.to_string()));
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
            if e.name == name {
                e.inode_ref = ObjectRef::new(new_inode_block);
            }
        }
        let new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &new_dir_page)?;

        // Update root inode.
        let mut new_root = root_inode.clone();
        new_root.directory_page_ref = ObjectRef::new(new_dp_block);
        new_root.modified_at = now_secs();
        let new_root_block = self.allocator.allocate()?;
        self.write_obj(new_root_block, ObjectKind::Inode, &new_root)?;

        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_root_block),
        };
        self.commit_superblock(new_sb)?;

        Ok(())
    }

    /// Read file data. Returns the requested slice of the file.
    pub fn read_file(&self, name: &str, offset: u64, len: usize) -> FsResult<Vec<u8>> {
        let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        let entry = dir_page
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| FsError::FileNotFound(name.to_string()))?;

        if entry.kind != InodeKind::File {
            return Err(FsError::NotAFile(name.to_string()));
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

    /// List entries in the root directory.
    pub fn list_directory(&self) -> FsResult<Vec<DirListEntry>> {
        let sb = self.superblock.as_ref().ok_or(FsError::NotInitialized)?;
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

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

    /// Create a subdirectory in the root directory.
    pub fn create_directory(&mut self, name: &str) -> FsResult<()> {
        self.validate_name(name)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let mut dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        if dir_page.entries.iter().any(|e| e.name == name) {
            return Err(FsError::DirectoryAlreadyExists(name.to_string()));
        }

        // Create empty directory page for the new subdirectory.
        let sub_dp = DirectoryPage::new();
        let sub_dp_block = self.allocator.allocate()?;
        self.write_obj(sub_dp_block, ObjectKind::DirectoryPage, &sub_dp)?;

        // Create directory inode.
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
            name: name.to_string(),
            inode_ref: ObjectRef::new(inode_block),
            inode_id,
            kind: InodeKind::Directory,
        });

        // CoW commit chain.
        let new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &dir_page)?;

        let mut new_root = root_inode.clone();
        new_root.directory_page_ref = ObjectRef::new(new_dp_block);
        new_root.modified_at = now_secs();
        let new_root_block = self.allocator.allocate()?;
        self.write_obj(new_root_block, ObjectKind::Inode, &new_root)?;

        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_root_block),
        };
        self.commit_superblock(new_sb)?;

        Ok(())
    }

    /// Remove a file from the root directory.
    pub fn remove_file(&mut self, name: &str) -> FsResult<()> {
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let mut dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        let idx = dir_page
            .entries
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| FsError::FileNotFound(name.to_string()))?;

        let entry = &dir_page.entries[idx];
        if entry.kind == InodeKind::Directory {
            // Check if directory is empty.
            let dir_inode: Inode = self.read_obj(entry.inode_ref.block_id)?;
            let sub_page: DirectoryPage = self.read_obj(dir_inode.directory_page_ref.block_id)?;
            if !sub_page.entries.is_empty() {
                return Err(FsError::DirectoryNotEmpty(name.to_string()));
            }
        }

        // TODO: free blocks belonging to the removed file (deferred GC).
        dir_page.entries.remove(idx);

        // CoW commit chain.
        let new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &dir_page)?;

        let mut new_root = root_inode.clone();
        new_root.directory_page_ref = ObjectRef::new(new_dp_block);
        new_root.modified_at = now_secs();
        let new_root_block = self.allocator.allocate()?;
        self.write_obj(new_root_block, ObjectKind::Inode, &new_root)?;

        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_root_block),
        };
        self.commit_superblock(new_sb)?;

        Ok(())
    }

    /// Rename a file or directory within the root directory.
    pub fn rename(&mut self, old_name: &str, new_name: &str) -> FsResult<()> {
        self.validate_name(new_name)?;
        let sb = self
            .superblock
            .as_ref()
            .ok_or(FsError::NotInitialized)?
            .clone();
        let root_inode: Inode = self.read_obj(sb.root_inode_ref.block_id)?;
        let mut dir_page: DirectoryPage = self.read_obj(root_inode.directory_page_ref.block_id)?;

        // Check that new_name doesn't already exist.
        if dir_page.entries.iter().any(|e| e.name == new_name) {
            return Err(FsError::FileAlreadyExists(new_name.to_string()));
        }

        let entry = dir_page
            .entries
            .iter_mut()
            .find(|e| e.name == old_name)
            .ok_or_else(|| FsError::FileNotFound(old_name.to_string()))?;

        entry.name = new_name.to_string();

        // CoW commit chain.
        let new_dp_block = self.allocator.allocate()?;
        self.write_obj(new_dp_block, ObjectKind::DirectoryPage, &dir_page)?;

        let mut new_root = root_inode.clone();
        new_root.directory_page_ref = ObjectRef::new(new_dp_block);
        new_root.modified_at = now_secs();
        let new_root_block = self.allocator.allocate()?;
        self.write_obj(new_root_block, ObjectKind::Inode, &new_root)?;

        let new_sb = Superblock {
            generation: sb.generation + 1,
            root_inode_ref: ObjectRef::new(new_root_block),
        };
        self.commit_superblock(new_sb)?;

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
