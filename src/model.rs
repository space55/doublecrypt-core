use serde::{Deserialize, Serialize};

/// Default block size: 64 KiB.
pub const DEFAULT_BLOCK_SIZE: usize = 65536;

/// Maximum filename length in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Reserved block IDs.
pub const BLOCK_STORAGE_HEADER: u64 = 0;
pub const BLOCK_ROOT_POINTER_A: u64 = 1;
pub const BLOCK_ROOT_POINTER_B: u64 = 2;

/// First allocatable block ID (after reserved blocks).
pub const FIRST_DATA_BLOCK: u64 = 3;

// ── Object types ──

/// Identifies the kind of logical object stored in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ObjectKind {
    Superblock = 1,
    RootPointer = 2,
    Inode = 3,
    DirectoryPage = 4,
    ExtentMap = 5,
    FileDataChunk = 6,
}

/// A reference to a logical object stored at a particular block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ObjectRef {
    /// Block ID where the object is stored.
    pub block_id: u64,
}

impl ObjectRef {
    pub fn new(block_id: u64) -> Self {
        Self { block_id }
    }

    pub fn null() -> Self {
        Self { block_id: u64::MAX }
    }

    pub fn is_null(&self) -> bool {
        self.block_id == u64::MAX
    }
}

// ── Storage header ──

/// Written to block 0. Identifies the filesystem format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub block_size: u32,
    pub total_blocks: u64,
}

impl StorageHeader {
    pub const MAGIC: [u8; 8] = *b"DBLCRYPT";

    pub fn new(block_size: u32, total_blocks: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            block_size,
            total_blocks,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == 1
    }
}

// ── Root pointer ──

/// Stored in block 1 (A) and block 2 (B). Points to the current superblock.
/// We alternate between A and B to get atomic commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootPointer {
    /// Monotonic generation counter. Higher = newer.
    pub generation: u64,
    /// Block ID of the current superblock object.
    pub superblock_ref: ObjectRef,
    /// BLAKE3 checksum of the serialized superblock for integrity.
    pub checksum: [u8; 32],
}

// ── Superblock ──

/// The root metadata object for the filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Superblock {
    pub generation: u64,
    /// Reference to the root directory inode.
    pub root_inode_ref: ObjectRef,
}

// ── Inode ──

/// The type of a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InodeKind {
    File = 1,
    Directory = 2,
}

/// Unique inode identifier. Monotonically allocated.
pub type InodeId = u64;

/// Metadata for a single filesystem object (file or directory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub id: InodeId,
    pub kind: InodeKind,
    /// For files: total size in bytes. For directories: 0.
    pub size: u64,
    /// For directories: reference to a DirectoryPage object.
    /// For files: ObjectRef::null().
    pub directory_page_ref: ObjectRef,
    /// For files: reference to the ExtentMap object.
    /// For directories: ObjectRef::null().
    pub extent_map_ref: ObjectRef,
    /// Unix timestamp – seconds since epoch. Placeholder for now.
    pub created_at: u64,
    pub modified_at: u64,
}

// ── Directory ──

/// A single entry in a directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// The name of this entry (file or subdirectory).
    pub name: String,
    /// Reference to the inode for this entry.
    pub inode_ref: ObjectRef,
    /// Inode ID (for quick lookup without loading the full inode).
    pub inode_id: InodeId,
    /// Kind hint so we can distinguish files/dirs without loading inode.
    pub kind: InodeKind,
}

/// A single page of directory entries. V1 uses one page per directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryPage {
    pub entries: Vec<DirectoryEntry>,
}

impl DirectoryPage {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

// ── Extent map ──

/// Maps a logical file chunk index to a block containing the encrypted data chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtentEntry {
    /// Chunk index (0-based).
    pub chunk_index: u64,
    /// Reference to the block containing the encrypted file data chunk.
    pub data_ref: ObjectRef,
    /// Size of the plaintext data in this chunk.
    pub plaintext_len: u32,
}

/// Per-file map of chunks. V1 uses one extent map per file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtentMap {
    pub entries: Vec<ExtentEntry>,
}

impl ExtentMap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

// ── Encrypted envelope ──

/// The on-disk (on-block) format: a serialized+encrypted logical object.
/// This is what actually gets written into a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedObject {
    pub kind: ObjectKind,
    pub version: u32,
    /// 12-byte nonce for ChaCha20-Poly1305.
    pub nonce: [u8; 12],
    /// Ciphertext (includes Poly1305 tag appended by AEAD).
    pub ciphertext: Vec<u8>,
}

// ── Logical object ──

/// A decrypted logical object with its kind tag and plaintext payload.
#[derive(Debug, Clone)]
pub struct LogicalObject {
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
}
