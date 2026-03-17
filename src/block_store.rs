use crate::error::{FsError, FsResult};
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
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
        let blocks = self
            .blocks
            .lock()
            .map_err(|e| FsError::Internal(e.to_string()))?;
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
        let mut blocks = self
            .blocks
            .lock()
            .map_err(|e| FsError::Internal(e.to_string()))?;
        blocks.insert(block_id, data.to_vec());
        Ok(())
    }
}

/// File-backed block store. Uses a regular file as a virtual block device.
///
/// Uses `pread`/`pwrite` (via `FileExt`) for positioned I/O without seeking,
/// which is safe for concurrent reads without a mutex on the file descriptor.
pub struct DiskBlockStore {
    file: File,
    block_size: usize,
    total_blocks: u64,
}

impl DiskBlockStore {
    /// Open an existing file as a block store.
    ///
    /// The file must already exist and be at least `block_size * total_blocks` bytes.
    /// If `total_blocks` is 0, it is inferred from the file size.
    pub fn open(path: &str, block_size: usize, total_blocks: u64) -> FsResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FsError::Internal(format!("open {path}: {e}")))?;

        let file_len = file
            .metadata()
            .map_err(|e| FsError::Internal(format!("stat {path}: {e}")))?
            .len();

        let total_blocks = if total_blocks == 0 {
            file_len / block_size as u64
        } else {
            total_blocks
        };

        let required = total_blocks * block_size as u64;
        if file_len < required {
            return Err(FsError::Internal(format!(
                "file too small: {file_len} bytes, need {required}"
            )));
        }

        Ok(Self {
            file,
            block_size,
            total_blocks,
        })
    }

    /// Create a new file of the given size and open it as a block store.
    ///
    /// Every block is filled with cryptographically random data so that
    /// unallocated blocks are indistinguishable from encrypted ones.
    pub fn create(path: &str, block_size: usize, total_blocks: u64) -> FsResult<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| FsError::Internal(format!("create {path}: {e}")))?;

        // Fill every block with random bytes so free space looks like ciphertext.
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; block_size];
        for _ in 0..total_blocks {
            rng.fill_bytes(&mut buf);
            file.write_all(&buf)
                .map_err(|e| FsError::Internal(format!("write {path}: {e}")))?;
        }
        file.sync_all()
            .map_err(|e| FsError::Internal(format!("sync {path}: {e}")))?;

        Ok(Self {
            file,
            block_size,
            total_blocks,
        })
    }
}

impl BlockStore for DiskBlockStore {
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
        let offset = block_id * self.block_size as u64;
        let mut buf = vec![0u8; self.block_size];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|e| FsError::Internal(format!("read block {block_id}: {e}")))?;
        Ok(buf)
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
        let offset = block_id * self.block_size as u64;
        self.file
            .write_all_at(data, offset)
            .map_err(|e| FsError::Internal(format!("write block {block_id}: {e}")))?;
        Ok(())
    }

    fn sync(&self) -> FsResult<()> {
        self.file
            .sync_all()
            .map_err(|e| FsError::Internal(format!("fsync: {e}")))
    }
}

/// Block-device-backed block store for raw devices such as EBS volumes.
///
/// Unlike [`DiskBlockStore`] which operates on regular files, this backend
/// targets raw block devices (e.g. `/dev/xvdf`, `/dev/nvme1n1p1`).  The
/// device must already exist; Linux does not allow creating device nodes
/// from userspace in the normal flow.
///
/// Device size is discovered via `lseek(SEEK_END)` because `stat()` reports
/// `st_size = 0` for block devices.  I/O uses `pread`/`pwrite` (via
/// [`FileExt`]) exactly like `DiskBlockStore`.
pub struct DeviceBlockStore {
    file: File,
    block_size: usize,
    total_blocks: u64,
}

impl DeviceBlockStore {
    /// Open an existing block device.
    ///
    /// `total_blocks` – pass 0 to infer from the device size.
    pub fn open(path: &str, block_size: usize, total_blocks: u64) -> FsResult<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FsError::Internal(format!("open device {path}: {e}")))?;

        let device_size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| FsError::Internal(format!("seek device {path}: {e}")))?;

        let total_blocks = if total_blocks == 0 {
            device_size / block_size as u64
        } else {
            total_blocks
        };

        let required = total_blocks * block_size as u64;
        if device_size < required {
            return Err(FsError::Internal(format!(
                "device too small: {device_size} bytes, need {required}"
            )));
        }

        Ok(Self {
            file,
            block_size,
            total_blocks,
        })
    }

    /// Initialize a block device by filling every block with random data so
    /// that free space is indistinguishable from ciphertext.
    ///
    /// **Warning:** this writes to *every* block and can take a long time on
    /// large volumes.  Call this once when first provisioning the device.
    ///
    /// `total_blocks` – pass 0 to use the entire device.
    pub fn initialize(path: &str, block_size: usize, total_blocks: u64) -> FsResult<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FsError::Internal(format!("open device {path}: {e}")))?;

        let device_size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| FsError::Internal(format!("seek device {path}: {e}")))?;

        let total_blocks = if total_blocks == 0 {
            device_size / block_size as u64
        } else {
            total_blocks
        };

        let required = total_blocks * block_size as u64;
        if device_size < required {
            return Err(FsError::Internal(format!(
                "device too small: {device_size} bytes, need {required}"
            )));
        }

        // Seek back to the start before writing.
        file.seek(SeekFrom::Start(0))
            .map_err(|e| FsError::Internal(format!("seek device {path}: {e}")))?;

        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; block_size];
        for _ in 0..total_blocks {
            rng.fill_bytes(&mut buf);
            file.write_all(&buf)
                .map_err(|e| FsError::Internal(format!("write device {path}: {e}")))?;
        }
        file.sync_all()
            .map_err(|e| FsError::Internal(format!("sync device {path}: {e}")))?;

        Ok(Self {
            file,
            block_size,
            total_blocks,
        })
    }
}

impl BlockStore for DeviceBlockStore {
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
        let offset = block_id * self.block_size as u64;
        let mut buf = vec![0u8; self.block_size];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|e| FsError::Internal(format!("read block {block_id}: {e}")))?;
        Ok(buf)
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
        let offset = block_id * self.block_size as u64;
        self.file
            .write_all_at(data, offset)
            .map_err(|e| FsError::Internal(format!("write block {block_id}: {e}")))?;
        Ok(())
    }

    fn sync(&self) -> FsResult<()> {
        self.file
            .sync_all()
            .map_err(|e| FsError::Internal(format!("fsync: {e}")))
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

    #[test]
    fn test_disk_block_store_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("doublecrypt_test_{}.img", std::process::id()));
        let path_str = path.to_str().unwrap();

        // Cleanup if leftover from a previous run.
        let _ = std::fs::remove_file(&path);

        let store = DiskBlockStore::create(path_str, 512, 16).unwrap();
        let data = vec![0xAB; 512];
        store.write_block(0, &data).unwrap();
        store.sync().unwrap();
        let read = store.read_block(0).unwrap();
        assert_eq!(read, data);

        // Unwritten block should be random-filled (not zero).
        let unwritten = store.read_block(10).unwrap();
        assert_eq!(unwritten.len(), 512);
        // Overwhelmingly unlikely that 512 random bytes are all zero.
        assert!(unwritten.iter().any(|&b| b != 0));

        // Out of range.
        assert!(store.read_block(16).is_err());
        assert!(store.write_block(16, &data).is_err());

        // Block size mismatch.
        assert!(store.write_block(0, &[0u8; 64]).is_err());

        drop(store);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_disk_block_store_open_existing() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("doublecrypt_test_open_{}.img", std::process::id()));
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);

        // Create and write.
        {
            let store = DiskBlockStore::create(path_str, 256, 8).unwrap();
            let data = vec![0xCD; 256];
            store.write_block(3, &data).unwrap();
            store.sync().unwrap();
        }

        // Reopen and verify.
        {
            let store = DiskBlockStore::open(path_str, 256, 8).unwrap();
            let read = store.read_block(3).unwrap();
            assert_eq!(read, vec![0xCD; 256]);
        }

        // Open with inferred total_blocks (0).
        {
            let store = DiskBlockStore::open(path_str, 256, 0).unwrap();
            assert_eq!(store.total_blocks(), 8);
        }

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_disk_block_store_file_too_small() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("doublecrypt_test_small_{}.img", std::process::id()));
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);

        // Create a small file.
        std::fs::write(&path, vec![0u8; 100]).unwrap();

        // Try to open with more blocks than fit.
        assert!(DiskBlockStore::open(path_str, 256, 8).is_err());

        std::fs::remove_file(&path).unwrap();
    }
}
