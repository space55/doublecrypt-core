use rand::RngCore;

use crate::block_store::BlockStore;
use crate::crypto::{decrypt_object, encrypt_object, CryptoEngine};
use crate::error::{FsError, FsResult};
use crate::model::*;

/// Create a block-sized buffer filled with random bytes.
fn random_block(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Trait for serializing and deserializing logical objects to/from bytes.
pub trait ObjectCodec: Send + Sync {
    fn serialize_object<T: serde::Serialize>(&self, obj: &T) -> FsResult<Vec<u8>>;
    fn deserialize_object<T: serde::de::DeserializeOwned>(&self, bytes: &[u8]) -> FsResult<T>;
}

/// Postcard-based codec (compact binary serialization).
pub struct PostcardCodec;

impl ObjectCodec for PostcardCodec {
    fn serialize_object<T: serde::Serialize>(&self, obj: &T) -> FsResult<Vec<u8>> {
        postcard::to_allocvec(obj).map_err(|e| FsError::Serialization(e.to_string()))
    }

    fn deserialize_object<T: serde::de::DeserializeOwned>(&self, bytes: &[u8]) -> FsResult<T> {
        postcard::from_bytes(bytes).map_err(|e| FsError::Deserialization(e.to_string()))
    }
}

/// High-level helper: serialize a typed object, encrypt it, pad to block size, and write.
pub fn write_encrypted_object<T: serde::Serialize>(
    store: &dyn BlockStore,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    block_id: u64,
    kind: ObjectKind,
    obj: &T,
) -> FsResult<()> {
    let plaintext = codec.serialize_object(obj)?;
    let encrypted = encrypt_object(crypto, kind, &plaintext)?;
    let envelope_bytes = codec.serialize_object(&encrypted)?;

    let block_size = store.block_size();
    if envelope_bytes.len() > block_size {
        return Err(FsError::DataTooLarge(envelope_bytes.len()));
    }

    // Pad to block size with random bytes so padding is indistinguishable from ciphertext.
    let mut block = random_block(block_size);
    // First 4 bytes: little-endian length of the envelope.
    let len = envelope_bytes.len() as u32;
    block[..4].copy_from_slice(&len.to_le_bytes());
    block[4..4 + envelope_bytes.len()].copy_from_slice(&envelope_bytes);

    store.write_block(block_id, &block)
}

/// High-level helper: read a block, extract envelope, decrypt, deserialize.
pub fn read_encrypted_object<T: serde::de::DeserializeOwned>(
    store: &dyn BlockStore,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    block_id: u64,
) -> FsResult<T> {
    let plaintext = decrypt_block_to_plaintext(store, crypto, codec, block_id)?;
    codec.deserialize_object(&plaintext)
}

/// Read a block, extract envelope, decrypt, and return the raw plaintext bytes
/// (before deserialization into a typed object).  Used by the object cache.
pub fn decrypt_block_to_plaintext(
    store: &dyn BlockStore,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    block_id: u64,
) -> FsResult<Vec<u8>> {
    let block = store.read_block(block_id)?;

    if block.len() < 4 {
        return Err(FsError::Deserialization("block too small".into()));
    }

    let len = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
    if len == 0 || 4 + len > block.len() {
        return Err(FsError::ObjectNotFound(block_id));
    }

    let envelope_bytes = &block[4..4 + len];
    let encrypted: EncryptedObject = codec.deserialize_object(envelope_bytes)?;
    decrypt_object(crypto, &encrypted)
}

/// Write raw encrypted bytes (for file data chunks that are already raw bytes).
pub fn write_encrypted_raw(
    store: &dyn BlockStore,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    block_id: u64,
    kind: ObjectKind,
    raw_data: &[u8],
) -> FsResult<()> {
    let block = prepare_encrypted_block(store.block_size(), crypto, codec, kind, raw_data)?;
    store.write_block(block_id, &block)
}

/// Encrypt raw data and pack it into a block-sized buffer (without writing to store).
/// Returns the ready-to-write block bytes.
pub fn prepare_encrypted_block(
    block_size: usize,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    kind: ObjectKind,
    raw_data: &[u8],
) -> FsResult<Vec<u8>> {
    let encrypted = encrypt_object(crypto, kind, raw_data)?;
    let envelope_bytes = codec.serialize_object(&encrypted)?;

    if envelope_bytes.len() > block_size {
        return Err(FsError::DataTooLarge(envelope_bytes.len()));
    }

    let mut block = random_block(block_size);
    let len = envelope_bytes.len() as u32;
    block[..4].copy_from_slice(&len.to_le_bytes());
    block[4..4 + envelope_bytes.len()].copy_from_slice(&envelope_bytes);

    Ok(block)
}

/// Read and decrypt raw bytes (for file data chunks).
pub fn read_encrypted_raw(
    store: &dyn BlockStore,
    crypto: &dyn CryptoEngine,
    codec: &PostcardCodec,
    block_id: u64,
) -> FsResult<Vec<u8>> {
    let block = store.read_block(block_id)?;

    if block.len() < 4 {
        return Err(FsError::Deserialization("block too small".into()));
    }

    let len = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
    if len == 0 || 4 + len > block.len() {
        return Err(FsError::ObjectNotFound(block_id));
    }

    let envelope_bytes = &block[4..4 + len];
    let encrypted: EncryptedObject = codec.deserialize_object(envelope_bytes)?;
    decrypt_object(crypto, &encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_store::MemoryBlockStore;
    use crate::crypto::ChaChaEngine;

    #[test]
    fn test_write_read_encrypted_object() {
        let store = MemoryBlockStore::new(4096, 16);
        let engine = ChaChaEngine::generate().unwrap();
        let codec = PostcardCodec;

        let inode = Inode {
            id: 42,
            kind: InodeKind::File,
            size: 1024,
            directory_page_ref: ObjectRef::null(),
            extent_map_ref: ObjectRef::new(5),
            created_at: 1000,
            modified_at: 2000,
        };

        write_encrypted_object(&store, &engine, &codec, 3, ObjectKind::Inode, &inode).unwrap();
        let recovered: Inode = read_encrypted_object(&store, &engine, &codec, 3).unwrap();

        assert_eq!(recovered.id, 42);
        assert_eq!(recovered.size, 1024);
        assert_eq!(recovered.kind, InodeKind::File);
    }
}
