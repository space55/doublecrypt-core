use crate::error::{FsError, FsResult};
use crate::model::EncryptedObject;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Trait for encrypting and decrypting logical object payloads.
pub trait CryptoEngine: Send + Sync {
    /// Encrypt plaintext into ciphertext with a nonce. Returns (nonce, ciphertext).
    fn encrypt(&self, plaintext: &[u8]) -> FsResult<(Vec<u8>, Vec<u8>)>;

    /// Decrypt ciphertext with the given nonce. Returns plaintext.
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> FsResult<Vec<u8>>;
}

/// ChaCha20-Poly1305 based crypto engine.
/// Derives the actual encryption key from a master key using HKDF.
pub struct ChaChaEngine {
    /// Derived 256-bit encryption key.
    key: [u8; 32],
}

impl ChaChaEngine {
    /// Create from a raw master key. The encryption key is derived via HKDF-SHA256.
    pub fn new(master_key: &[u8]) -> FsResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(b"doublecrypt-v1"), master_key);
        let mut key = [0u8; 32];
        hk.expand(b"block-encryption", &mut key)
            .map_err(|e| FsError::Encryption(format!("HKDF expand failed: {e}")))?;
        Ok(Self { key })
    }

    /// Convenience: create with a randomly generated master key (for testing / new FS).
    pub fn generate() -> FsResult<Self> {
        let mut master = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master);
        let engine = Self::new(&master)?;
        master.zeroize();
        Ok(engine)
    }
}

impl CryptoEngine for ChaChaEngine {
    fn encrypt(&self, plaintext: &[u8]) -> FsResult<(Vec<u8>, Vec<u8>)> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| FsError::Encryption(format!("AEAD encrypt failed: {e}")))?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> FsResult<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(FsError::Decryption(format!(
                "invalid nonce length: {}",
                nonce.len()
            )));
        }
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| FsError::Decryption(format!("AEAD decrypt failed: {e}")))
    }
}

impl Drop for ChaChaEngine {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Encrypt a logical object payload into an EncryptedObject envelope.
pub fn encrypt_object(
    engine: &dyn CryptoEngine,
    kind: crate::model::ObjectKind,
    plaintext: &[u8],
) -> FsResult<EncryptedObject> {
    let (nonce_vec, ciphertext) = engine.encrypt(plaintext)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    Ok(EncryptedObject {
        kind,
        version: 1,
        nonce,
        ciphertext,
    })
}

/// Decrypt an EncryptedObject envelope back to plaintext bytes.
pub fn decrypt_object(
    engine: &dyn CryptoEngine,
    obj: &EncryptedObject,
) -> FsResult<Vec<u8>> {
    engine.decrypt(&obj.nonce, &obj.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ObjectKind;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let engine = ChaChaEngine::generate().unwrap();
        let plaintext = b"hello, doublecrypt!";
        let enc = encrypt_object(&engine, ObjectKind::FileDataChunk, plaintext).unwrap();
        let dec = decrypt_object(&engine, &enc).unwrap();
        assert_eq!(&dec, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let engine1 = ChaChaEngine::generate().unwrap();
        let engine2 = ChaChaEngine::generate().unwrap();
        let plaintext = b"secret data";
        let enc = encrypt_object(&engine1, ObjectKind::FileDataChunk, plaintext).unwrap();
        assert!(decrypt_object(&engine2, &enc).is_err());
    }
}
