//! Integration tests for the filesystem core.

use std::sync::Arc;

use crate::block_store::MemoryBlockStore;
use crate::crypto::{ChaChaEngine, CryptoEngine};
use crate::fs::FilesystemCore;
use crate::model::{InodeKind, DEFAULT_BLOCK_SIZE};

/// Helper: create a fresh filesystem with an in-memory block store.
fn make_fs() -> (FilesystemCore, Arc<MemoryBlockStore>, Arc<ChaChaEngine>) {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 1024));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();
    (fs, store, crypto)
}

#[test]
fn test_init_filesystem() {
    let (fs, _, _) = make_fs();
    // Should be able to list empty root directory.
    let entries = fs.list_directory().unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_create_and_read_file() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("hello.txt").unwrap();
    fs.write_file("hello.txt", 0, b"Hello, world!").unwrap();

    let data = fs.read_file("hello.txt", 0, 1024).unwrap();
    assert_eq!(data, b"Hello, world!");
}

#[test]
fn test_overwrite_file_contents() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("data.bin").unwrap();
    fs.write_file("data.bin", 0, b"first version").unwrap();

    let v1 = fs.read_file("data.bin", 0, 1024).unwrap();
    assert_eq!(v1, b"first version");

    fs.write_file("data.bin", 0, b"second version!!").unwrap();

    let v2 = fs.read_file("data.bin", 0, 1024).unwrap();
    assert_eq!(v2, b"second version!!");
}

#[test]
fn test_write_at_offset() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("offset.txt").unwrap();
    fs.write_file("offset.txt", 0, b"AAAAAAAAAA").unwrap(); // 10 bytes
    fs.write_file("offset.txt", 5, b"BBBBB").unwrap(); // overwrite bytes 5..10

    let data = fs.read_file("offset.txt", 0, 1024).unwrap();
    assert_eq!(data, b"AAAAABBBBB");
}

#[test]
fn test_read_at_offset() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("slice.txt").unwrap();
    fs.write_file("slice.txt", 0, b"0123456789").unwrap();

    let data = fs.read_file("slice.txt", 3, 4).unwrap();
    assert_eq!(data, b"3456");
}

#[test]
fn test_list_root_directory() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("a.txt").unwrap();
    fs.create_file("b.txt").unwrap();
    fs.create_directory("subdir").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 3);

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.txt"));
    assert!(names.contains(&"b.txt"));
    assert!(names.contains(&"subdir"));

    let subdir = entries.iter().find(|e| e.name == "subdir").unwrap();
    assert_eq!(subdir.kind, InodeKind::Directory);

    let a = entries.iter().find(|e| e.name == "a.txt").unwrap();
    assert_eq!(a.kind, InodeKind::File);
}

#[test]
fn test_create_directory() {
    let (mut fs, _, _) = make_fs();

    fs.create_directory("mydir").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "mydir");
    assert_eq!(entries[0].kind, InodeKind::Directory);
}

#[test]
fn test_rename_file() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("old.txt").unwrap();
    fs.write_file("old.txt", 0, b"content").unwrap();

    fs.rename("old.txt", "new.txt").unwrap();

    // Old name should not exist.
    assert!(fs.read_file("old.txt", 0, 1024).is_err());

    // New name should have the data.
    let data = fs.read_file("new.txt", 0, 1024).unwrap();
    assert_eq!(data, b"content");
}

#[test]
fn test_delete_file() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("doomed.txt").unwrap();
    fs.write_file("doomed.txt", 0, b"bye").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 1);

    fs.remove_file("doomed.txt").unwrap();

    let entries = fs.list_directory().unwrap();
    assert!(entries.is_empty());

    // Should fail to read deleted file.
    assert!(fs.read_file("doomed.txt", 0, 1024).is_err());
}

#[test]
fn test_delete_empty_directory() {
    let (mut fs, _, _) = make_fs();

    fs.create_directory("emptydir").unwrap();
    fs.remove_file("emptydir").unwrap();

    let entries = fs.list_directory().unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_duplicate_file_fails() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("dup.txt").unwrap();
    assert!(fs.create_file("dup.txt").is_err());
}

#[test]
fn test_duplicate_directory_fails() {
    let (mut fs, _, _) = make_fs();

    fs.create_directory("dup").unwrap();
    assert!(fs.create_directory("dup").is_err());
}

#[test]
fn test_read_nonexistent_file() {
    let (fs, _, _) = make_fs();
    assert!(fs.read_file("nope.txt", 0, 1024).is_err());
}

#[test]
fn test_reopen_filesystem() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 1024));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());

    // First session: create and populate.
    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.init_filesystem().unwrap();
        fs.create_file("persist.txt").unwrap();
        fs.write_file("persist.txt", 0, b"I survived a reopen!")
            .unwrap();
        fs.create_directory("mydir").unwrap();
    }

    // Second session: open from the same store.
    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.open().unwrap();

        let entries = fs.list_directory().unwrap();
        assert_eq!(entries.len(), 2);

        let data = fs.read_file("persist.txt", 0, 1024).unwrap();
        assert_eq!(data, b"I survived a reopen!");

        // Should be able to continue operating.
        fs.create_file("new_after_reopen.txt").unwrap();
        fs.write_file("new_after_reopen.txt", 0, b"fresh").unwrap();

        let entries = fs.list_directory().unwrap();
        assert_eq!(entries.len(), 3);
    }

    // Third session: verify again.
    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.open().unwrap();

        let entries = fs.list_directory().unwrap();
        assert_eq!(entries.len(), 3);

        let data = fs.read_file("new_after_reopen.txt", 0, 1024).unwrap();
        assert_eq!(data, b"fresh");
    }
}

#[test]
fn test_large_file_multiple_chunks() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("big.bin").unwrap();

    // Write data larger than a single chunk (~64KiB block - 200 bytes overhead).
    let data = vec![0xAB_u8; 100_000];
    fs.write_file("big.bin", 0, &data).unwrap();

    let read_back = fs.read_file("big.bin", 0, 200_000).unwrap();
    assert_eq!(read_back.len(), 100_000);
    assert_eq!(read_back, data);
}

#[test]
fn test_empty_file_read() {
    let (mut fs, _, _) = make_fs();

    fs.create_file("empty.txt").unwrap();
    let data = fs.read_file("empty.txt", 0, 1024).unwrap();
    assert!(data.is_empty());
}

#[test]
fn test_sync_does_not_error() {
    let (fs, _, _) = make_fs();
    fs.sync().unwrap();
}

// ── Authentication tests ────────────────────────────────────

#[test]
fn test_derive_auth_token_deterministic() {
    let key = [0xABu8; 32];
    let t1 = crate::crypto::derive_auth_token(&key).unwrap();
    let t2 = crate::crypto::derive_auth_token(&key).unwrap();
    assert_eq!(t1, t2, "same master key must produce the same auth token");
}

#[test]
fn test_derive_auth_token_different_keys() {
    let t1 = crate::crypto::derive_auth_token(&[1u8; 32]).unwrap();
    let t2 = crate::crypto::derive_auth_token(&[2u8; 32]).unwrap();
    assert_ne!(
        t1, t2,
        "different master keys must produce different auth tokens"
    );
}

#[test]
fn test_auth_token_independent_of_encryption_key() {
    let master = [0x42u8; 32];
    let auth_token = crate::crypto::derive_auth_token(&master).unwrap();
    let engine = ChaChaEngine::new(&master).unwrap();

    // The encryption key is internal, but we can verify independence by
    // checking that the auth token is not the same bytes as encrypting
    // an empty payload (which would be the case if the same HKDF info
    // were used).
    let (nonce, ciphertext) = engine.encrypt(b"").unwrap();
    // Auth token should not appear anywhere in the encrypt output.
    assert_ne!(auth_token.to_vec(), nonce);
    assert_ne!(auth_token.to_vec(), ciphertext);
    // And the token itself is 32 bytes.
    assert_eq!(auth_token.len(), 32);
}

#[test]
fn test_auth_token_blake3_hash_stable() {
    let master = [0xFFu8; 32];
    let token = crate::crypto::derive_auth_token(&master).unwrap();
    let hash1 = blake3::hash(&token);
    let hash2 = blake3::hash(&token);
    assert_eq!(
        hash1, hash2,
        "BLAKE3 hash of auth token must be deterministic"
    );
    // Different token → different hash.
    let other_token = crate::crypto::derive_auth_token(&[0x00u8; 32]).unwrap();
    let other_hash = blake3::hash(&other_token);
    assert_ne!(hash1, other_hash);
}

#[test]
fn test_authenticate_proto_roundtrip() {
    use crate::proto;
    use prost::Message;

    let token = crate::crypto::derive_auth_token(&[0xAA; 32]).unwrap();

    // Encode a request.
    let req = proto::Request {
        request_id: 42,
        command: Some(proto::request::Command::Authenticate(
            proto::AuthenticateRequest {
                auth_token: token.to_vec(),
            },
        )),
    };
    let bytes = req.encode_to_vec();
    let decoded = proto::Request::decode(&*bytes).unwrap();
    assert_eq!(decoded.request_id, 42);
    match decoded.command {
        Some(proto::request::Command::Authenticate(a)) => {
            assert_eq!(a.auth_token, token.to_vec());
        }
        _ => panic!("expected Authenticate command"),
    }

    // Encode a success response.
    let resp = proto::Response {
        request_id: 42,
        result: Some(proto::response::Result::Authenticate(
            proto::AuthenticateResponse {},
        )),
    };
    let bytes = resp.encode_to_vec();
    let decoded = proto::Response::decode(&*bytes).unwrap();
    assert_eq!(decoded.request_id, 42);
    assert!(matches!(
        decoded.result,
        Some(proto::response::Result::Authenticate(_))
    ));

    // Encode an error response (auth rejected).
    let err_resp = proto::Response {
        request_id: 42,
        result: Some(proto::response::Result::Error(proto::ErrorResponse {
            code: 403,
            message: "invalid auth token".into(),
        })),
    };
    let bytes = err_resp.encode_to_vec();
    let decoded = proto::Response::decode(&*bytes).unwrap();
    match decoded.result {
        Some(proto::response::Result::Error(e)) => {
            assert_eq!(e.code, 403);
            assert_eq!(e.message, "invalid auth token");
        }
        _ => panic!("expected Error result"),
    }
}
