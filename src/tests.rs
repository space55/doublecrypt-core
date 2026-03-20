//! Integration tests for the filesystem core.

use std::sync::Arc;

use crate::block_store::{BlockStore, MemoryBlockStore};
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
    let entries = fs.list_directory("").unwrap();
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

    let entries = fs.list_directory("").unwrap();
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

    let entries = fs.list_directory("").unwrap();
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

    let entries = fs.list_directory("").unwrap();
    assert_eq!(entries.len(), 1);

    fs.remove_file("doomed.txt").unwrap();

    let entries = fs.list_directory("").unwrap();
    assert!(entries.is_empty());

    // Should fail to read deleted file.
    assert!(fs.read_file("doomed.txt", 0, 1024).is_err());
}

#[test]
fn test_delete_empty_directory() {
    let (mut fs, _, _) = make_fs();

    fs.create_directory("emptydir").unwrap();
    fs.remove_file("emptydir").unwrap();

    let entries = fs.list_directory("").unwrap();
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
        fs.sync().unwrap();
    }

    // Second session: open from the same store.
    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.open().unwrap();

        let entries = fs.list_directory("").unwrap();
        assert_eq!(entries.len(), 2);

        let data = fs.read_file("persist.txt", 0, 1024).unwrap();
        assert_eq!(data, b"I survived a reopen!");

        // Should be able to continue operating.
        fs.create_file("new_after_reopen.txt").unwrap();
        fs.write_file("new_after_reopen.txt", 0, b"fresh").unwrap();

        let entries = fs.list_directory("").unwrap();
        assert_eq!(entries.len(), 3);
        fs.sync().unwrap();
    }

    // Third session: verify again.
    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.open().unwrap();

        let entries = fs.list_directory("").unwrap();
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
    let (mut fs, _, _) = make_fs();
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

// ── Nested directory tests ──

#[test]
fn test_nested_create_file() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("docs").unwrap();
    fs.create_file("docs/readme.txt").unwrap();
    fs.write_file("docs/readme.txt", 0, b"hello nested")
        .unwrap();
    let data = fs.read_file("docs/readme.txt", 0, 64).unwrap();
    assert_eq!(data, b"hello nested");
}

#[test]
fn test_nested_list_directory() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_file("a/one.txt").unwrap();
    fs.create_file("a/two.txt").unwrap();

    let entries = fs.list_directory("a").unwrap();
    assert_eq!(entries.len(), 2);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"one.txt"));
    assert!(names.contains(&"two.txt"));
}

#[test]
fn test_deeply_nested_directories() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("a/b").unwrap();
    fs.create_directory("a/b/c").unwrap();
    fs.create_file("a/b/c/deep.txt").unwrap();
    fs.write_file("a/b/c/deep.txt", 0, b"deep data").unwrap();

    let data = fs.read_file("a/b/c/deep.txt", 0, 64).unwrap();
    assert_eq!(data, b"deep data");

    let entries = fs.list_directory("a/b/c").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "deep.txt");
}

#[test]
fn test_nested_remove_file() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("dir").unwrap();
    fs.create_file("dir/file.txt").unwrap();

    let entries = fs.list_directory("dir").unwrap();
    assert_eq!(entries.len(), 1);

    fs.remove_file("dir/file.txt").unwrap();
    let entries = fs.list_directory("dir").unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_nested_remove_empty_directory() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("parent").unwrap();
    fs.create_directory("parent/child").unwrap();

    fs.remove_file("parent/child").unwrap();
    let entries = fs.list_directory("parent").unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_nested_remove_nonempty_directory_fails() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("parent").unwrap();
    fs.create_file("parent/file.txt").unwrap();

    assert!(fs.remove_file("parent").is_err());
}

#[test]
fn test_nested_rename() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("dir").unwrap();
    fs.create_file("dir/old.txt").unwrap();
    fs.write_file("dir/old.txt", 0, b"content").unwrap();

    fs.rename("dir/old.txt", "dir/new.txt").unwrap();

    assert!(fs.read_file("dir/old.txt", 0, 64).is_err());
    let data = fs.read_file("dir/new.txt", 0, 64).unwrap();
    assert_eq!(data, b"content");
}

#[test]
fn test_cross_dir_rename() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("b").unwrap();
    fs.create_file("a/file.txt").unwrap();
    fs.write_file("a/file.txt", 0, b"hello cross").unwrap();
    fs.sync().unwrap();

    fs.rename("a/file.txt", "b/file.txt").unwrap();

    // Source gone, destination readable with same content.
    assert!(fs.read_file("a/file.txt", 0, 1).is_err());
    let data = fs.read_file("b/file.txt", 0, 20).unwrap();
    assert_eq!(data, b"hello cross");
}

#[test]
fn test_create_file_missing_parent_fails() {
    let (mut fs, _, _) = make_fs();
    assert!(fs.create_file("nonexistent/file.txt").is_err());
}

#[test]
fn test_list_root_via_empty_and_slash() {
    let (mut fs, _, _) = make_fs();
    fs.create_file("root.txt").unwrap();

    let e1 = fs.list_directory("").unwrap();
    let e2 = fs.list_directory("/").unwrap();
    assert_eq!(e1.len(), 1);
    assert_eq!(e2.len(), 1);
    assert_eq!(e1[0].name, "root.txt");
    assert_eq!(e2[0].name, "root.txt");
}

#[test]
fn test_nested_cow_preserves_sibling() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("dir").unwrap();
    fs.create_file("dir/a.txt").unwrap();
    fs.create_file("dir/b.txt").unwrap();
    fs.write_file("dir/a.txt", 0, b"aaa").unwrap();
    fs.write_file("dir/b.txt", 0, b"bbb").unwrap();

    // Modify one file; the sibling should be unchanged.
    fs.write_file("dir/a.txt", 0, b"AAA").unwrap();
    let a = fs.read_file("dir/a.txt", 0, 64).unwrap();
    let b = fs.read_file("dir/b.txt", 0, 64).unwrap();
    assert_eq!(a, b"AAA");
    assert_eq!(b, b"bbb");
}

// ── Write performance / correctness tests ──

/// Simulate `dd bs=1M count=N`: sequential 1 MiB appends.
/// Verify the data roundtrips correctly and that per-write block
/// allocation is bounded (not O(file_size)).
#[test]
fn test_sequential_append_does_not_degrade() {
    // Use a large store so we don't run out of blocks.
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 8192));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();

    fs.create_file("big.bin").unwrap();

    let write_size: usize = 256 * 1024; // 256 KiB per write
    let num_writes = 20;
    let pattern = vec![0xABu8; write_size];

    let mut alloc_counts: Vec<u64> = Vec::new();
    for i in 0..num_writes {
        let before = store.stats_writes();
        fs.write_file("big.bin", (i * write_size) as u64, &pattern)
            .unwrap();
        let after = store.stats_writes();
        alloc_counts.push(after - before);
    }

    // Verify data integrity: spot-check first and last writes.
    let first = fs.read_file("big.bin", 0, write_size).unwrap();
    assert_eq!(first.len(), write_size);
    assert!(first.iter().all(|&b| b == 0xAB));

    let last_offset = ((num_writes - 1) * write_size) as u64;
    let last = fs.read_file("big.bin", last_offset, write_size).unwrap();
    assert_eq!(last.len(), write_size);
    assert!(last.iter().all(|&b| b == 0xAB));

    // The key invariant: later writes should NOT do more block writes
    // than early ones.  Allow 2x tolerance for metadata overhead.
    let first_cost = alloc_counts[0];
    let last_cost = *alloc_counts.last().unwrap();
    assert!(
        last_cost <= first_cost * 2,
        "last write cost ({last_cost}) is more than 2× first ({first_cost}); \
         write is still O(n): {:?}",
        alloc_counts
    );
}

/// Overwrite a range in the middle of a file — only the affected chunks
/// should be rewritten, not the entire file.
#[test]
fn test_mid_file_overwrite_is_bounded() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 4096));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();

    fs.create_file("data.bin").unwrap();

    // Write 1 MiB of 0xFF.
    let mb = vec![0xFFu8; 1024 * 1024];
    fs.write_file("data.bin", 0, &mb).unwrap();

    // Overwrite 4 KiB in the middle.
    let patch = vec![0x42u8; 4096];
    let before = store.stats_writes();
    fs.write_file("data.bin", 512 * 1024, &patch).unwrap();
    let after = store.stats_writes();

    // Should only rewrite a few data chunks + metadata, not all ~16 data chunks.
    // Old approach would be 16+ data rewrites + metadata ≈ 22+.
    let writes = after - before;
    assert!(
        writes < 16,
        "mid-file 4 KiB overwrite caused {writes} block writes; expected < 16"
    );

    // Verify the patch landed correctly.
    let read_back = fs.read_file("data.bin", 512 * 1024, 4096).unwrap();
    assert_eq!(read_back, patch);

    // Verify surrounding data is unchanged.
    let before_patch = fs.read_file("data.bin", 512 * 1024 - 16, 16).unwrap();
    assert!(before_patch.iter().all(|&b| b == 0xFF));
    let after_patch = fs.read_file("data.bin", 512 * 1024 + 4096, 16).unwrap();
    assert!(after_patch.iter().all(|&b| b == 0xFF));
}

/// Write at a high offset creating a gap — the gap should be zero-filled
/// and surrounding data correct.
#[test]
fn test_write_with_gap_fills_zeros() {
    let (mut fs, _, _) = make_fs();
    fs.create_file("sparse.bin").unwrap();
    fs.write_file("sparse.bin", 0, b"HEAD").unwrap();

    // Write far past the current end.
    fs.write_file("sparse.bin", 200_000, b"TAIL").unwrap();

    let head = fs.read_file("sparse.bin", 0, 4).unwrap();
    assert_eq!(head, b"HEAD");

    // Gap should be zeros.
    let gap = fs.read_file("sparse.bin", 4, 1000).unwrap();
    assert!(gap.iter().all(|&b| b == 0), "gap should be zero-filled");

    let tail = fs.read_file("sparse.bin", 200_000, 4).unwrap();
    assert_eq!(tail, b"TAIL");
}

// ── Garbage collection tests ──

#[test]
fn test_gc_overwrite_reclaims_blocks() {
    let (mut fs, _store, _crypto) = make_fs();
    fs.create_file("a.txt").unwrap();
    fs.write_file("a.txt", 0, &[0xAA; 80_000]).unwrap();
    fs.sync().unwrap();

    let free_before = fs.free_block_count();

    // Overwrite with same size data — old data chunks + metadata should be freed.
    fs.write_file("a.txt", 0, &[0xBB; 80_000]).unwrap();
    fs.sync().unwrap();

    let free_after = fs.free_block_count();
    // After GC, free count should be similar (not monotonically decreasing).
    // The overwrite allocates new blocks but frees old ones, so free count
    // should stay roughly the same (within a small delta for metadata churn).
    let delta = (free_before as i64 - free_after as i64).unsigned_abs();
    assert!(
        delta <= 2,
        "free blocks should be ~stable after overwrite, delta={delta}"
    );
}

#[test]
fn test_gc_delete_reclaims_all_blocks() {
    let (mut fs, _store, _crypto) = make_fs();
    let free_initial = fs.free_block_count();

    fs.create_file("big.bin").unwrap();
    fs.write_file("big.bin", 0, &[0xCC; 200_000]).unwrap();
    fs.sync().unwrap();
    let free_after_write = fs.free_block_count();

    // File consumes several blocks — free count should have dropped.
    assert!(
        free_after_write < free_initial,
        "creating a file should consume blocks"
    );

    fs.remove_file("big.bin").unwrap();
    let free_after_delete = fs.free_block_count();

    // Deleting should reclaim most blocks (inode, extent map, data chunks).
    // It won't be exactly equal to initial because the superblock/root inode
    // metadata is still allocated, but should be very close.
    let reclaimed = free_after_delete as i64 - free_after_write as i64;
    assert!(
        reclaimed > 0,
        "deleting a file should reclaim blocks, but got delta={reclaimed}"
    );
    let gap = free_initial as i64 - free_after_delete as i64;
    assert!(
        gap <= 2,
        "after delete, free count should be close to initial, gap={gap}"
    );
}

#[test]
fn test_gc_create_delete_cycle_does_not_exhaust() {
    let (mut fs, _store, _crypto) = make_fs();
    let free_initial = fs.free_block_count();

    for i in 0..50 {
        let name = format!("file_{i}.dat");
        fs.create_file(&name).unwrap();
        fs.write_file(&name, 0, &[0xDD; 70_000]).unwrap();
        fs.sync().unwrap();
        fs.remove_file(&name).unwrap();
    }

    let free_final = fs.free_block_count();
    let leak = free_initial as i64 - free_final as i64;
    assert!(
        leak <= 2,
        "50 create/delete cycles should not leak blocks, leaked={leak}"
    );
}

#[test]
fn test_gc_nested_dir_delete_reclaims() {
    let (mut fs, _store, _crypto) = make_fs();
    let free_initial = fs.free_block_count();

    fs.create_directory("/a").unwrap();
    fs.create_directory("/a/b").unwrap();
    fs.create_file("/a/b/f.txt").unwrap();
    fs.write_file("/a/b/f.txt", 0, &[0xEE; 10_000]).unwrap();
    fs.sync().unwrap();

    // Delete from the inside out.
    fs.remove_file("/a/b/f.txt").unwrap();
    fs.remove_file("/a/b").unwrap();
    fs.remove_file("/a").unwrap();

    let free_final = fs.free_block_count();
    let gap = free_initial as i64 - free_final as i64;
    assert!(
        gap <= 2,
        "deleting nested dirs should reclaim blocks, gap={gap}"
    );
}

// ── Cross-directory rename tests ──

#[test]
fn test_cross_dir_rename_to_root() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("sub").unwrap();
    fs.create_file("sub/deep.txt").unwrap();
    fs.write_file("sub/deep.txt", 0, b"moved up").unwrap();
    fs.sync().unwrap();

    fs.rename("sub/deep.txt", "shallow.txt").unwrap();

    assert!(fs.read_file("sub/deep.txt", 0, 1).is_err());
    assert_eq!(fs.read_file("shallow.txt", 0, 20).unwrap(), b"moved up");
}

#[test]
fn test_cross_dir_rename_from_root() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("sub").unwrap();
    fs.create_file("top.txt").unwrap();
    fs.write_file("top.txt", 0, b"moved down").unwrap();
    fs.sync().unwrap();

    fs.rename("top.txt", "sub/top.txt").unwrap();

    assert!(fs.read_file("top.txt", 0, 1).is_err());
    assert_eq!(fs.read_file("sub/top.txt", 0, 20).unwrap(), b"moved down");
}

#[test]
fn test_cross_dir_rename_deep_to_deep() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("a/b").unwrap();
    fs.create_directory("x").unwrap();
    fs.create_directory("x/y").unwrap();
    fs.create_file("a/b/data.bin").unwrap();
    fs.write_file("a/b/data.bin", 0, &[0xAA; 1000]).unwrap();
    fs.sync().unwrap();

    fs.rename("a/b/data.bin", "x/y/data.bin").unwrap();

    assert!(fs.read_file("a/b/data.bin", 0, 1).is_err());
    let data = fs.read_file("x/y/data.bin", 0, 1000).unwrap();
    assert!(data.iter().all(|&b| b == 0xAA));
}

#[test]
fn test_cross_dir_rename_with_shared_ancestor() {
    let (mut fs, _, _) = make_fs();
    // Both paths share ancestor "root/shared".
    fs.create_directory("shared").unwrap();
    fs.create_directory("shared/src").unwrap();
    fs.create_directory("shared/dst").unwrap();
    fs.create_file("shared/src/item.txt").unwrap();
    fs.write_file("shared/src/item.txt", 0, b"shared ancestor")
        .unwrap();
    fs.sync().unwrap();

    fs.rename("shared/src/item.txt", "shared/dst/item.txt")
        .unwrap();

    assert!(fs.read_file("shared/src/item.txt", 0, 1).is_err());
    assert_eq!(
        fs.read_file("shared/dst/item.txt", 0, 30).unwrap(),
        b"shared ancestor"
    );
}

#[test]
fn test_cross_dir_move_directory() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("b").unwrap();
    fs.create_directory("a/subdir").unwrap();
    fs.create_file("a/subdir/child.txt").unwrap();
    fs.write_file("a/subdir/child.txt", 0, b"child data")
        .unwrap();
    fs.sync().unwrap();

    // Move entire directory across parents.
    fs.rename("a/subdir", "b/subdir").unwrap();

    // Old path gone.
    assert!(fs.list_directory("a/subdir").is_err());
    // New path accessible.
    let entries = fs.list_directory("b/subdir").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "child.txt");
    assert_eq!(
        fs.read_file("b/subdir/child.txt", 0, 20).unwrap(),
        b"child data"
    );
}

#[test]
fn test_cross_dir_rename_with_new_name() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("src").unwrap();
    fs.create_directory("dst").unwrap();
    fs.create_file("src/old_name.txt").unwrap();
    fs.write_file("src/old_name.txt", 0, b"renamed").unwrap();
    fs.sync().unwrap();

    // Move AND rename in one operation.
    fs.rename("src/old_name.txt", "dst/new_name.txt").unwrap();

    assert!(fs.read_file("src/old_name.txt", 0, 1).is_err());
    assert_eq!(fs.read_file("dst/new_name.txt", 0, 20).unwrap(), b"renamed");
}

#[test]
fn test_cross_dir_rename_dest_name_collision() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("b").unwrap();
    fs.create_file("a/f.txt").unwrap();
    fs.create_file("b/f.txt").unwrap();

    // Destination name already exists — must fail.
    assert!(fs.rename("a/f.txt", "b/f.txt").is_err());
}

#[test]
fn test_cross_dir_rename_into_self_rejected() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("a").unwrap();
    fs.create_directory("a/b").unwrap();

    // Moving /a into /a/b/a would create a cycle.
    assert!(fs.rename("a", "a/b/a").is_err());
}

#[test]
fn test_cross_dir_rename_preserves_siblings() {
    let (mut fs, _, _) = make_fs();
    fs.create_directory("src").unwrap();
    fs.create_directory("dst").unwrap();
    fs.create_file("src/moving.txt").unwrap();
    fs.create_file("src/staying.txt").unwrap();
    fs.create_file("dst/existing.txt").unwrap();

    fs.rename("src/moving.txt", "dst/moving.txt").unwrap();

    // Source dir still has the other file.
    let src_entries = fs.list_directory("src").unwrap();
    assert_eq!(src_entries.len(), 1);
    assert_eq!(src_entries[0].name, "staying.txt");

    // Dest dir has both.
    let dst_entries = fs.list_directory("dst").unwrap();
    assert_eq!(dst_entries.len(), 2);
    let names: Vec<&str> = dst_entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"existing.txt"));
    assert!(names.contains(&"moving.txt"));
}

// ── Scrub free blocks tests ──

#[test]
fn test_scrub_free_blocks_writes_all_free() {
    let (mut fs, store, _) = make_fs();

    // After init there should be many free blocks.
    let free_before = fs.free_block_count();
    assert!(free_before > 10, "should have many free blocks");

    // Free blocks should initially be zeroes (MemoryBlockStore default).
    let first_free_id = {
        // Block 3 is the first allocatable block (FIRST_DATA_BLOCK).
        // Some will be allocated by init_filesystem. Find one that's free.
        let mut id = None;
        for candidate in 3..store.total_blocks() {
            if store.read_block(candidate).unwrap().iter().all(|&b| b == 0) {
                id = Some(candidate);
                break;
            }
        }
        id.expect("should find a zero block")
    };

    fs.scrub_free_blocks().unwrap();

    // Free block should now contain random (non-zero) data.
    let data = store.read_block(first_free_id).unwrap();
    let nonzero = data.iter().filter(|&&b| b != 0).count();
    // With 65536 random bytes, essentially all will be nonzero.
    assert!(
        nonzero > 100,
        "scrubbed block should be non-zero random data, got {nonzero} nonzero bytes"
    );

    // Free count should be unchanged — no blocks were allocated.
    assert_eq!(fs.free_block_count(), free_before);
}

#[test]
fn test_scrub_preserves_file_data() {
    let (mut fs, _, _) = make_fs();
    fs.create_file("keep.txt").unwrap();
    fs.write_file("keep.txt", 0, b"important data").unwrap();
    fs.sync().unwrap();

    fs.scrub_free_blocks().unwrap();

    // File data must be intact.
    let data = fs.read_file("keep.txt", 0, 100).unwrap();
    assert_eq!(data, b"important data");
}

#[test]
fn test_scrub_on_full_store_is_noop() {
    // Small store: 8 blocks total — just enough for init_filesystem.
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 8));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();

    // Fill remaining free blocks.
    while fs
        .create_file(&format!("f{}", rand::random::<u32>()))
        .is_ok()
    {}

    // Scrub should succeed even with zero free blocks.
    fs.scrub_free_blocks().unwrap();
}
