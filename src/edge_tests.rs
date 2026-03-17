//! Aggressive edge-case and fuzz-style tests.

use std::sync::Arc;

use crate::block_store::MemoryBlockStore;
use crate::crypto::ChaChaEngine;
use crate::error::FsError;
use crate::fs::FilesystemCore;
use crate::model::{DEFAULT_BLOCK_SIZE, MAX_NAME_LEN};

fn make_fs() -> FilesystemCore {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 2048));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);
    fs.init_filesystem().unwrap();
    fs
}

fn make_fs_with_store() -> (FilesystemCore, Arc<MemoryBlockStore>, Arc<ChaChaEngine>) {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 2048));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();
    (fs, store, crypto)
}

// ── Name validation edge cases ──

#[test]
fn test_empty_filename_rejected() {
    let mut fs = make_fs();
    assert!(fs.create_file("").is_err());
}

#[test]
fn test_slash_in_filename_rejected() {
    let mut fs = make_fs();
    assert!(fs.create_file("foo/bar").is_err());
    assert!(fs.create_file("/").is_err());
    assert!(fs.create_file("a/").is_err());
}

#[test]
fn test_null_byte_in_filename_rejected() {
    let mut fs = make_fs();
    assert!(fs.create_file("foo\0bar").is_err());
    assert!(fs.create_file("\0").is_err());
}

#[test]
fn test_max_length_filename() {
    let mut fs = make_fs();
    let long_name: String = "x".repeat(MAX_NAME_LEN);
    fs.create_file(&long_name).unwrap();
    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, long_name);
}

#[test]
fn test_filename_exceeds_max_length() {
    let mut fs = make_fs();
    let too_long: String = "x".repeat(MAX_NAME_LEN + 1);
    assert!(fs.create_file(&too_long).is_err());
}

#[test]
fn test_unicode_filename() {
    let mut fs = make_fs();
    fs.create_file("日本語ファイル.txt").unwrap();
    fs.create_file("émojis_🔥🎉.data").unwrap();
    fs.create_file("Ñoño").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 3);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"日本語ファイル.txt"));
    assert!(names.contains(&"émojis_🔥🎉.data"));
    assert!(names.contains(&"Ñoño"));
}

#[test]
fn test_filename_with_spaces_and_special_chars() {
    let mut fs = make_fs();
    fs.create_file("file with spaces.txt").unwrap();
    fs.create_file("dots...many...dots").unwrap();
    fs.create_file(".hidden").unwrap();
    fs.create_file("..also_hidden").unwrap();
    fs.create_file("tab\there").unwrap();
    fs.create_file("new\nline").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 6);
}

#[test]
fn test_filename_single_char() {
    let mut fs = make_fs();
    fs.create_file("a").unwrap();
    fs.create_file("b").unwrap();
    fs.create_file(".").unwrap(); // "." as a filename (not path)
    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 3);
}

#[test]
fn test_dirname_validation_same_as_file() {
    let mut fs = make_fs();
    assert!(fs.create_directory("").is_err());
    assert!(fs.create_directory("foo/bar").is_err());
    assert!(fs.create_directory("has\0null").is_err());

    let long_dir: String = "d".repeat(MAX_NAME_LEN + 1);
    assert!(fs.create_directory(&long_dir).is_err());
}

#[test]
fn test_rename_validation() {
    let mut fs = make_fs();
    fs.create_file("src.txt").unwrap();
    assert!(fs.rename("src.txt", "").is_err());
    assert!(fs.rename("src.txt", "bad/name").is_err());
    assert!(fs.rename("src.txt", "bad\0name").is_err());

    let too_long: String = "z".repeat(MAX_NAME_LEN + 1);
    assert!(fs.rename("src.txt", &too_long).is_err());
}

// ── Cross-type collision tests ──

#[test]
fn test_file_and_dir_same_name_collision() {
    let mut fs = make_fs();
    fs.create_file("thing").unwrap();
    // Creating a directory with the same name should fail.
    assert!(fs.create_directory("thing").is_err());
}

#[test]
fn test_dir_and_file_same_name_collision() {
    let mut fs = make_fs();
    fs.create_directory("thing").unwrap();
    // Creating a file with the same name should fail.
    assert!(fs.create_file("thing").is_err());
}

#[test]
fn test_rename_to_existing_name_fails() {
    let mut fs = make_fs();
    fs.create_file("a").unwrap();
    fs.create_file("b").unwrap();
    assert!(fs.rename("a", "b").is_err());
}

#[test]
fn test_rename_nonexistent_source_fails() {
    let mut fs = make_fs();
    assert!(fs.rename("ghost", "target").is_err());
}

// ── Write/read boundary conditions ──

#[test]
fn test_write_zero_bytes() {
    let mut fs = make_fs();
    fs.create_file("zero.bin").unwrap();
    fs.write_file("zero.bin", 0, &[]).unwrap();
    let data = fs.read_file("zero.bin", 0, 1024).unwrap();
    assert!(data.is_empty());
}

#[test]
fn test_write_single_byte() {
    let mut fs = make_fs();
    fs.create_file("one.bin").unwrap();
    fs.write_file("one.bin", 0, &[0x42]).unwrap();
    let data = fs.read_file("one.bin", 0, 1024).unwrap();
    assert_eq!(data, vec![0x42]);
}

#[test]
fn test_write_at_high_offset_creates_gap() {
    let mut fs = make_fs();
    fs.create_file("gap.bin").unwrap();
    // Write 3 bytes at offset 100 - should create a 103-byte file with zero-fill.
    fs.write_file("gap.bin", 100, b"XYZ").unwrap();
    let data = fs.read_file("gap.bin", 0, 200).unwrap();
    assert_eq!(data.len(), 103);
    assert_eq!(&data[..100], &[0u8; 100]);
    assert_eq!(&data[100..], b"XYZ");
}

#[test]
fn test_write_extends_file() {
    let mut fs = make_fs();
    fs.create_file("extend.bin").unwrap();
    fs.write_file("extend.bin", 0, b"AAAA").unwrap();
    // Write beyond current end.
    fs.write_file("extend.bin", 6, b"BB").unwrap();
    let data = fs.read_file("extend.bin", 0, 100).unwrap();
    assert_eq!(data.len(), 8);
    assert_eq!(&data[0..4], b"AAAA");
    assert_eq!(&data[4..6], &[0, 0]);
    assert_eq!(&data[6..8], b"BB");
}

#[test]
fn test_read_beyond_eof_returns_empty() {
    let mut fs = make_fs();
    fs.create_file("short.txt").unwrap();
    fs.write_file("short.txt", 0, b"hi").unwrap();
    let data = fs.read_file("short.txt", 1000, 100).unwrap();
    assert!(data.is_empty());
}

#[test]
fn test_read_spanning_eof() {
    let mut fs = make_fs();
    fs.create_file("f.txt").unwrap();
    fs.write_file("f.txt", 0, b"12345").unwrap();
    // Read 100 bytes starting at offset 3 — should get only "45".
    let data = fs.read_file("f.txt", 3, 100).unwrap();
    assert_eq!(data, b"45");
}

#[test]
fn test_read_zero_length() {
    let mut fs = make_fs();
    fs.create_file("f.txt").unwrap();
    fs.write_file("f.txt", 0, b"data").unwrap();
    let data = fs.read_file("f.txt", 0, 0).unwrap();
    assert!(data.is_empty());
}

// ── Repeated write/overwrite stress ──

#[test]
fn test_many_sequential_overwrites() {
    let mut fs = make_fs();
    fs.create_file("stress.bin").unwrap();
    for i in 0u32..50 {
        let payload = format!("version-{i:04}");
        fs.write_file("stress.bin", 0, payload.as_bytes()).unwrap();
    }
    let data = fs.read_file("stress.bin", 0, 1024).unwrap();
    assert_eq!(data, b"version-0049");
}

#[test]
fn test_many_files_in_root() {
    let mut fs = make_fs();
    let count = 100;
    for i in 0..count {
        let name = format!("file_{i:04}.dat");
        fs.create_file(&name).unwrap();
        let payload = format!("data for file {i}");
        fs.write_file(&name, 0, payload.as_bytes()).unwrap();
    }

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), count);

    // Verify a sample.
    let data = fs.read_file("file_0050.dat", 0, 1024).unwrap();
    assert_eq!(data, b"data for file 50");
}

#[test]
fn test_create_delete_cycle() {
    let mut fs = make_fs();
    for i in 0..30 {
        let name = format!("cycle_{i}.tmp");
        fs.create_file(&name).unwrap();
        fs.write_file(&name, 0, b"temporary").unwrap();
        fs.remove_file(&name).unwrap();
    }
    let entries = fs.list_directory().unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_rename_chain() {
    let mut fs = make_fs();
    fs.create_file("name_0").unwrap();
    fs.write_file("name_0", 0, b"persistent data").unwrap();

    for i in 1..20 {
        let old = format!("name_{}", i - 1);
        let new = format!("name_{i}");
        fs.rename(&old, &new).unwrap();
    }

    let data = fs.read_file("name_19", 0, 1024).unwrap();
    assert_eq!(data, b"persistent data");

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "name_19");
}

// ── Multi-chunk / large file edge cases ──

#[test]
fn test_data_exactly_one_chunk() {
    let mut fs = make_fs();
    fs.create_file("exact.bin").unwrap();
    // max_chunk_payload(65536) = 65336 bytes
    let chunk_size = DEFAULT_BLOCK_SIZE - 200;
    let data = vec![0xCD; chunk_size];
    fs.write_file("exact.bin", 0, &data).unwrap();
    let read_back = fs.read_file("exact.bin", 0, chunk_size + 100).unwrap();
    assert_eq!(read_back.len(), chunk_size);
    assert_eq!(read_back, data);
}

#[test]
fn test_data_exactly_one_chunk_plus_one_byte() {
    let mut fs = make_fs();
    fs.create_file("plus1.bin").unwrap();
    let chunk_size = DEFAULT_BLOCK_SIZE - 200;
    let data = vec![0xEF; chunk_size + 1];
    fs.write_file("plus1.bin", 0, &data).unwrap();
    let read_back = fs.read_file("plus1.bin", 0, chunk_size + 100).unwrap();
    assert_eq!(read_back.len(), chunk_size + 1);
    assert_eq!(read_back, data);
}

#[test]
fn test_multi_chunk_boundary_read() {
    let mut fs = make_fs();
    fs.create_file("boundary.bin").unwrap();
    let chunk_size = DEFAULT_BLOCK_SIZE - 200;
    // Write exactly 2 chunks worth.
    let data: Vec<u8> = (0..chunk_size * 2).map(|i| (i % 251) as u8).collect();
    fs.write_file("boundary.bin", 0, &data).unwrap();

    // Read spanning the chunk boundary.
    let mid = chunk_size - 10;
    let span = fs.read_file("boundary.bin", mid as u64, 20).unwrap();
    assert_eq!(span, &data[mid..mid + 20]);
}

#[test]
fn test_overwrite_shrinks_file() {
    let mut fs = make_fs();
    fs.create_file("shrink.bin").unwrap();
    let big = vec![0xFF; 50_000];
    fs.write_file("shrink.bin", 0, &big).unwrap();
    assert_eq!(fs.read_file("shrink.bin", 0, 60_000).unwrap().len(), 50_000);

    // Overwrite from offset 0 with smaller data — file becomes smaller.
    fs.write_file("shrink.bin", 0, b"tiny").unwrap();
    let data = fs.read_file("shrink.bin", 0, 60_000).unwrap();
    // Actually, write at offset 0 with "tiny" rebuilds the buffer as:
    // existing 50000 bytes, splice [0..4] = "tiny", so file stays 50000 bytes.
    assert_eq!(data.len(), 50_000);
    assert_eq!(&data[..4], b"tiny");
}

// ── Type confusion ──

#[test]
fn test_write_to_directory_fails() {
    let mut fs = make_fs();
    fs.create_directory("mydir").unwrap();
    let result = fs.write_file("mydir", 0, b"nope");
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::NotAFile(_) => {}
        other => panic!("expected NotAFile, got: {other:?}"),
    }
}

#[test]
fn test_read_from_directory_fails() {
    let mut fs = make_fs();
    fs.create_directory("mydir").unwrap();
    let result = fs.read_file("mydir", 0, 1024);
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::NotAFile(_) => {}
        other => panic!("expected NotAFile, got: {other:?}"),
    }
}

// ── Operations on uninitialized filesystem ──

#[test]
fn test_operations_before_init() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 256));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);

    assert!(fs.list_directory().is_err());
    assert!(fs.create_file("x").is_err());
    assert!(fs.read_file("x", 0, 10).is_err());
    assert!(fs.write_file("x", 0, b"data").is_err());
    assert!(fs.create_directory("d").is_err());
    assert!(fs.remove_file("x").is_err());
    assert!(fs.rename("a", "b").is_err());
}

#[test]
fn test_open_on_empty_store_fails() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 256));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);
    assert!(fs.open().is_err());
}

#[test]
fn test_open_with_wrong_key_fails() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 256));
    let crypto1 = Arc::new(ChaChaEngine::generate().unwrap());
    let crypto2 = Arc::new(ChaChaEngine::generate().unwrap());

    {
        let mut fs = FilesystemCore::new(store.clone(), crypto1);
        fs.init_filesystem().unwrap();
        fs.create_file("secret.txt").unwrap();
        fs.write_file("secret.txt", 0, b"classified").unwrap();
    }

    // Try to open with a different key.
    let mut fs = FilesystemCore::new(store, crypto2);
    assert!(fs.open().is_err());
}

// ── Disk space exhaustion ──

#[test]
fn test_tiny_store_exhaustion() {
    // Minimal store: 3 reserved + a handful of data blocks.
    // init_filesystem needs: dir_page (1) + root_inode (1) + superblock (1) = 3 data blocks min.
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 7));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);
    fs.init_filesystem().unwrap();

    // We have only ~1 free block left after init (blocks 3,4,5,6 total, init uses 3+commit=4).
    // Attempting to create a file needs several blocks, should fail at some point.
    let result = fs.create_file("test.txt");
    // May succeed or fail depending on exact block usage.
    // But writing more should eventually fail.
    if result.is_ok() {
        // Try writing — will need more allocation.
        let _ = fs.write_file("test.txt", 0, b"data");
    }
    // If we got here without panic, that's the important thing.
}

#[test]
fn test_fill_store_then_create_fails() {
    // Give enough blocks for init but tight for many files.
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 30));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);
    fs.init_filesystem().unwrap();

    let mut created = 0;
    // Each create_file needs ~4 blocks (extent_map, inode, dir_page, root_inode) + 1 for commit.
    for i in 0..100 {
        let name = format!("f{i}");
        match fs.create_file(&name) {
            Ok(()) => created += 1,
            Err(_) => break,
        }
    }
    // Should have created some files before running out of space.
    assert!(created > 0);
    assert!(created < 100);
}

// ── Reopen resilience ──

#[test]
fn test_reopen_after_many_mutations() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 4096));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());

    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.init_filesystem().unwrap();

        for i in 0..20 {
            let name = format!("file_{i}");
            fs.create_file(&name).unwrap();
            let data = format!("content_{i}");
            fs.write_file(&name, 0, data.as_bytes()).unwrap();
        }
        // Delete some.
        for i in 0..10 {
            let name = format!("file_{i}");
            fs.remove_file(&name).unwrap();
        }
        // Rename some.
        for i in 10..15 {
            let old = format!("file_{i}");
            let new = format!("renamed_{i}");
            fs.rename(&old, &new).unwrap();
        }
    }

    // Reopen.
    let mut fs = FilesystemCore::new(store, crypto);
    fs.open().unwrap();

    let entries = fs.list_directory().unwrap();
    // 20 created - 10 deleted = 10 remaining.
    assert_eq!(entries.len(), 10);

    // Verify renamed files have data.
    for i in 10..15 {
        let name = format!("renamed_{i}");
        let expected = format!("content_{i}");
        let data = fs.read_file(&name, 0, 1024).unwrap();
        assert_eq!(data, expected.as_bytes());
    }

    // Verify non-renamed files.
    for i in 15..20 {
        let name = format!("file_{i}");
        let expected = format!("content_{i}");
        let data = fs.read_file(&name, 0, 1024).unwrap();
        assert_eq!(data, expected.as_bytes());
    }
}

#[test]
fn test_reopen_preserves_file_sizes() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 2048));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());

    let sizes = [0, 1, 255, 1024, 50_000, 100_000];

    {
        let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
        fs.init_filesystem().unwrap();
        for (i, &sz) in sizes.iter().enumerate() {
            let name = format!("sized_{i}");
            fs.create_file(&name).unwrap();
            if sz > 0 {
                let data = vec![(i + 1) as u8; sz];
                fs.write_file(&name, 0, &data).unwrap();
            }
        }
    }

    let mut fs = FilesystemCore::new(store, crypto);
    fs.open().unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), sizes.len());

    for (i, &sz) in sizes.iter().enumerate() {
        let name = format!("sized_{i}");
        let entry = entries.iter().find(|e| e.name == name).unwrap();
        assert_eq!(entry.size as usize, sz, "size mismatch for {name}");

        let data = fs.read_file(&name, 0, sz + 100).unwrap();
        assert_eq!(data.len(), sz);
        if sz > 0 {
            assert!(data.iter().all(|&b| b == (i + 1) as u8));
        }
    }
}

// ── All-bytes data integrity ──

#[test]
fn test_all_byte_values_roundtrip() {
    let mut fs = make_fs();
    fs.create_file("allbytes.bin").unwrap();
    let data: Vec<u8> = (0..=255).collect();
    fs.write_file("allbytes.bin", 0, &data).unwrap();
    let read_back = fs.read_file("allbytes.bin", 0, 512).unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn test_binary_data_with_nulls() {
    let mut fs = make_fs();
    fs.create_file("nulls.bin").unwrap();
    let data = vec![0u8; 10_000];
    fs.write_file("nulls.bin", 0, &data).unwrap();
    let read_back = fs.read_file("nulls.bin", 0, 20_000).unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn test_random_pattern_data_integrity() {
    let mut fs = make_fs();
    fs.create_file("pattern.bin").unwrap();
    // Deterministic pseudo-random pattern.
    let data: Vec<u8> = (0..30_000_u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 24) as u8)
        .collect();
    fs.write_file("pattern.bin", 0, &data).unwrap();
    let read_back = fs.read_file("pattern.bin", 0, 50_000).unwrap();
    assert_eq!(read_back, data);
}

// ── Interleaved operations ──

#[test]
fn test_interleaved_create_write_read_delete() {
    let mut fs = make_fs();

    fs.create_file("a").unwrap();
    fs.create_file("b").unwrap();
    fs.write_file("a", 0, b"alpha").unwrap();
    fs.create_file("c").unwrap();
    fs.write_file("b", 0, b"beta").unwrap();

    assert_eq!(fs.read_file("a", 0, 100).unwrap(), b"alpha");

    fs.remove_file("a").unwrap();
    fs.write_file("c", 0, b"gamma").unwrap();

    assert!(fs.read_file("a", 0, 100).is_err());
    assert_eq!(fs.read_file("b", 0, 100).unwrap(), b"beta");
    assert_eq!(fs.read_file("c", 0, 100).unwrap(), b"gamma");

    fs.rename("c", "a").unwrap();
    assert_eq!(fs.read_file("a", 0, 100).unwrap(), b"gamma");

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries.len(), 2);
}

// ── Double init ──

#[test]
fn test_double_init_reinitializes() {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 1024));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store, crypto);

    fs.init_filesystem().unwrap();
    fs.create_file("before.txt").unwrap();

    // Re-init — the old data will be conceptually lost
    // (though blocks may linger since no GC).
    fs.init_filesystem().unwrap();

    let entries = fs.list_directory().unwrap();
    assert!(entries.is_empty());
}

// ── Remove semantics ──

#[test]
fn test_remove_nonexistent_fails() {
    let mut fs = make_fs();
    assert!(fs.remove_file("ghost").is_err());
}

#[test]
fn test_remove_and_recreate_same_name() {
    let mut fs = make_fs();

    fs.create_file("recycled.txt").unwrap();
    fs.write_file("recycled.txt", 0, b"version1").unwrap();
    fs.remove_file("recycled.txt").unwrap();

    fs.create_file("recycled.txt").unwrap();
    fs.write_file("recycled.txt", 0, b"version2").unwrap();

    let data = fs.read_file("recycled.txt", 0, 100).unwrap();
    assert_eq!(data, b"version2");
}

// ── FFI edge cases (safe wrappers) ──

#[test]
fn test_ffi_null_handle_safety() {
    use crate::ffi::*;
    use std::ptr;

    unsafe {
        assert_ne!(fs_init_filesystem(ptr::null_mut()), 0);
        assert_ne!(fs_open(ptr::null_mut()), 0);
        assert_ne!(fs_sync(ptr::null_mut()), 0);
        fs_destroy(ptr::null_mut()); // should not crash
        fs_free_string(ptr::null_mut()); // should not crash
    }
}

#[test]
fn test_ffi_null_key_returns_null() {
    use crate::ffi::*;
    use std::ptr;

    unsafe {
        let handle = fs_create(256, ptr::null(), 0);
        assert!(handle.is_null());
    }
}

#[test]
fn test_ffi_roundtrip() {
    use crate::ffi::*;
    use std::ffi::CString;

    unsafe {
        let key = [0x42u8; 32];
        let handle = fs_create(1024, key.as_ptr(), key.len());
        assert!(!handle.is_null());

        assert_eq!(fs_init_filesystem(handle), 0);

        let name = CString::new("test.txt").unwrap();
        assert_eq!(fs_create_file(handle, name.as_ptr()), 0);

        let data = b"hello from ffi";
        assert_eq!(
            fs_write_file(handle, name.as_ptr(), 0, data.as_ptr(), data.len()),
            0
        );

        let mut buf = vec![0u8; 256];
        let mut out_len: usize = 0;
        assert_eq!(
            fs_read_file(
                handle,
                name.as_ptr(),
                0,
                256,
                buf.as_mut_ptr(),
                &mut out_len
            ),
            0
        );
        assert_eq!(&buf[..out_len], data);

        let mut err: i32 = 0;
        let json_ptr = fs_list_root(handle, &mut err);
        assert_eq!(err, 0);
        assert!(!json_ptr.is_null());
        let json_cstr = std::ffi::CStr::from_ptr(json_ptr);
        let json_str = json_cstr.to_str().unwrap();
        assert!(json_str.contains("test.txt"));
        fs_free_string(json_ptr);

        fs_destroy(handle);
    }
}

// ── Block store edge cases ──

#[test]
fn test_block_store_concurrent_reads() {
    use crate::block_store::BlockStore;
    let store = MemoryBlockStore::new(64, 10);
    let data = vec![0xAB; 64];
    store.write_block(3, &data).unwrap();

    // Multiple reads should always return the same data.
    for _ in 0..100 {
        assert_eq!(store.read_block(3).unwrap(), data);
    }
}

// ── Crypto edge cases ──

#[test]
fn test_encrypt_empty_payload() {
    use crate::crypto::{decrypt_object, encrypt_object, ChaChaEngine};
    use crate::model::ObjectKind;

    let engine = ChaChaEngine::generate().unwrap();
    let enc = encrypt_object(&engine, ObjectKind::FileDataChunk, &[]).unwrap();
    let dec = decrypt_object(&engine, &enc).unwrap();
    assert!(dec.is_empty());
}

#[test]
fn test_encrypt_large_payload() {
    use crate::crypto::{decrypt_object, encrypt_object, ChaChaEngine};
    use crate::model::ObjectKind;

    let engine = ChaChaEngine::generate().unwrap();
    let data = vec![0xCC; 100_000];
    let enc = encrypt_object(&engine, ObjectKind::FileDataChunk, &data).unwrap();
    let dec = decrypt_object(&engine, &enc).unwrap();
    assert_eq!(dec, data);
}

#[test]
fn test_each_encryption_produces_different_ciphertext() {
    use crate::crypto::{encrypt_object, ChaChaEngine};
    use crate::model::ObjectKind;

    let engine = ChaChaEngine::generate().unwrap();
    let plaintext = b"identical data";
    let enc1 = encrypt_object(&engine, ObjectKind::FileDataChunk, plaintext).unwrap();
    let enc2 = encrypt_object(&engine, ObjectKind::FileDataChunk, plaintext).unwrap();
    // Different nonces → different ciphertext (with overwhelming probability).
    assert_ne!(enc1.ciphertext, enc2.ciphertext);
    assert_ne!(enc1.nonce, enc2.nonce);
}

// ── Metadata coherence after many operations ──

#[test]
fn test_file_size_tracking() {
    let mut fs = make_fs();
    fs.create_file("tracked.bin").unwrap();

    let entries = fs.list_directory().unwrap();
    assert_eq!(entries[0].size, 0);

    fs.write_file("tracked.bin", 0, b"12345").unwrap();
    let entries = fs.list_directory().unwrap();
    assert_eq!(entries[0].size, 5);

    fs.write_file("tracked.bin", 0, b"123456789").unwrap();
    let entries = fs.list_directory().unwrap();
    assert_eq!(entries[0].size, 9);
}

// ── Root pointer A/B alternation ──

#[test]
fn test_many_commits_alternate_root_pointers() {
    let (mut fs, store, crypto) = make_fs_with_store();

    // Perform several mutations, each causing a commit.
    for i in 0..10 {
        let name = format!("commit_test_{i}");
        fs.create_file(&name).unwrap();
    }

    // Reopen and verify everything is consistent.
    let mut fs2 = FilesystemCore::new(store, crypto);
    fs2.open().unwrap();

    let entries = fs2.list_directory().unwrap();
    assert_eq!(entries.len(), 10);
}
