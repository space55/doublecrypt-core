//! Creates a small disk-backed encrypted filesystem image, writes some sample
//! data into it, and prints the absolute path so you can inspect it in a hex
//! editor.
//!
//! Run with:
//!   cargo run --example create_image

use std::sync::Arc;

use doublecrypt_core::block_store::DiskBlockStore;
use doublecrypt_core::crypto::ChaChaEngine;
use doublecrypt_core::fs::FilesystemCore;
use doublecrypt_core::model::DEFAULT_BLOCK_SIZE;

fn main() {
    let path = std::env::current_dir()
        .unwrap()
        .join("sample.dcfs")
        .to_string_lossy()
        .to_string();

    // Remove leftover from a previous run, if any.
    let _ = std::fs::remove_file(&path);

    // 64 blocks × 64 KiB = 4 MiB image.
    let total_blocks: u64 = 64;
    let store = Arc::new(
        DiskBlockStore::create(&path, DEFAULT_BLOCK_SIZE, total_blocks)
            .expect("failed to create image file"),
    );

    let crypto = Arc::new(ChaChaEngine::generate().expect("failed to init crypto"));
    let mut fs = FilesystemCore::new(store, crypto);

    fs.init_filesystem().expect("init_filesystem failed");

    // Create a text file.
    fs.create_file("hello.txt").expect("create_file failed");
    fs.write_file("hello.txt", 0, b"Hello, hex editor!")
        .expect("write_file failed");

    // Create a directory.
    fs.create_directory("notes")
        .expect("create_directory failed");

    // Create a larger binary file so there's more to look at.
    let pattern: Vec<u8> = (0..=255).cycle().take(200_000).collect();
    fs.create_file("pattern.bin").expect("create_file failed");
    fs.write_file("pattern.bin", 0, &pattern)
        .expect("write_file failed");

    fs.sync().expect("sync failed");

    println!("Filesystem image written to:\n  {path}");
    println!(
        "  {} blocks × {} bytes = {} bytes total",
        total_blocks,
        DEFAULT_BLOCK_SIZE,
        total_blocks as usize * DEFAULT_BLOCK_SIZE
    );
}
