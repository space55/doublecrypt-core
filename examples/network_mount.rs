//! Connects to a `doublecrypt-server` over TLS, authenticates with a
//! key-derived token, mounts a network-backed encrypted filesystem with a
//! write-back cache, and performs basic operations.
//!
//! Run with:
//!   cargo run --example network_mount -- \
//!       --addr 127.0.0.1:9100 \
//!       --server-name localhost \
//!       --ca certs/ca.pem \
//!       --master-key 0000000000000000000000000000000000000000000000000000000000000000

use std::path::Path;
use std::sync::Arc;

use doublecrypt_core::block_store::BlockStore;
use doublecrypt_core::cached_store::CachedBlockStore;
use doublecrypt_core::crypto::ChaChaEngine;
use doublecrypt_core::fs::FilesystemCore;
use doublecrypt_core::network_store::NetworkBlockStore;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut addr = "127.0.0.1:9100";
    let mut server_name = "localhost";
    let mut ca = "certs/ca.pem";
    let mut master_key_hex = "";
    let mut init = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                addr = &args[i + 1];
                i += 2;
            }
            "--server-name" => {
                server_name = &args[i + 1];
                i += 2;
            }
            "--ca" => {
                ca = &args[i + 1];
                i += 2;
            }
            "--master-key" => {
                master_key_hex = &args[i + 1];
                i += 2;
            }
            "--init" => {
                init = true;
                i += 1;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    if master_key_hex.is_empty() || master_key_hex.len() != 64 {
        eprintln!("--master-key must be a 64-character hex string (32 bytes)");
        std::process::exit(1);
    }

    let master_key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&master_key_hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();

    // ── Connect ─────────────────────────────────────────────
    println!("Connecting to {addr} (SNI: {server_name})...");
    let net = NetworkBlockStore::connect(addr, server_name, Path::new(ca), &master_key)
        .expect("failed to connect to server");

    println!(
        "Connected: {} blocks × {} bytes ({} MiB)",
        net.total_blocks(),
        net.block_size(),
        net.total_blocks() as usize * net.block_size() / (1024 * 1024)
    );

    // ── Wrap with cache ─────────────────────────────────────
    let store = Arc::new(CachedBlockStore::new(net, 1024));
    let crypto = Arc::new(ChaChaEngine::new(&master_key).expect("invalid master key"));
    let mut fs = FilesystemCore::new(store.clone(), crypto);

    // ── Mount or init ───────────────────────────────────────
    if init {
        println!("Initializing new filesystem...");
        fs.init_filesystem().expect("init_filesystem failed");
    } else {
        println!("Mounting existing filesystem...");
        fs.open().expect("open failed");
    }

    // ── Demo operations ─────────────────────────────────────
    println!("\nCreating file 'hello.txt'...");
    match fs.create_file("hello.txt") {
        Ok(()) => {}
        Err(e) => println!("  (skipped: {e})"),
    }

    fs.write_file("hello.txt", 0, b"Hello from the network!")
        .expect("write failed");

    let data = fs.read_file("hello.txt", 0, 4096).expect("read failed");
    println!("Read back: {:?}", String::from_utf8_lossy(&data));

    println!("\nListing root directory:");
    for entry in fs.list_directory("").expect("list failed") {
        println!(
            "  {:?}  {:>10} bytes  {}",
            entry.kind, entry.size, entry.name
        );
    }

    // ── Sync ────────────────────────────────────────────────
    fs.sync().expect("sync failed");
    println!("\nAll data synced to server.");
}
