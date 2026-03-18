# doublecrypt-core

A minimal encrypted filesystem core in Rust. All data at rest is encrypted with ChaCha20-Poly1305 AEAD; the backing block store sees only opaque ciphertext. Designed for embedding in desktop and mobile apps via a C ABI (Swift, Kotlin/JNI, etc.) and for use in Rust-based Linux FUSE mounts.

Supports five storage backends: in-memory (for testing), regular files (disk images), raw block devices (e.g. AWS EBS volumes), and **network-backed storage** via mTLS to a [`doublecrypt-server`](https://github.com/doublecrypt/doublecrypt-server) — with an optional write-back LRU cache layer that can sit in front of any backend.

## Quick Start

```rust
use std::sync::Arc;
use doublecrypt_core::block_store::MemoryBlockStore;
use doublecrypt_core::crypto::ChaChaEngine;
use doublecrypt_core::fs::FilesystemCore;
use doublecrypt_core::model::DEFAULT_BLOCK_SIZE;

// 1. Create a block store (in-memory for this example).
let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, 64));

// 2. Create a crypto engine with a 32-byte master key.
let crypto = Arc::new(ChaChaEngine::new(&[0xAA; 32]).unwrap());

// 3. Build the filesystem and format it.
let mut fs = FilesystemCore::new(store, crypto);
fs.init_filesystem().unwrap();

// 4. Create a file, write, read back.
fs.create_file("hello.txt").unwrap();
fs.write_file("hello.txt", 0, b"Hello, encrypted world!").unwrap();

let data = fs.read_file("hello.txt", 0, 4096).unwrap();
assert_eq!(data, b"Hello, encrypted world!");
```

## Architecture

The crate is organized as a layered stack. Each layer depends only on the ones below it.

```
┌─────────────────────────────────────────┐
│  ffi              C ABI for Swift/etc   │
├─────────────────────────────────────────┤
│  fs               FilesystemCore        │
├─────────────────────────────────────────┤
│  transaction      A/B root pointer      │
│                   commit manager        │
├──────────────┬──────────────────────────┤
│  codec       │  allocator               │
│  serialize + │  block bitmap            │
│  encrypt     │                          │
├──────────────┴──────────────────────────┤
│  crypto           ChaCha20-Poly1305     │
├─────────────────────────────────────────┤
│  cached_store     Write-back LRU cache  │
├─────────────────────────────────────────┤
│  block_store      trait BlockStore      │
│    ├ MemoryBlockStore    (testing)      │
│    ├ DiskBlockStore      (file images)  │
│    ├ DeviceBlockStore    (raw devices)  │
│    └ NetworkBlockStore   (mTLS, opt)    │
├─────────────────────────────────────────┤
│  proto            wire protocol types   │
├─────────────────────────────────────────┤
│  model / error    on-disk types         │
└─────────────────────────────────────────┘
```

## Modules

### `error` — Error types

All fallible operations return `FsResult<T>`, which is `Result<T, FsError>`.

```rust
use doublecrypt_core::error::{FsError, FsResult};
```

`FsError` variants:

| Variant                               | Meaning                                        |
| ------------------------------------- | ---------------------------------------------- |
| `BlockNotFound(u64)`                  | Referenced block doesn't exist                 |
| `BlockOutOfRange(u64)`                | Block ID ≥ total blocks                        |
| `NoFreeBlocks`                        | Allocator exhausted                            |
| `BlockSizeMismatch { expected, got }` | Write with wrong-sized buffer                  |
| `Serialization(String)`               | Encoding failure                               |
| `Deserialization(String)`             | Decoding failure                               |
| `Encryption(String)`                  | AEAD encrypt failure                           |
| `Decryption(String)`                  | AEAD decrypt failure (wrong key or corruption) |
| `ObjectNotFound(u64)`                 | Block has zero-length or invalid envelope      |
| `FileNotFound(String)`                | Name not in directory                          |
| `DirectoryNotFound(String)`           | Directory name not found                       |
| `FileAlreadyExists(String)`           | Duplicate name on create                       |
| `DirectoryAlreadyExists(String)`      | Duplicate directory name                       |
| `NotAFile(String)`                    | Tried a file operation on a directory          |
| `NotADirectory(String)`               | Tried a directory operation on a file          |
| `DirectoryNotEmpty(String)`           | Cannot remove non-empty directory              |
| `NameTooLong(usize, usize)`           | Filename exceeds 255 bytes                     |
| `NotInitialized`                      | Filesystem not mounted/formatted               |
| `InvalidSuperblock`                   | Bad magic, version, or checksum                |
| `InvalidRootPointer`                  | Neither A nor B root pointer slot is valid     |
| `DataTooLarge(usize)`                 | Serialized envelope exceeds block size         |
| `Internal(String)`                    | Catch-all (mutex poison, I/O, etc.)            |

`FsErrorCode` is a `#[repr(i32)]` enum used by the FFI layer to map errors to integer codes.

### `model` — On-disk data types

All persistent structures live here. They derive `Serialize` + `Deserialize` for postcard encoding.

**Constants:**

| Name                   | Value   | Meaning                      |
| ---------------------- | ------- | ---------------------------- |
| `DEFAULT_BLOCK_SIZE`   | `65536` | 64 KiB per block             |
| `MAX_NAME_LEN`         | `255`   | Max filename bytes (UTF-8)   |
| `BLOCK_STORAGE_HEADER` | `0`     | Block 0: storage header      |
| `BLOCK_ROOT_POINTER_A` | `1`     | Block 1: root pointer slot A |
| `BLOCK_ROOT_POINTER_B` | `2`     | Block 2: root pointer slot B |
| `FIRST_DATA_BLOCK`     | `3`     | First allocatable block      |

**Key types:**

| Type              | Purpose                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `StorageHeader`   | Written to block 0. Contains magic (`DBLCRYPT`), version, block size, total blocks.                 |
| `RootPointer`     | Written to blocks 1 or 2. Contains generation counter, superblock reference, BLAKE3 checksum.       |
| `Superblock`      | Points to the root inode. Written encrypted to a data block.                                        |
| `Inode`           | Metadata for a file or directory: kind, size, timestamps, refs to directory page / extent map.      |
| `DirectoryPage`   | List of `DirectoryEntry` structs (name, inode ref, kind).                                           |
| `ExtentMap`       | List of `ExtentEntry` structs mapping chunk index → encrypted data block.                           |
| `EncryptedObject` | On-disk envelope: `ObjectKind`, version, 12-byte nonce, ciphertext.                                 |
| `ObjectRef`       | A typed block pointer (`u64`). `ObjectRef::null()` is `u64::MAX`.                                   |
| `ObjectKind`      | Discriminator: `Superblock`, `RootPointer`, `Inode`, `DirectoryPage`, `ExtentMap`, `FileDataChunk`. |

### `block_store` — Storage backends

The `BlockStore` trait abstracts fixed-size block I/O:

```rust
pub trait BlockStore: Send + Sync {
    fn block_size(&self) -> usize;
    fn total_blocks(&self) -> u64;
    fn read_block(&self, block_id: u64) -> FsResult<Vec<u8>>;
    fn write_block(&self, block_id: u64, data: &[u8]) -> FsResult<()>;
    fn sync(&self) -> FsResult<()> { Ok(()) }  // default no-op

    // Batch operations — overridden by NetworkBlockStore for pipelined I/O.
    fn read_blocks(&self, block_ids: &[u64]) -> FsResult<Vec<Vec<u8>>>;
    fn write_blocks(&self, blocks: &[(u64, &[u8])]) -> FsResult<()>;
}
```

The `read_blocks`/`write_blocks` methods have default sequential implementations. The network backend overrides them with pipelined I/O.

**`MemoryBlockStore`** — in-memory `HashMap<u64, Vec<u8>>` behind a `Mutex`. Good for tests and ephemeral use.

```rust
let store = MemoryBlockStore::new(block_size, total_blocks);
```

**`DiskBlockStore`** — file-backed I/O using `pread`/`pwrite` (positioned I/O, no seeking). `sync()` calls `file.sync_all()`.

```rust
// Create a new image file (random-filled, fails if file exists).
let store = DiskBlockStore::create("/path/to/image.dcfs", 65536, 1024)?;

// Open an existing image file.
let store = DiskBlockStore::open("/path/to/image.dcfs", 65536, 1024)?;

// Open and infer total_blocks from file size.
let store = DiskBlockStore::open("/path/to/image.dcfs", 65536, 0)?;
```

New image files are filled with cryptographically random bytes so free space is indistinguishable from ciphertext.

**`DeviceBlockStore`** — raw block device backend for devices such as AWS EBS volumes, local NVMe drives, or any `/dev/*` block device. Uses `pread`/`pwrite` just like `DiskBlockStore`, but discovers the device size via `lseek(SEEK_END)` because `stat()` reports `st_size = 0` for block devices.

```rust
// Open an existing block device (e.g. an already-initialized EBS volume).
let store = DeviceBlockStore::open("/dev/xvdf", 65536, 0)?;   // infer total_blocks

// Initialize a fresh device (fills with random data — slow on large volumes).
let store = DeviceBlockStore::initialize("/dev/xvdf", 65536, 0)?;
```

> **Note:** The process must have read/write permissions on the device node. On EC2, you typically need `root` or membership in the `disk` group.

**Implementing a custom backend:** Implement the `BlockStore` trait. The rest of the stack works with `Arc<dyn BlockStore>`, so any backend (network, FUSE, database) can be plugged in without changing any other code.

### `cached_store` — Write-back LRU cache

`CachedBlockStore<S>` wraps any `BlockStore` with an in-memory LRU cache. Reads are served from cache when possible; writes are marked dirty and flushed in batch on `sync()`. If a dirty entry is evicted by cache pressure, it is written-back to the inner store immediately.

```rust
use doublecrypt_core::cached_store::CachedBlockStore;

// Wrap any BlockStore with a 1024-block LRU cache.
let cached = CachedBlockStore::new(inner_store, 1024);

cached.write_block(0, &data)?;  // dirty, in cache only
cached.sync()?;                 // batch-flush to inner store
```

The cache uses `write_blocks()` during `sync()`, so a `NetworkBlockStore` underneath benefits from pipelined batch writes.

### `network_store` — Remote mTLS block store _(feature: `network`)_

`NetworkBlockStore` connects to a [`doublecrypt-server`](https://github.com/doublecrypt/doublecrypt-server) over mutual TLS using a 4-byte little-endian length-prefixed protobuf protocol.

```rust
use std::path::Path;
use doublecrypt_core::network_store::NetworkBlockStore;

let store = NetworkBlockStore::connect(
    "10.0.0.5:9100",
    "block-server",
    Path::new("certs/client.pem"),
    Path::new("certs/client-key.pem"),
    Path::new("certs/ca.pem"),
)?;
```

Or with the builder for full control:

```rust
use std::time::Duration;
use doublecrypt_core::network_store::{NetworkBlockStore, NetworkBlockStoreConfig};

let store = NetworkBlockStore::from_config(
    NetworkBlockStoreConfig::new("10.0.0.5:9100", "block-server")
        .client_cert("certs/client.pem")
        .client_key("certs/client-key.pem")
        .ca_cert("certs/ca.pem")
        .connect_timeout(Duration::from_secs(5))
        .io_timeout(Duration::from_secs(60)),
)?;
```

**Features:**

- **Request pipelining** — `read_blocks()`/`write_blocks()` send a full batch of requests before reading any responses (up to 64 at a time).
- **Automatic reconnection** — one transparent retry with a fresh TLS handshake on I/O failure.
- **Configurable timeouts** — connect timeout (default 10 s) and I/O timeout (default 30 s).

**Typical production setup** (network + cache):

```rust
use std::sync::Arc;
use doublecrypt_core::network_store::NetworkBlockStore;
use doublecrypt_core::cached_store::CachedBlockStore;
use doublecrypt_core::crypto::ChaChaEngine;
use doublecrypt_core::fs::FilesystemCore;

let net = NetworkBlockStore::connect(addr, sni, cert, key, ca)?;
let store = Arc::new(CachedBlockStore::new(net, 1024));
let crypto = Arc::new(ChaChaEngine::new(&master_key)?);
let mut fs = FilesystemCore::new(store, crypto);
fs.open()?;
```

### `proto` — Wire protocol types

The `proto` module contains hand-written [prost](https://crates.io/crates/prost) structs defining the length-prefixed protobuf wire protocol used between `NetworkBlockStore` and `doublecrypt-server`. It is **always available** (not feature-gated).

**Key types:**

| Type                 | Purpose                                               |
| -------------------- | ----------------------------------------------------- |
| `Request`            | Top-level message: one-of `Command` variants          |
| `Response`           | Top-level message: one-of `Result` variants           |
| `request::Command`   | `ReadBlock`, `WriteBlock`, `Sync`, `GetInfo`          |
| `response::Result`   | `ReadBlock`, `WriteBlock`, `Sync`, `GetInfo`, `Error` |
| `ReadBlockRequest`   | `block_id: u64`                                       |
| `ReadBlockResponse`  | `block_id: u64`, `data: Vec<u8>`                      |
| `WriteBlockRequest`  | `block_id: u64`, `data: Vec<u8>`                      |
| `WriteBlockResponse` | _(empty — success acknowledgement)_                   |
| `SyncResponse`       | _(empty — success acknowledgement)_                   |
| `GetInfoResponse`    | `block_size: u64`, `total_blocks: u64`                |
| `ErrorResponse`      | `code: i32`, `message: String`                        |

See [Sharing protocol types](#sharing-protocol-types-with-doublecrypt-server) in the Features section for cross-crate usage.

### `allocator` — Block allocation

The `SlotAllocator` trait manages free/allocated block tracking:

```rust
pub trait SlotAllocator: Send + Sync {
    fn allocate(&self) -> FsResult<u64>;
    fn free(&self, block_id: u64) -> FsResult<()>;
    fn is_allocated(&self, block_id: u64) -> bool;
}
```

`BitmapAllocator` is a `BTreeSet`-backed implementation. Blocks `0..FIRST_DATA_BLOCK` (0, 1, 2) are permanently reserved. On mount, the allocator is rebuilt by walking the metadata tree.

### `crypto` — Encryption engine

```rust
pub trait CryptoEngine: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> FsResult<(Vec<u8>, Vec<u8>)>;  // (nonce, ciphertext)
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> FsResult<Vec<u8>>;
}
```

**`ChaChaEngine`** — ChaCha20-Poly1305 AEAD with HKDF-SHA256 key derivation.

```rust
// From a caller-provided 32-byte master key:
let engine = ChaChaEngine::new(&master_key_bytes)?;

// Generate a random master key:
let engine = ChaChaEngine::generate()?;
```

| Parameter | Value                                                                               |
| --------- | ----------------------------------------------------------------------------------- |
| Cipher    | ChaCha20-Poly1305                                                                   |
| Key       | 256-bit, derived via HKDF-SHA256 (salt: `doublecrypt-v1`, info: `block-encryption`) |
| Nonce     | 96-bit, randomly generated per encryption                                           |
| Auth tag  | 128-bit (appended to ciphertext by AEAD)                                            |

The derived key is zeroized on drop.

**Helper functions:**

```rust
// Wrap plaintext into an EncryptedObject envelope:
let encrypted = encrypt_object(&engine, ObjectKind::Inode, &plaintext)?;

// Unwrap back to plaintext:
let plaintext = decrypt_object(&engine, &encrypted)?;
```

### `codec` — Serialization + encrypt/write pipeline

Combines serialization (postcard), encryption (crypto engine), and block I/O into single calls.

```rust
// Write a struct → serialize → encrypt → pad to block → write to store.
write_encrypted_object(&*store, &*crypto, &codec, block_id, ObjectKind::Inode, &inode)?;

// Read block → extract envelope → decrypt → deserialize → return typed struct.
let inode: Inode = read_encrypted_object(&*store, &*crypto, &codec, block_id)?;

// Same pipeline but for raw bytes (file data chunks):
write_encrypted_raw(&*store, &*crypto, &codec, block_id, ObjectKind::FileDataChunk, &raw_data)?;
let raw = read_encrypted_raw(&*store, &*crypto, &codec, block_id)?;
```

Every block is padded with random bytes (not zeroes) so the padding region is indistinguishable from ciphertext.

### `transaction` — Copy-on-write commit

`TransactionManager` handles atomic commits using alternating A/B root pointer slots.

**Commit sequence:**

1. All mutations allocate new blocks (copy-on-write). Old blocks are never modified in place.
2. `commit()` writes the new superblock to a fresh encrypted block.
3. Computes a BLAKE3 checksum of the serialized superblock.
4. Writes a `RootPointer` (generation, superblock ref, checksum) to the next A/B slot.
5. Toggles the next slot.

**Recovery on mount:**

```rust
// Read both root pointer slots, pick highest generation.
let (root_ptr, was_b) = TransactionManager::recover_latest(&*store, &codec)?
    .ok_or(FsError::InvalidRootPointer)?;
```

The single-block root pointer write is the atomic commit point. If a crash happens before it completes, the previous generation's root pointer is still valid.

### `fs` — High-level filesystem API

`FilesystemCore` is the main entry point for all filesystem operations.

```rust
use doublecrypt_core::fs::{FilesystemCore, DirListEntry};

let mut fs = FilesystemCore::new(store, crypto);
```

**Lifecycle:**

```rust
// Format a new filesystem (call once):
fs.init_filesystem()?;

// Or mount an existing one:
fs.open()?;
```

**File operations:**

```rust
fs.create_file("document.pdf")?;
fs.write_file("document.pdf", 0, &pdf_bytes)?;
fs.write_file("document.pdf", 1024, &more_bytes)?;   // write at offset
let data = fs.read_file("document.pdf", 0, 1_000_000)?;
fs.rename("document.pdf", "final.pdf")?;
fs.remove_file("final.pdf")?;
```

**Directory operations:**

```rust
fs.create_directory("photos")?;

let entries: Vec<DirListEntry> = fs.list_directory()?;
for e in &entries {
    println!("{} ({:?}) {} bytes", e.name, e.kind, e.size);
}

fs.remove_file("photos")?;  // must be empty
```

**Persistence:**

```rust
fs.sync()?;  // flush block store to disk
```

Every mutation (create, write, rename, remove) automatically commits a new generation via copy-on-write. Call `sync()` to ensure the underlying `BlockStore` flushes to durable storage.

### `ffi` — C ABI

The FFI layer exposes a handle-based C API for use from Swift, Kotlin, C, etc. See `include/doublecrypt_core.h` (generated by cbindgen).

Build the C header:

```bash
cargo install cbindgen
cbindgen --config cbindgen.toml --crate doublecrypt-core --output include/doublecrypt_core.h
```

Build the static/dynamic library:

```bash
cargo build --release
# Produces:
#   target/release/libdoublecrypt_core.a      (static)
#   target/release/libdoublecrypt_core.dylib   (dynamic, macOS)
```

**FFI functions:**

| Function                                                                                 | Purpose                    |
| ---------------------------------------------------------------------------------------- | -------------------------- |
| `fs_create(total_blocks, key, key_len) → *FsHandle`                                      | Create in-memory FS        |
| `fs_create_disk(path, total_blocks, block_size, create_new, key, key_len) → *FsHandle`   | Create/open disk FS        |
| `fs_create_device(path, total_blocks, block_size, initialize, key, key_len) → *FsHandle` | Open/init block device FS  |
| `fs_destroy(handle)`                                                                     | Free handle                |
| `fs_init_filesystem(handle) → i32`                                                       | Format new FS              |
| `fs_open(handle) → i32`                                                                  | Mount existing FS          |
| `fs_create_file(handle, name) → i32`                                                     | Create file                |
| `fs_write_file(handle, name, offset, data, len) → i32`                                   | Write data                 |
| `fs_read_file(handle, name, offset, len, out_buf, out_len) → i32`                        | Read into buffer           |
| `fs_list_root(handle, out_error) → *char`                                                | List root dir (JSON)       |
| `fs_create_dir(handle, name) → i32`                                                      | Create directory           |
| `fs_remove_file(handle, name) → i32`                                                     | Remove file/dir            |
| `fs_rename(handle, old, new) → i32`                                                      | Rename                     |
| `fs_sync(handle) → i32`                                                                  | Flush                      |
| `fs_free_string(s)`                                                                      | Free Rust-allocated string |

All functions return `0` on success or a negative `FsErrorCode` value on failure.

## On-Disk Format

Every block (allocated or free) contains random bytes. Allocated blocks have this structure:

```
Offset  Size     Content
──────  ───────  ──────────────────────────────────
0       4 bytes  u32 LE — length of the envelope (n)
4       n bytes  Serialized envelope (postcard)
4+n     rest     Random padding to fill block_size
```

**Block 0** (storage header, unencrypted):

```
envelope = StorageHeader { magic: "DBLCRYPT", version: 1, block_size, total_blocks }
```

**Blocks 1–2** (root pointers, unencrypted):

```
envelope = RootPointer { generation, superblock_ref, checksum }
```

**Blocks 3+** (data blocks, encrypted):

```
envelope = EncryptedObject { kind, version, nonce: [u8;12], ciphertext }
    where ciphertext = AEAD(plaintext || 16-byte Poly1305 tag)
    and plaintext = postcard-serialized Inode / DirectoryPage / ExtentMap / raw file data
```

## Features

| Feature   | Default | What it enables                                      |
| --------- | ------- | ---------------------------------------------------- |
| `network` | **yes** | `NetworkBlockStore` (rustls mTLS client)             |
| _(none)_  | always  | `proto` module (prost structs for the wire protocol) |

```toml
# Default — includes network support:
doublecrypt-core = "0.1"

# Local-only (no TLS dependencies, but proto types are still available):
doublecrypt-core = { version = "0.1", default-features = false }
```

### Sharing protocol types with `doublecrypt-server`

The `proto` module is **always available** regardless of feature flags. It contains hand-written [prost](https://crates.io/crates/prost) structs that define the wire protocol (requests, responses, error codes), so there is no need for `protoc` or `prost-build` at compile time.

This makes `doublecrypt-core` the single source of truth for the protocol. The server can import the types directly:

```toml
# In doublecrypt-server/Cargo.toml:
[dependencies]
doublecrypt-core = { version = "0.1", default-features = false }  # proto only, no TLS client
```

```rust
use doublecrypt_core::proto::{
    Request, Response,
    request::Command,
    response::Result as RespResult,
    ReadBlockRequest, ReadBlockResponse,
    WriteBlockRequest, WriteBlockResponse,
    SyncRequest, SyncResponse,
    GetInfoRequest, GetInfoResponse,
    ErrorResponse,
};
```

With `default-features = false`, only `prost` (for derive macros and encoding/decoding) is pulled in — no TLS dependencies.

## Limitations (v0.1)

- **Flat directory model** — all entries live in the root directory. No nested subdirectories.
- **No garbage collection** — old blocks from previous copy-on-write generations are never reclaimed. Extended use will exhaust the block store.
- **Whole-file rewrite on write** — `write_file` reads all existing chunks, splices the new data, and rewrites every chunk. Fine for small files; not suitable for large sequential appends.
- **Single directory/extent page** — no overflow pages for directories or extent maps.
- **Unix-only disk I/O** — `DiskBlockStore` and `DeviceBlockStore` use `std::os::unix::fs::FileExt` (`pread`/`pwrite`). Works on Linux and macOS; Windows would need a different implementation.

## Block Device Usage (EBS / EC2)

To use an AWS EBS volume (or any raw block device) as the encrypted store:

1. **Attach** an EBS volume to your EC2 instance (e.g. as `/dev/xvdf`).
2. **Do NOT** format or mount it with a traditional filesystem — doublecrypt writes directly to the raw device.
3. **Initialize** the device once (fills with random data so free blocks look like ciphertext):

```rust
use std::sync::Arc;
use doublecrypt_core::block_store::DeviceBlockStore;
use doublecrypt_core::crypto::ChaChaEngine;
use doublecrypt_core::fs::FilesystemCore;

let store = Arc::new(DeviceBlockStore::initialize("/dev/xvdf", 65536, 0).unwrap());
let crypto = Arc::new(ChaChaEngine::new(&master_key).unwrap());
let mut fs = FilesystemCore::new(store, crypto);
fs.init_filesystem().unwrap();
```

4. **Open** on subsequent boots:

```rust
let store = Arc::new(DeviceBlockStore::open("/dev/xvdf", 65536, 0).unwrap());
let crypto = Arc::new(ChaChaEngine::new(&master_key).unwrap());
let mut fs = FilesystemCore::new(store, crypto);
fs.open().unwrap();  // mount existing filesystem
```

From Swift (via the C FFI):

```swift
// First time — initialize the device:
let fs = try DoubleCryptFS.initializeDevice(path: "/dev/xvdf", key: masterKey)
try fs.initFilesystem()

// Subsequent opens:
let fs = try DoubleCryptFS.openDevice(path: "/dev/xvdf", key: masterKey)
try fs.mount()
```

> **Permissions:** The process needs read/write access to the device node. Run as `root` or add the user to the `disk` group (`sudo usermod -aG disk $USER`).

> **Sizing:** With the default 64 KiB block size, a 1 GiB EBS volume yields ~16,384 blocks. Pass `total_blocks: 0` to automatically use the full device.

## Examples

Create a local disk image:

```bash
cargo run --example create_image
```

Connect to a remote `doublecrypt-server` (network-backed):

```bash
cargo run --example network_mount -- \
    --addr 10.0.0.5:9100 \
    --server-name block-server \
    --cert certs/client.pem \
    --key certs/client-key.pem \
    --ca certs/ca.pem \
    --master-key 0000000000000000000000000000000000000000000000000000000000000000
```

See `examples/create_image.rs` and `examples/network_mount.rs`.

## Swift Integration

A ready-made Swift package wrapping the C ABI is in the `swift/` directory. See `swift/DOUBLECRYPT.md` for usage instructions.

```bash
./build-swift.sh    # builds static lib + C header
cd swift && swift build
```

## License

MIT
