# DoubleCryptCore Swift Library

Encrypted filesystem core for macOS / iOS. All data at rest is encrypted with ChaCha20-Poly1305; the backing store sees only opaque ciphertext blocks.

## Build Prerequisites

The Rust static library **must** be built before the Swift package can link. From the repository root:

```bash
# Install cbindgen (one-time)
cargo install cbindgen

# Build the static library + regenerate the C header
./build-swift.sh
```

This produces:

- `target/release/libdoublecrypt_core.a` — static library linked by Swift
- `include/doublecrypt_core.h` — auto-generated C header (do not edit by hand)

## Adding to an Xcode Project

1. In Xcode, **File → Add Package Dependencies → Add Local…** and select the `swift/` directory.
2. Add `libdoublecrypt_core.a` (from `target/release/`) to your target's **Link Binary With Libraries** build phase.
3. `import DoubleCryptCore` in your Swift files.

Or, in another Swift package, add a local dependency:

```swift
.package(path: "../doublecrypt-core/swift")
```

## API Reference

### Initialization

```swift
import DoubleCryptCore

// A 32-byte encryption key. In production, derive from a passphrase via Argon2 / scrypt.
let key: Data = ...  // exactly 32 bytes

// Option A: Create a new encrypted image file (4 MiB = 64 blocks × 64 KiB)
let fs = try DoubleCryptFS.createOnDisk(
    path: "/path/to/vault.dcfs",
    totalBlocks: 64,        // default 64
    blockSize: 0,           // 0 = default 65536 (64 KiB)
    key: key
)
try fs.initFilesystem()     // format the new image — call exactly once after create

// Option B: Open an existing image
let fs = try DoubleCryptFS.open(
    path: "/path/to/vault.dcfs",
    key: key
)
try fs.mount()              // read existing root pointers — call after open

// Option C: In-memory (for unit tests, no disk I/O)
let fs = try DoubleCryptFS.createInMemory(totalBlocks: 64, key: key)
try fs.initFilesystem()

// Option D: Connect to a remote doublecrypt-server over TLS
let fs = try DoubleCryptFS.connectToServer(
    addr: "10.0.0.5:9100",      // server address
    serverName: "dc-server",     // TLS SNI hostname
    caCertPath: "/path/to/ca.pem", // CA certificate for server verification
    cacheBlocks: 256,            // local LRU cache size (0 = default 256)
    key: key
)
try fs.mount()                   // read existing root pointers from remote store
```

> **Network mode** uses key-derived authentication (HKDF) — no separate credentials needed.
> A local write-back LRU cache sits in front of the TLS connection for performance.

### File Operations

```swift
// Create a file (supports nested paths like "docs/notes.txt")
try fs.createFile("notes.txt")

// Write data (offset defaults to 0)
try fs.writeFile("notes.txt", data: Data("Hello, world!".utf8))

// Write at a specific offset
try fs.writeFile("notes.txt", offset: 14, data: Data(" Appended.".utf8))

// Read data (offset defaults to 0, maxLength defaults to 1 MiB)
let data = try fs.readFile("notes.txt", maxLength: 4096)
let text = String(data: data, encoding: .utf8)!

// Rename
try fs.rename(from: "notes.txt", to: "readme.txt")

// Delete
try fs.removeFile("readme.txt")
```

### Directory Operations

```swift
// Create a directory
try fs.createDirectory("photos")

// Create nested directories (parents must exist)
try fs.createDirectory("photos/vacation")

// List root directory — returns [DirEntry]
let entries = try fs.listDirectory()
for entry in entries {
    print("\(entry.name)  \(entry.kind)  \(entry.size) bytes")
    // entry.kind is "File" or "Directory"
    // entry.isFile / entry.isDirectory convenience booleans
}

// List a subdirectory
let photos = try fs.listDirectory(path: "photos")

// Stat a single file (cheaper than listing the parent directory)
let (size, isDir, inodeId) = try fs.stat("notes.txt")

// Remove an empty directory
try fs.removeFile("photos/vacation")
try fs.removeFile("photos")
```

### Persistence

```swift
// Flush buffered writes (no fsync). Preferred for normal use.
try fs.flush()

// Flush + fsync. Use for explicit durability guarantees.
try fs.sync()
```

The `DoubleCryptFS` instance is freed automatically when it goes out of scope (`deinit` calls the Rust destructor). Always call `flush()` or `sync()` before the handle is dropped if you need durability.

### Security

```swift
// Fill all free blocks with random data so free space is indistinguishable
// from ciphertext. Run periodically or after bulk deletes.
try fs.scrubFreeBlocks()
```

### Error Handling

All methods throw `DoubleCryptError`. Catch specific cases:

```swift
do {
    try fs.createFile("duplicate.txt")
    try fs.createFile("duplicate.txt")  // throws
} catch DoubleCryptError.alreadyExists {
    print("File already exists")
} catch {
    print("Unexpected: \(error)")
}
```

Error cases:

| Case                 | Meaning                                                              |
| -------------------- | -------------------------------------------------------------------- |
| `.notFound`          | File or directory does not exist                                     |
| `.alreadyExists`     | Name already taken                                                   |
| `.noSpace`           | Block store is full                                                  |
| `.invalidArgument`   | Null pointer, bad name, or invalid parameter                         |
| `.notInitialized`    | Called `mount()` on unformatted image, or operated before init/mount |
| `.ioError`           | Disk I/O failure                                                     |
| `.cryptoError`       | Decryption failed (wrong key or corrupted data)                      |
| `.internalError`     | Serialization or unexpected internal failure                         |
| `.bufferTooSmall`    | Read buffer too small (should not occur via Swift wrapper)           |
| `.notAFile`          | Tried to read/write a directory                                      |
| `.notADirectory`     | Tried to list a file                                                 |
| `.directoryNotEmpty` | Tried to remove non-empty directory                                  |
| `.nameTooLong`       | Filename exceeds 255 bytes                                           |

### Types

```swift
public struct DirEntry: Codable {
    public let name: String     // filename
    public let kind: String     // "File" or "Directory"
    public let size: UInt64     // size in bytes (0 for directories)
    public let inode_id: UInt64 // logical inode id

    public var isFile: Bool
    public var isDirectory: Bool
}
```

## Typical Lifecycle

```
createOnDisk / open
        │
  initFilesystem / mount
        │
  ┌─────┴─────┐
  │ read/write │  ← repeated operations
  └─────┬─────┘
        │
      sync
        │
  (handle dropped)
```

## Constraints

- **Nested directories**: supported. Create parents before children.
- **Filename limit**: 255 bytes UTF-8.
- **Block size**: fixed at creation time (default 64 KiB). Cannot be changed after.
- **Concurrency**: the `DoubleCryptFS` handle is **not** thread-safe. Serialize access or use one handle per thread/actor.
- **Key size**: exactly 32 bytes.
