import CDoubleCrypt
import Foundation

/// Error codes returned by the doublecrypt-core C ABI.
public enum DoubleCryptError: Int32, Error, CustomStringConvertible {
    case notFound = -1
    case alreadyExists = -2
    case noSpace = -3
    case invalidArgument = -4
    case notInitialized = -5
    case ioError = -6
    case cryptoError = -7
    case internalError = -8
    case bufferTooSmall = -9
    case notAFile = -10
    case notADirectory = -11
    case directoryNotEmpty = -12
    case nameTooLong = -13

    public var description: String {
        switch self {
        case .notFound: return "Not found"
        case .alreadyExists: return "Already exists"
        case .noSpace: return "No space"
        case .invalidArgument: return "Invalid argument"
        case .notInitialized: return "Filesystem not initialized"
        case .ioError: return "I/O error"
        case .cryptoError: return "Crypto error"
        case .internalError: return "Internal error"
        case .bufferTooSmall: return "Buffer too small"
        case .notAFile: return "Not a file"
        case .notADirectory: return "Not a directory"
        case .directoryNotEmpty: return "Directory not empty"
        case .nameTooLong: return "Name too long"
        }
    }
}

/// A directory entry returned by ``DoubleCryptFS/listDirectory()``.
public struct DirEntry: Codable {
    public let name: String
    public let kind: String
    public let size: UInt64
}

/// Swift wrapper around the doublecrypt-core C ABI.
///
/// Usage:
/// ```swift
/// let key = Data(repeating: 0xAA, count: 32)
/// let fs = try DoubleCryptFS.createOnDisk(
///     path: "/tmp/vault.dcfs", totalBlocks: 64, key: key
/// )
/// try fs.initFilesystem()
/// try fs.createFile("secret.txt")
/// try fs.writeFile("secret.txt", data: Data("hello".utf8))
/// let data = try fs.readFile("secret.txt", maxLength: 1024)
/// ```
public final class DoubleCryptFS {
    private var handle: OpaquePointer

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        fs_destroy(handle)
    }

    // MARK: - Factory methods

    /// Create a new in-memory filesystem (useful for tests).
    public static func createInMemory(totalBlocks: UInt64 = 64, key: Data) throws -> DoubleCryptFS {
        let handle: OpaquePointer? = key.withUnsafeBytes { keyBuf -> OpaquePointer? in
            guard let ptr = keyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return fs_create(totalBlocks, ptr, UInt(keyBuf.count))
        }
        guard let handle else { throw DoubleCryptError.invalidArgument }
        return DoubleCryptFS(handle: handle)
    }

    /// Create a new disk-backed filesystem image.
    public static func createOnDisk(
        path: String,
        totalBlocks: UInt64 = 64,
        blockSize: UInt32 = 0,
        key: Data
    ) throws -> DoubleCryptFS {
        let handle: OpaquePointer? = key.withUnsafeBytes { keyBuf -> OpaquePointer? in
            guard let ptr = keyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return path.withCString { cPath in
                fs_create_disk(cPath, totalBlocks, blockSize, 1, ptr, UInt(keyBuf.count))
            }
        }
        guard let handle else { throw DoubleCryptError.ioError }
        return DoubleCryptFS(handle: handle)
    }

    /// Open an existing disk-backed filesystem image.
    public static func open(
        path: String,
        totalBlocks: UInt64 = 0,
        blockSize: UInt32 = 0,
        key: Data
    ) throws -> DoubleCryptFS {
        let handle: OpaquePointer? = key.withUnsafeBytes { keyBuf -> OpaquePointer? in
            guard let ptr = keyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return path.withCString { cPath in
                fs_create_disk(cPath, totalBlocks, blockSize, 0, ptr, UInt(keyBuf.count))
            }
        }
        guard let handle else { throw DoubleCryptError.ioError }
        return DoubleCryptFS(handle: handle)
    }

    /// Initialize a raw block device (e.g. an EBS volume) as a new encrypted filesystem.
    ///
    /// This fills the device with random data so free space is indistinguishable
    /// from ciphertext. **Warning:** this writes to every block and can take a
    /// long time on large devices.
    ///
    /// - Parameters:
    ///   - path: Path to the block device, e.g. `/dev/xvdf`.
    ///   - totalBlocks: Number of blocks to use. Pass 0 to use the entire device.
    ///   - blockSize: Block size in bytes. Pass 0 for the default (65536).
    ///   - key: 32-byte master encryption key.
    public static func initializeDevice(
        path: String,
        totalBlocks: UInt64 = 0,
        blockSize: UInt32 = 0,
        key: Data
    ) throws -> DoubleCryptFS {
        let handle: OpaquePointer? = key.withUnsafeBytes { keyBuf -> OpaquePointer? in
            guard let ptr = keyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return path.withCString { cPath in
                fs_create_device(cPath, totalBlocks, blockSize, 1, ptr, UInt(keyBuf.count))
            }
        }
        guard let handle else { throw DoubleCryptError.ioError }
        return DoubleCryptFS(handle: handle)
    }

    /// Open an existing encrypted filesystem on a raw block device.
    ///
    /// - Parameters:
    ///   - path: Path to the block device, e.g. `/dev/xvdf`.
    ///   - totalBlocks: Number of blocks. Pass 0 to infer from the device size.
    ///   - blockSize: Block size in bytes. Pass 0 for the default (65536).
    ///   - key: 32-byte master encryption key.
    public static func openDevice(
        path: String,
        totalBlocks: UInt64 = 0,
        blockSize: UInt32 = 0,
        key: Data
    ) throws -> DoubleCryptFS {
        let handle: OpaquePointer? = key.withUnsafeBytes { keyBuf -> OpaquePointer? in
            guard let ptr = keyBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return path.withCString { cPath in
                fs_create_device(cPath, totalBlocks, blockSize, 0, ptr, UInt(keyBuf.count))
            }
        }
        guard let handle else { throw DoubleCryptError.ioError }
        return DoubleCryptFS(handle: handle)
    }

    // MARK: - Lifecycle

    /// Initialize a fresh filesystem on the block store. Call once after ``createOnDisk(path:totalBlocks:blockSize:key:)`` or ``createInMemory(totalBlocks:key:)``.
    public func initFilesystem() throws {
        try check(fs_init_filesystem(handle))
    }

    /// Mount an existing filesystem from the block store.
    public func mount() throws {
        try check(fs_open(handle))
    }

    /// Flush all pending writes.
    public func sync() throws {
        try check(fs_sync(handle))
    }

    // MARK: - File operations

    public func createFile(_ name: String) throws {
        try check(name.withCString { fs_create_file(handle, $0) })
    }

    public func writeFile(_ name: String, offset: UInt64 = 0, data: Data) throws {
        try data.withUnsafeBytes { buf in
            guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                throw DoubleCryptError.invalidArgument
            }
            try check(name.withCString { cName in
                fs_write_file(handle, cName, offset, ptr, UInt(buf.count))
            })
        }
    }

    public func readFile(_ name: String, offset: UInt64 = 0, maxLength: Int = 1_048_576) throws -> Data {
        var outLen: UInt = UInt(maxLength)
        var buffer = Data(count: maxLength)
        let rc = try buffer.withUnsafeMutableBytes { buf in
            guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                throw DoubleCryptError.invalidArgument
            }
            return name.withCString { cName in
                fs_read_file(handle, cName, offset, UInt(maxLength), ptr, &outLen)
            }
        }
        try check(rc)
        return buffer.prefix(Int(outLen))
    }

    public func removeFile(_ name: String) throws {
        try check(name.withCString { fs_remove_file(handle, $0) })
    }

    public func rename(from oldName: String, to newName: String) throws {
        try check(oldName.withCString { cOld in
            newName.withCString { cNew in
                fs_rename(handle, cOld, cNew)
            }
        })
    }

    // MARK: - Directory operations

    public func createDirectory(_ name: String) throws {
        try check(name.withCString { fs_create_dir(handle, $0) })
    }

    public func listDirectory() throws -> [DirEntry] {
        var errCode: Int32 = 0
        guard let cStr = fs_list_root(handle, &errCode) else {
            throw DoubleCryptError(rawValue: errCode) ?? .internalError
        }
        defer { fs_free_string(cStr) }
        let json = String(cString: cStr)
        guard let data = json.data(using: .utf8) else {
            throw DoubleCryptError.internalError
        }
        return try JSONDecoder().decode([DirEntry].self, from: data)
    }

    // MARK: - Private

    @discardableResult
    private func check(_ code: Int32) throws -> Int32 {
        if code != 0 {
            throw DoubleCryptError(rawValue: code) ?? .internalError
        }
        return code
    }
}
