// swift-tools-version: 5.9
import PackageDescription
import Foundation

// Compute the absolute path to the Rust library output directories.
// This Package.swift lives at doublecrypt-core/swift/Package.swift,
// so the parent directory (../) is doublecrypt-core/.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let coreRoot   = URL(fileURLWithPath: packageDir).deletingLastPathComponent().path
let releaseLib = coreRoot + "/target/release"
let debugLib   = coreRoot + "/target/debug"
let staticLibRelease = releaseLib + "/libdoublecrypt_core.a"
let staticLibDebug   = debugLib   + "/libdoublecrypt_core.a"

let package = Package(
    name: "DoubleCryptCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DoubleCryptCore", targets: ["DoubleCryptCore"]),
    ],
    targets: [
        // System library that imports the C header via module.modulemap.
        .systemLibrary(
            name: "CDoubleCrypt",
            path: "CDoubleCrypt"
        ),
        .target(
            name: "DoubleCryptCore",
            dependencies: ["CDoubleCrypt"],
            path: "Sources/DoubleCryptCore",
            linkerSettings: [
                // Force-load the static library directly (not -l which prefers .dylib).
                // We try release first; if it doesn't exist the debug one will be used.
                .unsafeFlags([
                    "-force_load", staticLibRelease,
                ]),
            ]
        ),
    ]
)
