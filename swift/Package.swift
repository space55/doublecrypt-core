// swift-tools-version: 5.9
import PackageDescription
import Foundation

// Compute absolute path to the Rust static library.
// This Package.swift lives at doublecrypt-core/swift/Package.swift.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let coreRoot   = URL(fileURLWithPath: packageDir).deletingLastPathComponent().path
let staticLibRelease = coreRoot + "/target/release/libdoublecrypt_core.a"

let package = Package(
    name: "DoubleCryptCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DoubleCryptCore", targets: ["DoubleCryptCore"]),
    ],
    targets: [
        .systemLibrary(
            name: "CDoubleCrypt",
            path: "CDoubleCrypt"
        ),
        .target(
            name: "DoubleCryptCore",
            dependencies: ["CDoubleCrypt"],
            path: "Sources/DoubleCryptCore",
            linkerSettings: [
                // Force-load the static .a (not -l which prefers .dylib).
                .unsafeFlags([
                    "-force_load", staticLibRelease,
                ]),
            ]
        ),
    ]
)
