// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DoubleCryptCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DoubleCryptCore", targets: ["DoubleCryptCore"]),
    ],
    targets: [
        // System library that imports the C header via module.modulemap.
        // The static library (libdoublecrypt_core.a) must be available at link time.
        .systemLibrary(
            name: "CDoubleCrypt",
            path: "CDoubleCrypt"
        ),
        .target(
            name: "DoubleCryptCore",
            dependencies: ["CDoubleCrypt"],
            path: "Sources/DoubleCryptCore",
            linkerSettings: [
                .unsafeFlags([
                    "-L", "../target/release",      // Universal / host builds
                    "-L", "../target/debug",         // Debug builds
                ]),
            ]
        ),
    ]
)
