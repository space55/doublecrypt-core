// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DoubleCrypt",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DoubleCrypt", targets: ["DoubleCrypt"]),
    ],
    targets: [
        // System library that imports the C header via module.modulemap.
        // The static library (libdoublecrypt_core.a) must be available at link time.
        .systemLibrary(
            name: "CDoubleCrypt",
            path: "CDoubleCrypt"
        ),
        .target(
            name: "DoubleCrypt",
            dependencies: ["CDoubleCrypt"],
            path: "Sources/DoubleCrypt",
            linkerSettings: [
                .unsafeFlags([
                    "-L", "../target/release",      // Universal / host builds
                    "-L", "../target/debug",         // Debug builds
                ]),
            ]
        ),
    ]
)
