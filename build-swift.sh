#!/usr/bin/env bash
set -euo pipefail

# Build the Rust static library and regenerate the C header.
# Run from the doublecrypt-core root.

cd "$(dirname "$0")"

echo "==> Building static library (release)..."
cargo build --release

echo "==> Generating C header..."
cbindgen --config cbindgen.toml --crate doublecrypt-core --output include/doublecrypt_core.h

echo ""
echo "Done. Artifacts:"
echo "  Static lib:  target/release/libdoublecrypt_core.a"
echo "  Dynamic lib: target/release/libdoublecrypt_core.dylib"
echo "  C header:    include/doublecrypt_core.h"
echo ""
echo "To use from Swift:"
echo "  cd swift && swift build"
