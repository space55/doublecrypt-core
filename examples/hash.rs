//! Hashes arbitrary input with BLAKE3 and prints the result as hex.
//!
//! Run with:
//!   echo "hello" | cargo run --example hash
//!   cargo run --example hash -- "some string"

use std::io::Read;

fn main() {
    let input = if let Some(arg) = std::env::args().nth(1) {
        arg.into_bytes()
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .expect("failed to read stdin");
        buf
    };

    let hash = blake3::hash(&input);
    println!("{hash}");
}
