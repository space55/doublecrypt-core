//! Derives a 32-byte encryption key from a passphrase using BLAKE3's
//! key-derivation mode.
//!
//! Run with:
//!   cargo run --example derive_key -- "my secret passphrase"
//!
//! The derived key is printed as hex and can be fed to DoubleCryptFS as the
//! master encryption key.

fn main() {
    let passphrase = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("Usage: derive_key <passphrase>");
            std::process::exit(1);
        }
    };

    // BLAKE3 derive_key uses a context string to domain-separate the
    // derivation.  This ensures the same passphrase used in a different
    // application produces a different key.
    let key = blake3::derive_key("doublecrypt-core master key v1", passphrase.as_bytes());

    println!("{}", hex(&key));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
