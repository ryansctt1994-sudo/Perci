//! Bounded, deterministic negative tests against the REAL PERCIW03 loader.
//! This is not cargo-fuzz, sanitizer evidence, or a proof of memory safety.
use perci::cognitive::CognitiveWeights;
use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn temp_path() -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("perciw03-negative-{}-{now}.pwgt", std::process::id()))
}

fn header_only() -> [u8; 80] {
    let mut bytes = [0u8; 80];
    bytes[0..8].copy_from_slice(b"PERCIW03");
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&4096u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&64u32.to_le_bytes());
    // Zero labels, zero records; header occupies the full fixture.
    bytes[32..40].copy_from_slice(&80u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&80u64.to_le_bytes());
    bytes
}

#[test]
fn actual_loader_rejects_all_truncated_fixed_headers() {
    let path = temp_path();
    let fixture = header_only();
    for end in 0..80 {
        fs::write(&path, &fixture[..end]).expect("write test fixture");
        assert!(
            CognitiveWeights::load(&path).is_err(),
            "truncated real PERCIW03 header unexpectedly accepted at length {end}"
        );
    }
    fs::remove_file(path).expect("clean up");
}

#[test]
fn actual_loader_rejects_bad_magic_and_untrusted_dimensions() {
    let path = temp_path();
    let valid = header_only();
    // Exercise each byte of the eight-byte real loader signature.
    for offset in 0..8 {
        let mut bytes = valid;
        bytes[offset] ^= 0x01;
        fs::write(&path, bytes).expect("write test fixture");
        assert!(CognitiveWeights::load(&path).is_err(), "bad magic byte {offset}");
    }
    // Regression for unbounded Vec::with_capacity(label_count). A short
    // file must reject this forged count without an allocation attempt.
    let mut enormous_labels = valid;
    enormous_labels[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, enormous_labels).expect("write test fixture");
    assert!(
        CognitiveWeights::load(&path).is_err(),
        "enormous declared label_count must fail before memory reservation"
    );
    // Specific valid-magic, malformed-header attacks.
    for (name, offset, byte) in [
        ("bit_width", 13usize, 0u8),
        ("word_count", 16usize, 0u8),
        ("label_table", 20usize, 1u8),
        ("record_count", 24usize, 1u8),
        ("header_offset", 32usize, 0u8),
        ("declared_size", 40usize, 0u8),
    ] {
        let mut bytes = valid;
        bytes[offset] = byte;
        fs::write(&path, bytes).expect("write test fixture");
        assert!(CognitiveWeights::load(&path).is_err(), "{name}");
    }
    fs::remove_file(path).expect("clean up");
}

#[test]
fn actual_loader_handles_deterministic_header_mutations_without_panic() {
    let path = temp_path();
    let mut seed: u64 = 0x717_012_2026;
    let valid = header_only();
    for _ in 0..512 {
        // Fixed-seed xorshift; mutate only format fields, never the kernel/file-system.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let index = (seed as usize) % 48;
        let mut bytes = valid;
        bytes[index] ^= 1u8 << ((seed >> 8) as usize % 8);
        fs::write(&path, bytes).expect("write test fixture");
        let _ = CognitiveWeights::load(&path);
    }
    fs::remove_file(path).expect("clean up");
}
