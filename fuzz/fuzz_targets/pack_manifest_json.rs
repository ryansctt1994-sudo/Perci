#![no_main]

// JSON sidecar parsing is distinct from the binary PERCIW03 header format.
// Exercise actual serde deserialization plus PackManifest::validate_basic.
// No filesystem discovery, promotion, or model loading occurs in this target.
use libfuzzer_sys::fuzz_target;
use perci::pack_manifest::PackManifest;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<PackManifest>(bytes) {
        let _ = manifest.validate_basic();
    }
});
