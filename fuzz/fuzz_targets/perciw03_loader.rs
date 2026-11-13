#![no_main]

// Exercises the REAL mmap-backed Perci loader, not the synthetic Python
// "PERC" parser. Each libFuzzer process uses a distinct temporary file.
// The input-length cap bounds temporary disk use and header-driven allocation
// space; it is not a proof of memory safety or a production sandbox.
use libfuzzer_sys::fuzz_target;
use perci::cognitive::CognitiveWeights;
use std::path::PathBuf;
use std::sync::OnceLock;

const MAX_INPUT_BYTES: usize = 8 * 1024;
static WORK_FILE: OnceLock<PathBuf> = OnceLock::new();

fn working_file() -> &'static PathBuf {
    WORK_FILE.get_or_init(|| {
        std::env::temp_dir().join(format!(
            "perciw03-libfuzzer-{}.pwgt",
            std::process::id()
        ))
    })
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    let file = working_file();
    // Do not silently skip inputs if the runner cannot write its scratch file.
    std::fs::write(file, bytes).expect("fuzz scratch write");
    // The real loader may return Err for malformed/untrusted payloads.
    // Panics, aborts, and sanitizer findings are fuzz failures.
    let _ = CognitiveWeights::load(file);
});
