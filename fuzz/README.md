# Perci native parser fuzz targets — bounded research harness

These targets exercise actual Rust parsing code, not the illustrative Python PERC fixture:

- perciw03_loader: invokes the real mmap-backed CognitiveWeights::load on process-local scratch bytes. It covers binary W01/W02/W03 headers and bounded table parsing.
- pack_manifest_json: invokes serde_json::from_slice for PackManifest, followed by validate_basic. JSON sidecars and binary weight headers are separate formats.

## Reproduce

From the repository root, with Rust nightly and cargo-fuzz installed:

    python3 fuzz/seed_corpus.py
    python3 -m unittest discover -s tests -p 'test_fuzz_seeds.py' -v
    python3 fuzz/seed_corpus.py --check
    cargo install cargo-fuzz --locked
    cargo +nightly fuzz run perciw03_loader -- -max_total_time=20 -max_len=8192 -rss_limit_mb=1024 -timeout=3
    cargo +nightly fuzz run pack_manifest_json -- -max_total_time=20 -max_len=16384 -rss_limit_mb=1024 -timeout=3

CI uses short runs and retains crash artifacts when possible. Seeds are generated
deterministically; the generator prints SHA-256 for each binary. Binary seeds
include valid W01/W02/W03 headers, a valid label and record, truncated
headers, forged label count u32::MAX (previous allocation DoS), and
magic/version mismatches.

## Constraints and non-claims

- The loader target caps inputs at 8 KiB, and uses a process-specific
  temporary file because the real parser expects a file for mmap.
- Generated corpora, scratch builds and fuzz crashes are not committed. Keep
  distilled regression cases in the native Rust tests.
- A brief coverage-guided smoke run is neither exhaustive testing nor a
  guarantee of memory safety. Confirm sanitizer instrumentation from logs;
  MSan and PyO3 FFI are not covered.
- Not a fuzz proof for full-size production model packages or all platforms.
  No independent external witness, no authority promotion, O0 WITHHELD.
