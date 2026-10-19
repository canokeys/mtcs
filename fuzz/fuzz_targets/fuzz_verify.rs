//! Fuzz the full verification pipeline with a fixed trust store.
//!
//! Seeds are the demo corpus DER fixtures; libFuzzer mutates valid Merkle Tree
//! Certificates into deep parser/verifier states.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mtcs::{CaTrust, TrustStore, verify_certificate};
use std::sync::LazyLock;

// 2025-01-01T00:00:00Z: inside the demo corpus validity window.
const NOW: i64 = 1735689600;

static STORE: LazyLock<TrustStore> = LazyLock::new(|| {
    let ca = CaTrust::from_ca_certificate(include_bytes!("../../tests/fixtures/ca.der"))
        .expect("fixture CA");
    let mut store = TrustStore::new();
    store.add_ca(ca);
    store
});

fuzz_target!(|data: &[u8]| {
    // Any verdict is fine; panics are not. Resource exhaustion is bounded by
    // the verifier's own structural limits (fixed-size hashes and bounded
    // vectors).
    let _ = verify_certificate(&STORE, data, NOW);
});
