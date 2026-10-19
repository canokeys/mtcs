//! Fuzz the base-layer parsers: MTCProof (lenient and strict), certificate
//! decomposition and entry hashing, CA certificate parsing, landmark documents
//! and certificate property lists.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mtcs::{
    CaTrust, CertificatePropertyList, MtcProof, entry_hash_from_certificate, parse_landmarks,
};

fuzz_target!(|data: &[u8]| {
    let _ = MtcProof::parse(data);
    let _ = MtcProof::parse_strict(data);
    if let Ok(proof) = MtcProof::from_certificate(data) {
        let _ = entry_hash_from_certificate(data, proof.entry_extensions_bytes());
    }
    let _ = CaTrust::from_ca_certificate(data);
    let _ = CertificatePropertyList::parse(data);
    let _ = parse_landmarks(&String::from_utf8_lossy(data), 1_700_000_000);
});
