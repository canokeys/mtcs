//! Verify Merkle Tree certificates against a CA certificate (requires the
//! default `verify` feature). Accepts DER or PEM inputs.
//!
//! Usage: cargo run --example verify -- ca.pem cert.pem...

use mtcs::{CaTrust, TrustStore, VerificationKind, verify_certificate};

fn read_certificate(path: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read certificate");
    let text = core::str::from_utf8(&bytes).ok();
    match text.and_then(|t| t.find("-----BEGIN CERTIFICATE-----")) {
        Some(begin) => {
            let text = &text.unwrap()[begin + 27..];
            let end = text.find("-----END CERTIFICATE-----").expect("PEM end");
            let body: String = text[..end].chars().filter(|c| !c.is_whitespace()).collect();
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                .expect("PEM base64")
        }
        None => bytes,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(ca_path) = args.next() else {
        eprintln!("usage: verify <ca-certificate> <certificate>...");
        std::process::exit(2);
    };
    // The CA certificate is trusted on input here, the way a trust anchor
    // store would ship it. Its signature (typically "unsigned") is not checked.
    let ca = CaTrust::from_ca_certificate(&read_certificate(&ca_path)).expect("CA certificate");
    let mut store = TrustStore::new();
    store.add_ca(ca);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let mut failed = false;
    for path in args {
        let der = read_certificate(&path);
        match verify_certificate(&store, &der, Some(now)) {
            Ok(verification) => {
                let kind = match verification.kind {
                    VerificationKind::Standalone => "standalone",
                    VerificationKind::LandmarkRelative => "landmark-relative",
                };
                println!(
                    "{path}: OK ({kind}, log {}, entry {})",
                    verification.log_number, verification.entry_index
                );
            }
            Err(error) => {
                failed = true;
                println!("{path}: {error}");
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
