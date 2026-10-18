//! Print the MTCProof embedded in a Merkle Tree certificate (base layer only:
//! no cosignature verification). Accepts DER or PEM input.
//!
//! Usage: cargo run --no-default-features --example inspect_proof -- cert.pem

use mtcs::{MtcProof, TrustAnchorId};

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
    let Some(path) = args.next() else {
        eprintln!("usage: inspect_proof <certificate.der|pem>");
        std::process::exit(2);
    };
    let der = read_certificate(&path);
    let proof = MtcProof::from_certificate(&der).expect("parse MTCProof");
    println!("subtree: [{}, {})", proof.subtree.start, proof.subtree.end);
    println!("entry extensions: {}", proof.entry_extensions.len());
    println!(
        "inclusion proof: {} bytes ({} hashes)",
        proof.inclusion_proof.len(),
        proof.inclusion_proof.len() / 32
    );
    for (i, hash) in proof.inclusion_proof.chunks(32).enumerate() {
        println!("  proof[{i}]: {}", hex::encode(hash));
    }
    for cosignature in &proof.cosignatures {
        let id = TrustAnchorId::from_binary(&cosignature.cosigner_id)
            .map(|id| id.to_dotted())
            .unwrap_or_else(|_| hex::encode(&cosignature.cosigner_id));
        println!(
            "cosigner {id}: {} signature bytes",
            cosignature.signature.len()
        );
    }
}
