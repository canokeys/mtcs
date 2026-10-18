//! End-to-end verification against the PLANTS WG demo corpus
//! (ietf-plants-wg/merkle-tree-certs, demo/mtc.json, "plants-07").
//! The demo's own `verify` subcommand agrees with the expectations below.

use mtcs::{
    verify_certificate, CaTrust, CosignerInfo, Error, SignatureAlgorithm, TrustAnchorId,
    TrustStore, TrustedSubtree, VerificationKind,
};

mod keys;

const STANDALONE: &[u8] = include_bytes!("fixtures/standalone.der");
const STANDALONE_CA_ONLY: &[u8] = include_bytes!("fixtures/standalone_ca_only.der");
const UNUSED_BIT_BAD: &[u8] = include_bytes!("fixtures/unused_bit_bad.der");
const BITFLIP_BAD: &[u8] = include_bytes!("fixtures/bitflip_bad.der");
const LANDMARK_32: &[u8] = include_bytes!("fixtures/landmark_32.der");
const LANDMARK_2121: &[u8] = include_bytes!("fixtures/landmark_2121.der");
const CA: &[u8] = include_bytes!("fixtures/ca.der");

const NOT_BEFORE: i64 = 1577836800; // 2020-01-01T00:00:00Z
const NOT_AFTER: i64 = 1924991999; // 2030-12-31T23:59:59Z
const NOW: i64 = 1735689600; // 2025-01-01T00:00:00Z

fn id(dotted: &str) -> TrustAnchorId {
    TrustAnchorId::from_dotted(dotted).unwrap()
}

fn cosigner(dotted: &str, algorithm: SignatureAlgorithm, spki_hex: &str) -> CosignerInfo {
    CosignerInfo {
        id: id(dotted),
        algorithm,
        spki_der: hex::decode(spki_hex).unwrap(),
    }
}

fn store() -> TrustStore {
    let mut store = TrustStore::new();
    store.add_ca(CaTrust::from_ca_certificate(CA).unwrap());
    store
}

fn hash(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

#[test]
fn standalone_certificate_verifies_with_ca_cosignature_only() {
    let store = store();
    let verification = verify_certificate(&store, STANDALONE, Some(NOW)).unwrap();
    assert_eq!(verification.kind, VerificationKind::Standalone);
    assert_eq!(verification.ca_id, id("32473.1"));
    assert_eq!((verification.log_number, verification.entry_index), (1, 10));
    assert!(verification.satisfied_cosigners.contains(&id("32473.1")));
    // The certificate also carries 32473.2.1 (P-256) and 32473.2.2 (ML-DSA-65),
    // which are unrecognized by this trust store and therefore ignored.
    assert_eq!(verification.satisfied_cosigners.len(), 1);

    let verification = verify_certificate(&store, STANDALONE_CA_ONLY, Some(NOW)).unwrap();
    assert_eq!(verification.kind, VerificationKind::Standalone);
    assert_eq!(verification.satisfied_cosigners, [id("32473.1")]);
}

#[test]
fn additional_required_cosigners_are_enforced() {
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.require_cosigner(cosigner(
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    ));
    ca.require_cosigner(cosigner(
        "32473.2.2",
        SignatureAlgorithm::MlDsa65,
        keys::C_32473_2_2,
    ));
    let mut with_extras = TrustStore::new();
    with_extras.add_ca(ca);

    // cert_10_0 carries CA + 32473.2.1 + 32473.2.2: satisfied.
    let verification = verify_certificate(&with_extras, STANDALONE, Some(NOW)).unwrap();
    assert_eq!(verification.satisfied_cosigners.len(), 3);
    // cert_10_3 carries only the CA cosignature: the two extra requirements fail.
    assert_eq!(
        verify_certificate(&with_extras, STANDALONE_CA_ONLY, Some(NOW)),
        Err(Error::PolicyUnsatisfied)
    );

    // A global requirement applies across CAs.
    let mut strict = store();
    strict.required_for_all.push(cosigner(
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    ));
    assert!(verify_certificate(&strict, STANDALONE, Some(NOW)).is_ok());
    assert_eq!(
        verify_certificate(&strict, STANDALONE_CA_ONLY, Some(NOW)),
        Err(Error::PolicyUnsatisfied)
    );
}

#[test]
fn tampered_and_misencoded_certificates_fail() {
    let store = store();
    // A flipped bit in the inclusion proof changes the subtree hash, so the
    // CA cosignature no longer verifies.
    assert_eq!(
        verify_certificate(&store, BITFLIP_BAD, Some(NOW)),
        Err(Error::InvalidCosignature(id("32473.1")))
    );
    // A signature BIT STRING with a nonzero unused-bit count is not an MTCProof.
    assert!(matches!(
        verify_certificate(&store, UNUSED_BIT_BAD, Some(NOW)),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn revocation_validity_and_ca_membership_are_checked() {
    let store = store();
    // Revoke entry 10's exact serial (log 1, index 10).
    let mut revoked = store.clone();
    revoked.cas[0].revoke_range(1 << 48 | 10, 1 << 48 | 10);
    assert_eq!(
        verify_certificate(&revoked, STANDALONE, Some(NOW)),
        Err(Error::Revoked)
    );
    // The CA certificate's own bounds revoke everything above log 5.
    let mut cert = STANDALONE.to_vec();
    // Bump the serial's log number byte (0x07 01 00... -> log 6).
    let pos = cert.windows(2).position(|w| w == [0x02, 0x07]).unwrap();
    assert_eq!(cert[pos + 2], 1);
    cert[pos + 2] = 6;
    assert_eq!(
        verify_certificate(&store, &cert, Some(NOW)),
        Err(Error::Revoked)
    );
    // Validity is evaluated against the caller's timestamp.
    assert_eq!(
        verify_certificate(&store, STANDALONE, Some(NOT_BEFORE - 1)),
        Err(Error::TimeInvalid)
    );
    assert_eq!(
        verify_certificate(&store, STANDALONE, Some(NOT_AFTER + 1)),
        Err(Error::TimeInvalid)
    );
    assert!(verify_certificate(&store, STANDALONE, None).is_ok());
    assert_eq!(
        verify_certificate(&TrustStore::new(), STANDALONE, Some(NOW)),
        Err(Error::UnknownCa)
    );
}

#[test]
fn non_mtc_certificates_are_rejected() {
    // An ordinary directly-signed ECDSA certificate.
    let der = pem_der(include_bytes!("fixtures/plain.pem"));
    assert_eq!(
        verify_certificate(&store(), &der, Some(NOW)),
        Err(Error::NotMtc)
    );
}

fn pem_der(pem: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(pem).unwrap();
    let start = text.find("-----BEGIN CERTIFICATE-----").unwrap() + 27;
    let end = text.find("-----END CERTIFICATE-----").unwrap();
    let body: String = text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

#[test]
fn landmark_relative_certificates_verify_against_trusted_subtrees() {
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.trust_subtree(TrustedSubtree {
        log_number: 1,
        start: 32,
        end: 34,
        hash: hash(keys::SUBTREE_32_34),
    });
    ca.trust_subtree(TrustedSubtree {
        log_number: 1,
        start: 2048,
        end: 2122,
        hash: hash(keys::SUBTREE_2048_2122),
    });
    let mut with_subtrees = TrustStore::new();
    with_subtrees.add_ca(ca);

    let verification = verify_certificate(&with_subtrees, LANDMARK_32, Some(NOW)).unwrap();
    assert_eq!(verification.kind, VerificationKind::LandmarkRelative);
    assert_eq!((verification.log_number, verification.entry_index), (1, 32));
    assert!(verification.satisfied_cosigners.is_empty());

    let verification = verify_certificate(&with_subtrees, LANDMARK_2121, Some(NOW)).unwrap();
    assert_eq!(verification.kind, VerificationKind::LandmarkRelative);
    assert_eq!(
        (verification.log_number, verification.entry_index),
        (1, 2121)
    );

    // A wrong trusted subtree hash fails verification outright (no fallback).
    let mut wrong = with_subtrees.clone();
    wrong.cas[0].trusted_subtrees[0].hash[0] ^= 1;
    assert_eq!(
        verify_certificate(&wrong, LANDMARK_32, Some(NOW)),
        Err(Error::ProofEvaluation)
    );
    // Without the trusted subtree, a signatureless certificate cannot verify.
    assert_eq!(
        verify_certificate(&store(), LANDMARK_32, Some(NOW)),
        Err(Error::PolicyUnsatisfied)
    );
}

#[test]
fn ca_certificate_parses_into_trust_configuration() {
    let ca = CaTrust::from_ca_certificate(CA).unwrap();
    assert_eq!(ca.ca_id, id("32473.1"));
    assert_eq!(ca.ca_cosigner.algorithm, SignatureAlgorithm::MlDsa44);
    assert_eq!(ca.ca_cosigner.id, ca.ca_id);
    assert_eq!(
        ca.ca_cosigner.spki_der,
        hex::decode(keys::C_32473_1).unwrap()
    );
    // Bounds from the demo config: [0, 2^48) and ((5<<48)|(2^48-1), u64::MAX].
    assert_eq!(ca.revoked_ranges.len(), 2);
    assert_eq!(ca.revoked_ranges[0], 0..=(1 << 48) - 1);
    assert_eq!(
        ca.revoked_ranges[1],
        ((5 << 48) | 0xffff_ffff_ffff) + 1..=u64::MAX
    );
}
