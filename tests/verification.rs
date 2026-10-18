//! End-to-end verification against the PLANTS WG demo corpus
//! (ietf-plants-wg/merkle-tree-certs, demo/mtc.json, "plants-07").
//! The demo's own `verify` subcommand agrees with the expectations below.

use mtcs::{
    CaTrust, CosignerGroup, CosignerInfo, Error, SignatureAlgorithm, TrustAnchorId, TrustStore,
    TrustedSubtree, VerificationKind, verify_certificate, verify_certificate_ignoring_validity,
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
    let verification = verify_certificate(&store, STANDALONE, NOW).unwrap();
    assert_eq!(verification.kind, VerificationKind::Standalone);
    assert_eq!(verification.ca_id, id("32473.1"));
    assert_eq!((verification.log_number, verification.entry_index), (1, 10));
    assert!(verification.satisfied_cosigners.contains(&id("32473.1")));
    // The certificate also carries 32473.2.1 (P-256) and 32473.2.2 (ML-DSA-65),
    // which are unrecognized by this trust store and therefore ignored.
    assert_eq!(verification.satisfied_cosigners.len(), 1);

    let verification = verify_certificate(&store, STANDALONE_CA_ONLY, NOW).unwrap();
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
    let verification = verify_certificate(&with_extras, STANDALONE, NOW).unwrap();
    assert_eq!(verification.satisfied_cosigners.len(), 3);
    // cert_10_3 carries only the CA cosignature: the two extra requirements fail.
    assert!(matches!(
        verify_certificate(&with_extras, STANDALONE_CA_ONLY, NOW),
        Err(Error::PolicyUnsatisfied { .. })
    ));

    // A global requirement applies across CAs.
    let mut strict = store();
    strict.required_for_all.push(CosignerGroup::single(cosigner(
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    )));
    assert!(verify_certificate(&strict, STANDALONE, NOW).is_ok());
    assert!(matches!(
        verify_certificate(&strict, STANDALONE_CA_ONLY, NOW),
        Err(Error::PolicyUnsatisfied { .. })
    ));
}

#[test]
fn tampered_and_misencoded_certificates_fail() {
    let store = store();
    // A flipped bit in the inclusion proof changes the subtree hash, so the
    // CA cosignature no longer verifies.
    assert_eq!(
        verify_certificate(&store, BITFLIP_BAD, NOW),
        Err(Error::InvalidCosignature(id("32473.1")))
    );
    // A signature BIT STRING with a nonzero unused-bit count is not an MTCProof.
    assert!(matches!(
        verify_certificate(&store, UNUSED_BIT_BAD, NOW),
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
        verify_certificate(&revoked, STANDALONE, NOW),
        Err(Error::Revoked)
    );
    // The CA certificate's own bounds revoke everything above log 5.
    let mut cert = STANDALONE.to_vec();
    // Bump the serial's log number byte (0x07 01 00... -> log 6).
    let pos = cert.windows(2).position(|w| w == [0x02, 0x07]).unwrap();
    assert_eq!(cert[pos + 2], 1);
    cert[pos + 2] = 6;
    assert_eq!(verify_certificate(&store, &cert, NOW), Err(Error::Revoked));
    // Validity is evaluated against the caller's timestamp.
    assert_eq!(
        verify_certificate(&store, STANDALONE, NOT_BEFORE - 1),
        Err(Error::TimeInvalid)
    );
    assert_eq!(
        verify_certificate(&store, STANDALONE, NOT_AFTER + 1),
        Err(Error::TimeInvalid)
    );
    assert!(verify_certificate_ignoring_validity(&store, STANDALONE).is_ok());
    assert_eq!(
        verify_certificate(&TrustStore::new(), STANDALONE, NOW),
        Err(Error::UnknownCa)
    );
}

#[test]
fn non_mtc_certificates_are_rejected() {
    // An ordinary directly-signed ECDSA certificate.
    let der = pem_der(include_bytes!("fixtures/plain.pem"));
    assert_eq!(verify_certificate(&store(), &der, NOW), Err(Error::NotMtc));
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

    let verification = verify_certificate(&with_subtrees, LANDMARK_32, NOW).unwrap();
    assert_eq!(verification.kind, VerificationKind::LandmarkRelative);
    assert_eq!((verification.log_number, verification.entry_index), (1, 32));
    assert!(verification.satisfied_cosigners.is_empty());

    let verification = verify_certificate(&with_subtrees, LANDMARK_2121, NOW).unwrap();
    assert_eq!(verification.kind, VerificationKind::LandmarkRelative);
    assert_eq!(
        (verification.log_number, verification.entry_index),
        (1, 2121)
    );

    // A wrong trusted subtree hash fails verification outright (no fallback).
    let mut wrong = with_subtrees.clone();
    wrong.cas[0].trusted_subtrees[0].hash[0] ^= 1;
    assert_eq!(
        verify_certificate(&wrong, LANDMARK_32, NOW),
        Err(Error::ProofEvaluation)
    );
    // Without the trusted subtree, a signatureless certificate cannot verify.
    assert!(matches!(
        verify_certificate(&store(), LANDMARK_32, NOW),
        Err(Error::PolicyUnsatisfied { .. })
    ));
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

#[test]
fn cosigner_groups_support_k_of_n_quorums() {
    // The standalone fixture carries CA + 32473.2.1 (P-256) + 32473.2.2 (ML-DSA-65).
    let p256 = cosigner(
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    );
    let mldsa65 = cosigner("32473.2.2", SignatureAlgorithm::MlDsa65, keys::C_32473_2_2);
    let absent = cosigner("32473.2.3", SignatureAlgorithm::MlDsa87, keys::C_32473_2_3);

    // 1-of-2 over the two witnesses passes.
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.require_group(CosignerGroup::new(vec![p256.clone(), mldsa65.clone()], 1).unwrap());
    // 2-of-2 over the two witnesses passes (both cosignatures are present).
    ca.require_group(CosignerGroup::new(vec![p256.clone(), mldsa65.clone()], 2).unwrap());
    let mut store = TrustStore::new();
    store.add_ca(ca);
    let verification = verify_certificate(&store, STANDALONE, NOW).unwrap();
    assert_eq!(verification.satisfied_cosigners.len(), 3);

    // 2-of-2 against the CA-only certificate fails, naming the absent members.
    let Err(Error::PolicyUnsatisfied { missing, invalid }) =
        verify_certificate(&store, STANDALONE_CA_ONLY, NOW)
    else {
        panic!("expected PolicyUnsatisfied")
    };
    assert!(missing.contains(&id("32473.2.1")) && missing.contains(&id("32473.2.2")));
    assert!(invalid.is_empty());

    // A group whose members are all absent from the certificate fails.
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.require_group(CosignerGroup::new(vec![absent.clone()], 1).unwrap());
    let mut store = TrustStore::new();
    store.add_ca(ca);
    let Err(Error::PolicyUnsatisfied { missing, .. }) = verify_certificate(&store, STANDALONE, NOW)
    else {
        panic!("expected PolicyUnsatisfied")
    };
    assert_eq!(missing, [id("32473.2.3")]);
}

#[test]
fn cosigner_groups_validate_their_threshold() {
    let member = cosigner(
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    );
    assert!(CosignerGroup::new(vec![member.clone()], 0).is_err());
    assert!(CosignerGroup::new(vec![member.clone()], 2).is_err());
    assert!(CosignerGroup::new(vec![], 1).is_err());
    assert!(CosignerGroup::new(vec![member], 1).is_ok());
}

#[test]
fn trust_store_and_cosignature_failures_are_distinguished() {
    // A malformed SPKI is a trust-store misconfiguration, not a bad certificate.
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.require_cosigner(CosignerInfo {
        id: id("32473.2.1"),
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        spki_der: vec![0x30, 0x03, 0x06, 0x01, 0x00], // truncated SPKI
    });
    let mut store = TrustStore::new();
    store.add_ca(ca);
    assert!(matches!(
        verify_certificate(&store, STANDALONE, NOW),
        Err(Error::UnsupportedKey(_))
    ));

    // A present-but-invalid cosignature lands in `invalid`, not `missing`.
    let mut wrong_spki = hex::decode(keys::C_32473_2_2).unwrap();
    let last = wrong_spki.len() - 1;
    wrong_spki[last] ^= 1; // Same length, wrong ML-DSA-65 key material.
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.require_cosigner(CosignerInfo {
        id: id("32473.2.2"),
        algorithm: SignatureAlgorithm::MlDsa65,
        spki_der: wrong_spki,
    });
    let mut store = TrustStore::new();
    store.add_ca(ca);
    let Err(Error::PolicyUnsatisfied { missing, invalid }) =
        verify_certificate(&store, STANDALONE, NOW)
    else {
        panic!("expected PolicyUnsatisfied")
    };
    assert_eq!(invalid, [id("32473.2.2")]);
    assert!(!missing.contains(&id("32473.2.2")));
}

#[test]
fn verification_exposes_the_subtree_and_its_hash() {
    let mut ca = CaTrust::from_ca_certificate(CA).unwrap();
    ca.trust_subtree(TrustedSubtree {
        log_number: 1,
        start: 32,
        end: 34,
        hash: hash(keys::SUBTREE_32_34),
    });
    let mut store = TrustStore::new();
    store.add_ca(ca);
    let verification = verify_certificate(&store, LANDMARK_32, NOW).unwrap();
    assert_eq!(verification.subtree, mtcs::Subtree { start: 32, end: 34 });
    assert_eq!(verification.subtree_hash, hash(keys::SUBTREE_32_34));
}

#[test]
fn ca_certificate_profile_is_enforced() {
    // Section 5.5: critical MTC CA extension, cA = TRUE, keyCertSign asserted.
    let mut not_critical = CA.to_vec();
    let needle = hex::decode("06082b0601050507012601 01ff".replace(' ', "")).unwrap();
    let pos = not_critical
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .unwrap();
    let last = pos + needle.len() - 1;
    not_critical[last] = 0x00; // critical: FALSE
    assert!(CaTrust::from_ca_certificate(&not_critical).is_err());

    let mut not_ca = CA.to_vec();
    let needle = hex::decode("0603551d13").unwrap();
    let pos = not_ca
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .unwrap();
    // The cA BOOLEAN is the last 01 01 ff within this extension.
    let window_end = pos + 20;
    let inner = not_ca[pos..window_end]
        .windows(3)
        .rposition(|w| w == [0x01, 0x01, 0xff])
        .unwrap();
    not_ca[pos + inner + 2] = 0x00; // cA = FALSE
    assert!(CaTrust::from_ca_certificate(&not_ca).is_err());

    let mut no_cert_sign = CA.to_vec();
    let needle = hex::decode("0603551d0f").unwrap();
    let pos = no_cert_sign
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .unwrap();
    let window_end = pos + 20;
    let inner = no_cert_sign[pos..window_end]
        .windows(4)
        .position(|w| w == [0x03, 0x02, 0x02, 0x04])
        .unwrap();
    no_cert_sign[pos + inner + 3] = 0x40; // nonRepudiation instead of keyCertSign
    assert!(CaTrust::from_ca_certificate(&no_cert_sign).is_err());
}
