//! Fuzz the verification policy logic with an input-driven trust store.
//!
//! Valid cosignatures cannot be forged by mutation, so the certificate comes
//! from the demo corpus fixtures while every relying-party input is derived
//! from the fuzz input: required cosigner groups (members and thresholds),
//! global groups, revoked serial ranges, trusted subtrees, and the timestamp.
//! This reaches quorum evaluation, missing/invalid diagnostics, revocation,
//! and the decisive trusted-subtree branch.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mtcs::{
    CaTrust, CosignerGroup, CosignerInfo, SignatureAlgorithm, TrustAnchorId, TrustStore,
    TrustedSubtree, verify_certificate,
};

const NOW_BASE: i64 = 1577836800; // 2020-01-01T00:00:00Z, the corpus notBefore.
const CA: &[u8] = include_bytes!("../../tests/fixtures/ca.der");
const CERTS: &[&[u8]] = &[
    include_bytes!("../../tests/fixtures/standalone.der"),
    include_bytes!("../../tests/fixtures/standalone_ca_only.der"),
    include_bytes!("../../tests/fixtures/landmark_32.der"),
    include_bytes!("../../tests/fixtures/landmark_2121.der"),
];

// The demo corpus cosigners: (id, algorithm, SPKI hex). Public material only.
const POOL: &[(&str, SignatureAlgorithm, &str)] = &[
    ("32473.1", SignatureAlgorithm::MlDsa44, keys::C_32473_1),
    (
        "32473.2.1",
        SignatureAlgorithm::EcdsaP256Sha256,
        keys::C_32473_2_1,
    ),
    ("32473.2.2", SignatureAlgorithm::MlDsa65, keys::C_32473_2_2),
    ("32473.2.3", SignatureAlgorithm::MlDsa87, keys::C_32473_2_3),
];

// Single source of truth with tests/keys.rs (tests/keys/).
mod keys {
    pub const C_32473_1: &str = include_str!("../../tests/keys/C_32473_1.hex");
    pub const C_32473_2_1: &str = include_str!("../../tests/keys/C_32473_2_1.hex");
    pub const C_32473_2_2: &str = include_str!("../../tests/keys/C_32473_2_2.hex");
    pub const C_32473_2_3: &str = include_str!("../../tests/keys/C_32473_2_3.hex");
}

#[derive(Arbitrary, Debug)]
struct Spec {
    cert: u8,
    now: i64,
    groups: Vec<GroupSpec>,
    revoked: Vec<(u64, u64)>,
    trusted: Vec<SubtreeSpec>,
}

#[derive(Arbitrary, Debug)]
struct GroupSpec {
    global: bool,
    members: Vec<MemberSpec>,
    threshold: usize,
}

#[derive(Arbitrary, Debug)]
struct MemberSpec {
    key: u8,
    corrupt_key: bool,
    mangle_id: bool,
}

#[derive(Arbitrary, Debug)]
struct SubtreeSpec {
    log_number: u16,
    start: u8,
    end: u8,
    corrupt_hash: bool,
}

fn cosigner(spec: &MemberSpec) -> CosignerInfo {
    let (dotted, algorithm, spki_hex) = POOL[(spec.key % POOL.len() as u8) as usize];
    let mut spki = hex::decode(spki_hex.trim()).expect("key hex");
    if spec.corrupt_key {
        let last = spki.len() - 1;
        spki[last] ^= 1; // Right length, wrong key material.
    }
    let mut id = TrustAnchorId::from_dotted(dotted).expect("id");
    if spec.mangle_id {
        id = id.child(9); // Unrecognized by the certificate.
    }
    CosignerInfo {
        id,
        algorithm,
        spki_der: spki,
    }
}

fuzz_target!(|spec: Spec| {
    let mut ca = CaTrust::from_ca_certificate(CA).expect("fixture CA");
    let ca_id = ca.ca_id.clone();
    // The per-member corrupt_key flags stay next to each pushed group so that
    // first_key below can be rebuilt in the verifier's lookup order.
    let mut added_groups: Vec<(CosignerGroup, Vec<bool>)> = Vec::new();
    let mut global_groups: Vec<(CosignerGroup, Vec<bool>)> = Vec::new();
    let mut trusted_uncorrupted: Vec<(u16, u64, u64)> = Vec::new();
    let mut revoked_ranges: Vec<core::ops::RangeInclusive<u64>> = Vec::new();
    for group_spec in spec.groups.iter().take(8) {
        let members: Vec<(CosignerInfo, bool)> = group_spec
            .members
            .iter()
            .take(8)
            .map(|member| (cosigner(member), member.corrupt_key))
            .collect();
        // Constructor rejections (bad threshold, duplicates) are coverage too.
        let Ok(group) = CosignerGroup::new(
            members.iter().map(|(info, _)| info.clone()).collect(),
            group_spec.threshold,
        ) else {
            continue;
        };
        let corrupted: Vec<bool> = members.iter().map(|(_, corrupted)| *corrupted).collect();
        if group_spec.global {
            global_groups.push((group, corrupted));
        // CA-self rejection is coverage, not a failure of the fuzz run.
        } else if ca.require_group(group.clone()).is_ok() {
            added_groups.push((group, corrupted));
        } else {
            continue;
        }
    }
    // Ground truth for the verdict invariants below, built only after both
    // group lists are final. first_key mirrors the verifier's lookup order in
    // verify.rs: the CA cosigner (always clean; its key comes from the CA
    // certificate), then per-CA groups in insertion order, then global groups.
    // For an ID present in several groups, the first entry is the key the
    // verifier uses; building this in spec order instead would misattribute
    // keys for IDs shared across per-CA and global groups.
    let mut first_key: Vec<(TrustAnchorId, bool)> = vec![(ca_id.clone(), false)];
    for (group, corrupted) in added_groups.iter().chain(&global_groups) {
        for (member, corrupted) in group.members().iter().zip(corrupted) {
            if !first_key.iter().any(|(id, _)| id == &member.id) {
                first_key.push((member.id.clone(), *corrupted));
            }
        }
    }
    for &(first, last) in spec.revoked.iter().take(8) {
        // Dense ranges around the fixture serial numbers.
        let first = (1u64 << 48) + first % 4096;
        let last = first.saturating_add(last % 4096);
        ca.revoke_range(first, last);
        revoked_ranges.push(first..=last);
    }
    for trusted in spec.trusted.iter().take(8) {
        let start = u64::from(trusted.start % 64);
        let end = start + u64::from(trusted.end % 64);
        let mut hash = LANDMARK_32_34;
        if trusted.corrupt_hash {
            hash[0] ^= 1;
        } else {
            trusted_uncorrupted.push((trusted.log_number % 3, start, end));
        }
        ca.trust_subtree(TrustedSubtree {
            log_number: trusted.log_number % 3,
            start,
            end,
            hash,
        });
    }
    let mut store = TrustStore::new();
    store.add_ca(ca);
    for (group, _) in &global_groups {
        store.require_group_for_all(group.clone());
    }
    let all_groups: Vec<_> = added_groups
        .iter()
        .chain(&global_groups)
        .map(|(group, _)| group)
        .collect();
    let cert = CERTS[(spec.cert % CERTS.len() as u8) as usize];
    let now = NOW_BASE + (spec.now.unsigned_abs() % (4 * 365 * 86400)) as i64;
    match verify_certificate(&store, cert, now) {
        Ok(verification) => {
            // Validity window (Section 7.2): the fixtures all cover 2020-2030.
            assert!((1577836800..=1924991999).contains(&now));
            // Revocation (Section 7.5): the verified serial is in no revoked range.
            let serial = (u64::from(verification.log_number) << 48) | verification.entry_index;
            assert!(revoked_ranges.iter().all(|range| !range.contains(&serial)));
            match verification.kind {
                mtcs::VerificationKind::LandmarkRelative => {
                    // The decisive branch must have used an uncorrupted hash.
                    assert!(trusted_uncorrupted.contains(&(
                        verification.log_number,
                        verification.subtree.start,
                        verification.subtree.end
                    )));
                }
                mtcs::VerificationKind::Standalone => {
                    // The CA cosigner always verified (authenticity, Section 7.3).
                    assert!(verification.satisfied_cosigners.contains(&ca_id));
                    for group in &all_groups {
                        let count = verification
                            .satisfied_cosigners
                            .iter()
                            .filter(|id| {
                                **id != ca_id && group.members().iter().any(|m| m.id == **id)
                            })
                            .count();
                        assert!(count >= group.threshold());
                    }
                    // A cosigner ID was satisfied only if its first-seen key
                    // (in lookup order) was clean.
                    for id in &verification.satisfied_cosigners {
                        let (_, corrupted) = first_key
                            .iter()
                            .find(|(first_id, _)| first_id == id)
                            .unwrap();
                        assert!(!corrupted, "satisfied {id} with a corrupted key");
                    }
                }
            }
        }
        Err(mtcs::Error::PolicyUnsatisfied { missing, invalid }) => {
            assert!(missing.iter().all(|id| !invalid.contains(id)));
            for id in &invalid {
                let (_, corrupted) = first_key
                    .iter()
                    .find(|(first_id, _)| first_id == id)
                    .unwrap();
                assert!(corrupted, "invalid {id} had a clean key");
            }
        }
        Err(_) => {}
    }
});

// Landmark 1 of the demo log 1: subtree [32, 34).
const LANDMARK_32_34: [u8; 32] = [
    0x69, 0x0e, 0xeb, 0x2d, 0x3c, 0x23, 0xc0, 0xbb, 0x98, 0x5f, 0xa2, 0x8b, 0x26, 0x91, 0x11, 0x96,
    0x80, 0x50, 0x11, 0x15, 0x52, 0x5a, 0x01, 0x54, 0xc5, 0xc3, 0xa2, 0x48, 0x8c, 0x2f, 0x34, 0xf8,
];
