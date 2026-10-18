//! Machine-readable test vectors from the IETF PLANTS WG demo
//! (ietf-plants-wg/merkle-tree-certs, demo/large_{inclusion,consistency}_proofs.json).
//! These are the draft's large-subtree vectors: trees of ~2^48 entries, so the
//! proofs exercise multi-level path handling that small hand-built trees miss.

use base64::Engine as _;
use mtcs::{Subtree, evaluate_inclusion_proof, verify_consistency_proof};

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

fn hash(text: &str) -> [u8; 32] {
    b64(text).try_into().unwrap()
}

#[derive(serde::Deserialize)]
struct InclusionVector {
    #[serde(rename = "Index")]
    index: String,
    #[serde(rename = "Start")]
    start: String,
    #[serde(rename = "End")]
    end: String,
    #[serde(rename = "EntryHash")]
    entry_hash: String,
    #[serde(rename = "SubtreeHash")]
    subtree_hash: String,
    #[serde(rename = "Proof")]
    proof: String,
}

#[derive(serde::Deserialize)]
struct ConsistencyVector {
    #[serde(rename = "Start")]
    start: String,
    #[serde(rename = "End")]
    end: String,
    #[serde(rename = "TreeSize")]
    tree_size: String,
    #[serde(rename = "SubtreeHash")]
    subtree_hash: String,
    #[serde(rename = "TreeHash")]
    tree_hash: String,
    #[serde(rename = "Proof")]
    proof: String,
}

#[test]
fn large_inclusion_proof_vectors() {
    let vectors: Vec<InclusionVector> = serde_json::from_str(include_str!(
        "fixtures/large_inclusion_proofs.json"
    ))
    .unwrap();
    assert!(vectors.len() >= 24);
    for v in &vectors {
        let (index, start, end) = (
            v.index.parse().unwrap(),
            v.start.parse().unwrap(),
            v.end.parse().unwrap(),
        );
        let subtree = Subtree::new(start, end).unwrap();
        let proof = b64(&v.proof);
        let expected = Some(hash(&v.subtree_hash));
        assert_eq!(
            evaluate_inclusion_proof(&proof, index, &hash(&v.entry_hash), subtree),
            expected,
            "[{start}, {end}) index {index}"
        );
        // A damaged proof must not evaluate to the subtree hash.
        let mut broken = proof.clone();
        broken[0] ^= 1;
        assert_ne!(
            evaluate_inclusion_proof(&broken, index, &hash(&v.entry_hash), subtree),
            expected
        );
        // An out-of-range index fails evaluation entirely.
        if end < u64::MAX {
            assert_eq!(
                evaluate_inclusion_proof(&proof, end, &hash(&v.entry_hash), subtree),
                None
            );
        }
    }
}

#[test]
fn large_consistency_proof_vectors() {
    let vectors: Vec<ConsistencyVector> = serde_json::from_str(include_str!(
        "fixtures/large_consistency_proofs.json"
    ))
    .unwrap();
    assert!(vectors.len() >= 21);
    for v in &vectors {
        let (start, end, tree_size) = (
            v.start.parse().unwrap(),
            v.end.parse().unwrap(),
            v.tree_size.parse().unwrap(),
        );
        let subtree = Subtree::new(start, end).unwrap();
        let (node_hash, root_hash) = (hash(&v.subtree_hash), hash(&v.tree_hash));
        let proof = b64(&v.proof);
        assert!(
            verify_consistency_proof(tree_size, subtree, &proof, &node_hash, &root_hash),
            "[{start}, {end}) in {tree_size}"
        );
        // A wrong root hash must fail. Empty subtrees are trivially consistent
        // with any root (Section 4.4.3 step 2), so this check only applies to
        // non-empty subtrees.
        if start != end {
            let mut wrong_root = root_hash;
            wrong_root[0] ^= 1;
            assert!(!verify_consistency_proof(
                tree_size, subtree, &proof, &node_hash, &wrong_root
            ));
        }
        // A damaged proof must fail (when it can carry damage).
        if !proof.is_empty() {
            let mut broken = proof.clone();
            broken[0] ^= 1;
            assert!(!verify_consistency_proof(tree_size, subtree, &broken, &node_hash, &root_hash));
        }
        // A subtree hash that does not match the tree must fail.
        let mut wrong_node = node_hash;
        wrong_node[0] ^= 1;
        assert!(!verify_consistency_proof(tree_size, subtree, &proof, &wrong_node, &root_hash));
    }
}

#[test]
fn consistency_proofs_reject_malformed_inputs() {
    let hash = [7u8; 32];
    let subtree = Subtree::new(0, 8).unwrap();
    // Proof not a multiple of the hash size.
    assert!(!verify_consistency_proof(8, subtree, &[0; 33], &hash, &hash));
    // Tree smaller than the subtree end.
    assert!(!verify_consistency_proof(4, subtree, &[], &hash, &hash));
    // Empty subtrees only verify against the empty hash with an empty proof.
    let empty = Subtree::new(3, 3).unwrap();
    assert!(!verify_consistency_proof(8, empty, &[], &hash, &hash));
}
