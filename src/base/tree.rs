//! Merkle subtree primitives (draft Section 4 and Appendix B), SHA-256 profile.

use sha2::Digest;

/// The hash output size of the SHA-256 tree profile, in bytes.
pub const HASH_SIZE: usize = 32;

/// A Merkle subtree interval `[start, end)` (Section 4.1 of the draft).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subtree {
    /// First entry index contained in the subtree.
    pub start: u64,
    /// One past the last entry index contained in the subtree.
    pub end: u64,
}

impl Subtree {
    /// Construct a subtree after validating the interval; see [`is_valid_subtree`].
    pub fn new(start: u64, end: u64) -> Option<Self> {
        is_valid_subtree(start, end).then_some(Self { start, end })
    }

    /// The number of entries in the subtree.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the subtree contains `index`.
    pub fn contains(&self, index: u64) -> bool {
        self.start <= index && index < self.end
    }
}

/// Whether `[start, end)` is a valid subtree: `start <= end` and `start` is a
/// multiple of `BIT_CEIL(end - start)` (Section 4.1 of the draft).
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }
    // u128 arithmetic avoids the fixed-width overflow the draft warns about.
    let size = u128::from(end - start);
    u128::from(start) % size.next_power_of_two() == 0
}

/// The RFC 9162 leaf hash `SHA-256(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = sha2::Sha256::new();
    hasher.update([0x00]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// The RFC 9162 interior node hash `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = sha2::Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn chunks(proof: &[u8]) -> Option<impl Iterator<Item = &[u8; HASH_SIZE]>> {
    if !proof.len().is_multiple_of(HASH_SIZE) {
        return None;
    }
    Some(proof.as_chunks::<HASH_SIZE>().0.iter().map(|c| {
        <&[u8; HASH_SIZE]>::try_from(&c[..]).unwrap_or_else(|_| unreachable!("chunk size"))
    }))
}

/// Evaluate a subtree inclusion proof (Section 4.3.2 of the draft), returning
/// the expected hash of the subtree `[start, end)`. Returns None on failure.
pub fn evaluate_inclusion_proof(
    proof: &[u8],
    index: u64,
    entry_hash: &[u8; HASH_SIZE],
    subtree: Subtree,
) -> Option<[u8; HASH_SIZE]> {
    if !subtree.contains(index) {
        return None;
    }
    let mut fn_ = index - subtree.start;
    let mut sn = subtree.end - subtree.start - 1;
    let mut r = *entry_hash;
    for p in chunks(proof)? {
        if sn == 0 {
            return None;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    (sn == 0).then_some(r)
}

/// Verify a subtree consistency proof (Section 4.4.3 of the draft): does the
/// subtree hash `node_hash` of `[start, end)` commit to the same entries as
/// `root_hash` of a tree of size `n`?
pub fn verify_consistency_proof(
    n: u64,
    subtree: Subtree,
    proof: &[u8],
    node_hash: &[u8; HASH_SIZE],
    root_hash: &[u8; HASH_SIZE],
) -> bool {
    let (start, end) = (subtree.start, subtree.end);
    if Subtree::new(start, end).is_none() || end > n {
        return false;
    }
    if start == end {
        let empty: [u8; HASH_SIZE] = sha2::Sha256::digest([]).into();
        return proof.is_empty() && *node_hash == empty;
    }
    let mut fn_ = start;
    let mut sn = end - 1;
    let mut tn = n - 1;
    if sn == tn {
        while fn_ != sn {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    } else {
        while fn_ != sn && sn & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    }
    let mut proof_iter = match chunks(proof) {
        Some(iter) => iter,
        None => return false,
    };
    let (mut fr, mut sr) = if fn_ == sn {
        (*node_hash, *node_hash)
    } else {
        match proof_iter.next() {
            Some(first) => (*first, *first),
            None => return false,
        }
    };
    for c in proof_iter {
        if tn == 0 {
            return false;
        }
        if sn & 1 == 1 || sn == tn {
            if fn_ < sn {
                fr = self::node_hash(c, &fr);
            }
            sr = self::node_hash(c, &sr);
            while sn & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        } else {
            sr = self::node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
        tn >>= 1;
    }
    tn == 0 && fr == *node_hash && sr == *root_hash
}

/// Select the two subtrees that efficiently cover `[start, end)` (Section 4.5.1
/// of the draft). The right subtree ends exactly at `end`; either may be empty.
pub fn covering_subtrees(start: u64, end: u64) -> (Subtree, Subtree) {
    let pair = |left: (u64, u64), right: (u64, u64)| {
        (
            Subtree {
                start: left.0,
                end: left.1,
            },
            Subtree {
                start: right.0,
                end: right.1,
            },
        )
    };
    if end - start <= 1 {
        return pair((start, end), (end, end));
    }
    let last = end - 1;
    let split = 63 - (start ^ last).leading_zeros();
    let mask = (1u64 << split) - 1;
    let mid = last & !mask;
    let inverse = !start & mask;
    let left_split = if inverse == 0 {
        0
    } else {
        u64::from(64 - inverse.leading_zeros())
    };
    let left_start = start & !((1u64 << left_split) - 1);
    pair((left_start, mid), (mid, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(entries: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        let mut levels = vec![entries.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let mut next = Vec::new();
            let mut bottom = levels.last().unwrap().iter();
            loop {
                match (bottom.next(), bottom.next()) {
                    (Some(l), Some(r)) => next.push(node_hash(l, r)),
                    (Some(l), None) => next.push(*l),
                    _ => break,
                }
            }
            levels.push(next);
        }
        levels
    }

    fn subtree_hash(levels: &[Vec<[u8; 32]>], start: u64, end: u64) -> [u8; 32] {
        // Reference: recompute over the leaf range directly.
        let mut hashes: Vec<[u8; 32]> = (start..end).map(|i| levels[0][i as usize]).collect();
        if hashes.is_empty() {
            return sha2::Sha256::digest([]).into();
        }
        while hashes.len() > 1 {
            let mut next = Vec::new();
            let mut it = hashes.into_iter();
            loop {
                match (it.next(), it.next()) {
                    (Some(l), Some(r)) => next.push(node_hash(&l, &r)),
                    (Some(l), None) => next.push(l),
                    _ => break,
                }
            }
            hashes = next;
        }
        hashes[0]
    }

    #[test]
    fn subtree_validity_follows_the_draft() {
        assert!(is_valid_subtree(0, 0));
        assert!(is_valid_subtree(4, 8));
        assert!(is_valid_subtree(8, 13));
        assert!(is_valid_subtree(2, 3)); // Size one: every index is aligned.
        assert!(is_valid_subtree(2, 4));
        assert!(!is_valid_subtree(7, 9));
        assert!(!is_valid_subtree(3, 5)); // Size two at an odd offset.
        assert!(is_valid_subtree(0, u64::MAX));
        assert!(!is_valid_subtree(5, 4));
    }

    #[test]
    fn inclusion_proofs_evaluate_against_reference_hashes() {
        let entries: Vec<[u8; 32]> = (0u8..13)
            .map(|i| leaf_hash(&vec![i; i as usize + 1]))
            .collect();
        let levels = tree(&entries);
        for start in 0..=12u64 {
            for end in start..=13u64 {
                let Some(subtree) = Subtree::new(start, end) else {
                    continue;
                };
                if start == end {
                    continue;
                }
                for index in start..end {
                    // Generate the proof by hand from the subtree leaves.
                    let leaves = &entries[start as usize..end as usize];
                    let proof = reference_inclusion_proof(leaves, index - start);
                    let expected = subtree_hash(&levels, start, end);
                    assert_eq!(
                        evaluate_inclusion_proof(&proof, index, &entries[index as usize], subtree),
                        Some(expected),
                        "[{start}, {end}) index {index}"
                    );
                    // A damaged proof must not evaluate to the subtree hash.
                    if !proof.is_empty() {
                        let mut broken = proof.clone();
                        broken[0] ^= 1;
                        assert_ne!(
                            evaluate_inclusion_proof(
                                &broken,
                                index,
                                &entries[index as usize],
                                subtree
                            ),
                            Some(expected)
                        );
                    }
                }
            }
        }
    }

    fn reference_inclusion_proof(leaves: &[[u8; 32]], index: u64) -> Vec<u8> {
        // RFC 9162 PATH(m, D_n) computed over explicit levels.
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let mut next = Vec::new();
            let mut it = levels.last().unwrap().iter();
            loop {
                match (it.next(), it.next()) {
                    (Some(l), Some(r)) => next.push(node_hash(l, r)),
                    (Some(l), None) => next.push(*l),
                    _ => break,
                }
            }
            levels.push(next);
        }
        let mut proof = Vec::new();
        let mut m = index as usize;
        for level in levels.iter().take_while(|l| l.len() > 1) {
            let neighbor = m ^ 1;
            if neighbor < level.len() {
                proof.extend_from_slice(&level[neighbor]);
            }
            m >>= 1;
        }
        proof
    }

    #[test]
    fn covering_subtrees_match_the_drafts_examples() {
        // Section 4.4 Figure 1 style example: [5, 13) -> [4, 8) + [8, 13).
        assert_eq!(
            covering_subtrees(5, 13),
            (Subtree { start: 4, end: 8 }, Subtree { start: 8, end: 13 })
        );
        // Single-element and empty intervals.
        assert_eq!(
            covering_subtrees(7, 8),
            (Subtree { start: 7, end: 8 }, Subtree { start: 8, end: 8 })
        );
        assert_eq!(
            covering_subtrees(9, 9),
            (Subtree { start: 9, end: 9 }, Subtree { start: 9, end: 9 })
        );
        // [7, 9) in a large tree -> [7, 8) + [8, 9).
        assert_eq!(
            covering_subtrees(7, 9),
            (Subtree { start: 7, end: 8 }, Subtree { start: 8, end: 9 })
        );
    }

    #[test]
    fn covering_subtrees_are_valid_and_cover() {
        for start in [0u64, 1, 5, 7, 63, 1023] {
            for size in [0u64, 1, 2, 3, 17, 100] {
                let end = start + size;
                let (left, right) = covering_subtrees(start, end);
                assert_eq!(Subtree::new(left.start, left.end), Some(left));
                assert_eq!(Subtree::new(right.start, right.end), Some(right));
                assert!(left.start <= start && end == right.end);
                assert!(left.end == right.start);
            }
        }
    }
}
