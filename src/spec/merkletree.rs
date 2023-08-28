/*
    Custom implementation for Bitcoin Transaction Tree

    1- Hash algorithm is sha256d from bitcoin package
    2- Odd leaves are duplicated for each level except root
      From bitcoin-core:
       The reason is that if the number of hashes in the list at a given level
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:

                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

    3- It should be able to generate serialized proof for inclusion of a transactions
    4- It should be able to verify a serialized proof for inclusion of a transactions
    5- Leaves are serialized as [u8; 32] (32 bytes)
*/
use bitcoin::hashes::{sha256d, Hash};

#[derive(Debug, Clone)]
pub struct BitcoinMerkleTree {
    root: Option<[u8; 32]>,
    leaves: Vec<[u8; 32]>,
}

impl Default for BitcoinMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BitcoinMerkleTree {
    pub fn new() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
        }
    }

    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let mut tree = Self::new();
        tree.leaves = leaves;
        tree.compute_tree();
        tree
    }

    pub fn compute_tree(&mut self) {
        let mut hashes = self.leaves.clone();
        while hashes.len() > 1 {
            hashes = self.next_level(hashes);
        }
        self.root = hashes.first().cloned();
    }

    fn next_level(&self, hashes: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        let mut next_level = Vec::new();
        for pair in hashes.chunks(2) {
            let mut data = vec![];
            let left_pair = pair[0];
            let right_pair = pair.get(1).unwrap_or(&left_pair);

            data.extend_from_slice(&left_pair);
            data.extend_from_slice(right_pair);

            let hash = sha256d::Hash::hash(&data);
            next_level.push(hash.into_inner());
        }
        next_level
    }

    pub fn get_root(&self) -> Option<[u8; 32]> {
        self.root
    }

    pub fn get_proof(&self, index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut idx = index;

        path.push(current_level[index]);

        while current_level.len() > 1 {
            if current_level.len() % 2 == 1 {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }

            let pair_idx = idx / 2;
            let pair = &current_level[pair_idx * 2..pair_idx * 2 + 2];
            let sibling = if pair.len() > 1 && idx % 2 == 0 {
                pair[1]
            } else {
                pair[0]
            };
            path.push(sibling);
            current_level = self.next_level(current_level);
            idx /= 2;
        }

        path
    }

    pub fn verify_proof(root: [u8; 32], proof: &[[u8; 32]], index: usize) -> bool {
        let mut computed_hash = proof[0];
        let mut idx = index;

        for sibling in &proof[1..] {
            let mut data = vec![];
            if idx % 2 == 0 {
                data.extend_from_slice(&computed_hash);
                data.extend_from_slice(sibling);
            } else {
                data.extend_from_slice(sibling);
                data.extend_from_slice(&computed_hash);
            }
            computed_hash = sha256d::Hash::hash(&data).into_inner();
            idx /= 2;
        }

        computed_hash == root
    }
}
