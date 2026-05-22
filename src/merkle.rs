use std::collections::VecDeque;

use anyhow::{Context, Result};
use ethers::types::H256;
use sqlx::{Pool, Postgres};
use tracing::debug;

use crate::{
    add_batch_tx_to_merkle,
    db::{BatchDb, PostgresBatchDb},
    get_batch_first_priority_op_id, load_l1_batch_with_metadata,
    utils::get_priority_op_merkle_path,
};

/// MiniMerkleTree keeps 'trimming/removing' the leftmost leafs to make it efficient.
/// Start index represents the 'absolute' index of the leftmost leaf.
#[derive(Debug, Clone)]
pub struct MiniMerkleTree {
    pub hashes: VecDeque<H256>,
    pub binary_tree_size: usize,
    // This represents the 'first' index of the tree.
    pub start_index: usize,
    pub cache: Vec<Option<H256>>,
    /// Number of priority ops that existed before the priority tree was introduced.
    /// Fetched on-chain via `getPriorityTreeStartIndex()`.
    pub priority_tree_start_index: usize,
}

impl MiniMerkleTree {
    /// Helper method for priority ops - as we had some priority ops BEFORE we introduced the merkle tree,
    /// we need to add there info to the index to better reflect the next priority op that is supposed to be added.
    pub fn next_priority_op_id(&self) -> usize {
        self.start_index + self.priority_tree_start_index + self.hashes.len()
    }

    pub fn from_start_index_and_proof(start_index: usize, proof: Vec<H256>, priority_tree_start_index: usize) -> Self {
        // Check if not off by one.
        let binary_tree_size = 1 << proof.len();
        debug!(
            "Initializing MiniMerkleTree with start_index {} and binary_tree_size {}",
            start_index, binary_tree_size
        );
        let depth = tree_depth_by_size(binary_tree_size);
        assert_eq!(proof.len(), depth);
        Self {
            hashes: VecDeque::new(),
            binary_tree_size,
            start_index,
            cache: proof.into_iter().map(Some).collect(),
            priority_tree_start_index,
        }
    }

    pub fn push_hash(&mut self, leaf_hash: H256) {
        self.hashes.push_back(leaf_hash);
        if self.start_index + self.hashes.len() > self.binary_tree_size {
            self.binary_tree_size *= 2;
            if self.cache.len() < tree_depth_by_size(self.binary_tree_size) {
                self.cache.push(None);
            }
        }
    }

    pub fn hashes_prefix(&self, length: usize) -> Vec<H256> {
        self.hashes.iter().take(length).copied().collect()
    }

    pub fn trim_start(&mut self, count: usize) {
        let mut new_cache = vec![];
        let root = self.compute_merkle_root_and_path(count, Some(&mut new_cache), Some(Side::Left));
        self.hashes.drain(..count);
        self.start_index += count;
        if self.start_index == self.binary_tree_size {
            new_cache.push(Some(root));
        }
        self.cache = new_cache;
    }

    pub fn merkle_root_and_paths_for_range(
        &self,
        range: std::ops::RangeTo<usize>,
    ) -> (H256, Vec<Option<H256>>, Vec<Option<H256>>) {
        let mut right_path = vec![];
        let root_hash = self.compute_merkle_root_and_path(
            range.end - 1,
            Some(&mut right_path),
            Some(Side::Right),
        );
        (root_hash, self.cache.clone(), right_path)
    }

    pub fn compute_merkle_root_and_path(
        &self,
        mut index: usize,
        mut path: Option<&mut Vec<Option<H256>>>,
        side: Option<Side>,
    ) -> H256 {
        let depth = tree_depth_by_size(self.binary_tree_size);

        if let Some(path) = path.as_deref_mut() {
            path.reserve(depth);
        }

        let mut hashes = self.hashes.clone();
        let mut absolute_start_index = self.start_index;

        for level in 0..depth {
            if absolute_start_index % 2 == 1 {
                hashes.push_front(self.cache[level].expect("cache is invalid"));
                index += 1;
            }
            if hashes.len() % 2 == 1 {
                hashes.push_back(compute_empty_tree_hashes(empty_leaf_hash())[level]);
            }

            if let Some(path) = path.as_deref_mut() {
                let hash = match side {
                    Some(Side::Left) if index % 2 == 0 => None,
                    Some(Side::Right) if index % 2 == 1 => None,
                    _ => hashes.get(index ^ 1).copied(),
                };
                path.push(hash);
            }

            let level_len = hashes.len() / 2;
            for i in 0..level_len {
                hashes[i] = compress_hashes(&hashes[2 * i], &hashes[2 * i + 1]);
            }
            hashes.truncate(level_len);
            index /= 2;
            absolute_start_index /= 2;
        }

        hashes[0]
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Side {
    Left,
    Right,
}

fn compress_hashes(left: &H256, right: &H256) -> H256 {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left.as_bytes());
    data[32..].copy_from_slice(right.as_bytes());
    H256::from(ethers::utils::keccak256(data))
}

fn empty_leaf_hash() -> H256 {
    H256::from(ethers::utils::keccak256(&[]))
}

fn compute_empty_tree_hashes(empty_leaf_hash: H256) -> Vec<H256> {
    let mut hashes = Vec::with_capacity(33);
    let mut cur = empty_leaf_hash;
    for _ in 0..=32 {
        hashes.push(cur);
        cur = compress_hashes(&cur, &cur);
    }
    hashes
}

fn tree_depth_by_size(tree_size: usize) -> usize {
    tree_size.trailing_zeros() as usize
}

pub async fn initialize_merkle_tree(
    pool: Pool<Postgres>,
    eth_rpc_url: &String,
    initialize_from: Option<u64>,
    priority_tree_start_index: usize,
) -> Result<MiniMerkleTree> {
    let db = PostgresBatchDb::new(pool.clone());
    // Latest executed batch with some L1 txs.
    let latest_batch = match initialize_from {
        Some(batch_number) => batch_number as i64,
        None => match db.get_latest_executed_batch_with_l1_tx_number().await? {
            Some(batch) => batch,
            None => {
                debug!("No executed batches with L1 txs found in DB; starting with empty Merkle tree");
                return Ok(MiniMerkleTree::from_start_index_and_proof(0, vec![], priority_tree_start_index));
            }
        },
    };

    debug!("Latest batch is: {}", latest_batch);

    // Now let's get the 'execute tx hash' for that batch, and fetch the calldata from Ethereum mainnet.
    let execute_tx_hash = match db.get_execution_tx_hash_for_batch(latest_batch).await? {
        Some(hash) => hash,
        None => {
            debug!("Latest executed batch with L1 txs has no execution tx hash in DB; starting with empty Merkle tree");
            return Ok(MiniMerkleTree::from_start_index_and_proof(0, vec![], priority_tree_start_index));
        }
    };

    debug!("Execution tx hash for latest batch: {}", execute_tx_hash);

    let (batch_number, proof, _) = match get_priority_op_merkle_path(eth_rpc_url.as_str(), &execute_tx_hash).await {
        Ok(result) => result,
        Err(e) => {
            debug!("Failed to fetch execution tx {} from ETH RPC (may be on a different chain): {}; starting with empty Merkle tree", execute_tx_hash, e);
            return Ok(MiniMerkleTree::from_start_index_and_proof(0, vec![], priority_tree_start_index));
        }
    };

    let first_priority_op_id = get_batch_first_priority_op_id(&pool.clone(), batch_number.as_u32())
        .await
        .context("get_batch_first_priority_op_id")?
        .unwrap();

    let mut initial_mini_merkle_tree = MiniMerkleTree::from_start_index_and_proof(
        first_priority_op_id - priority_tree_start_index,
        proof,
        priority_tree_start_index,
    );
    // sanity check.
    assert_eq!(
        initial_mini_merkle_tree.next_priority_op_id(),
        first_priority_op_id as usize
    );
    let added = add_batch_tx_to_merkle(
        &pool,
        &load_l1_batch_with_metadata(&pool, batch_number.as_u32()).await?,
        &mut initial_mini_merkle_tree,
    )
    .await?;

    initial_mini_merkle_tree.trim_start(added);

    Ok(initial_mini_merkle_tree)
}

/// Takes a mini merkle tree, and adds all priority ops up to the given priority op id, and returns the updated mini merkle tree.
/// Checks that all the priority ops from the current one in merkle to the final one are present in DB.
/// Trims the tree in the end.
pub async fn prepare_merkle_up_to_priority_op(
    pool: &Pool<Postgres>,
    mini_merkle_tree: &mut MiniMerkleTree,
    up_to_priority_op_id: usize,
) -> Result<()> {
    let db = PostgresBatchDb::new(pool.clone());
    debug!(
        "Catching up mini merkle tree from priority op id {} to {}, hashes: {}",
        mini_merkle_tree.next_priority_op_id(),
        up_to_priority_op_id,
        mini_merkle_tree.hashes.len()
    );

    let start = mini_merkle_tree.next_priority_op_id();

    let end = up_to_priority_op_id;

    if start > end {
        anyhow::bail!(
            "Current mini merkle tree already has priority ops up to id {}, which is higher than the given up_to_priority_op_id {}",
            start - 1,
            end
        );
    }

    let hashes = db.get_l1_transactions_hashes_in_range(start, end).await?;

    for hash in hashes {
        mini_merkle_tree.push_hash(hash);
    }

    // Trim the tree to remove any unnecessary nodes.
    if mini_merkle_tree.hashes.len() > 0 {
        debug!(
            "Trimming mini merkle tree, start index: {}, number of hashes: {}",
            mini_merkle_tree.start_index,
            mini_merkle_tree.hashes.len(),
        );
        mini_merkle_tree.trim_start(mini_merkle_tree.hashes.len());
    }

    Ok(())
}
