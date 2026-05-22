use anyhow::{Context, Result};
use ethers::types::H256;
use sqlx::{PgPool, Row};

#[derive(Debug, Clone)]
pub struct ReadyExecuteCall {
    pub l1_batch_number: i64,
}

/// Minimal DB interface so the rest of the program stays clean.
#[async_trait::async_trait]
pub trait BatchDb: Send + Sync {
    async fn fetch_next_ready_execute_call(
        &self,
        min_batch_exclusive: i64,
    ) -> Result<Option<ReadyExecuteCall>>;
    async fn get_latest_executed_batch_with_l1_tx_number(&self) -> Result<Option<i64>>;

    async fn get_execution_tx_hash_for_batch(&self, batch_number: i64) -> Result<Option<String>>;

    /// Returns the last L1 batch number that the EN's consistency checker has verified
    /// against the L1 commit data. Returns None if no batch has been checked yet.
    async fn get_consistency_checker_last_verified_batch(&self) -> Result<Option<i64>>;

    /// Gets all the priority transactions in a given range (exclusive of end_id).
    /// All of them must exist in the db.
    async fn get_l1_transactions_hashes_in_range(
        &self,
        start_id: usize,
        end_id: usize,
    ) -> Result<Vec<H256>>;

    /// Smallest `priority_op_id` present in the DB, or `None` if there are no priority txs.
    /// On a snapshot-recovered / pruned node this is the first priority op the node has data
    /// for; everything below it predates the snapshot and must be sourced from L1.
    async fn get_min_priority_op_id(&self) -> Result<Option<i64>>;
}

pub struct PostgresBatchDb {
    pool: PgPool,
}

impl PostgresBatchDb {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl BatchDb for PostgresBatchDb {
    async fn fetch_next_ready_execute_call(
        &self,
        min_batch_exclusive: i64,
    ) -> Result<Option<ReadyExecuteCall>> {
        // Only approve batches that the EN consistency checker has already verified
        // against L1 commit data. This prevents approving batches based on
        // potentially fabricated data that hasn't been cross-checked with L1.
        let consistency_limit = self
            .get_consistency_checker_last_verified_batch()
            .await?;

        let max_allowed = match consistency_limit {
            Some(last_verified) => last_verified,
            None => {
                tracing::warn!(
                    "consistency_checker_info has no entries; refusing to approve any batch \
                     until the consistency checker has run"
                );
                return Ok(None);
            }
        };

        let row = sqlx::query(
            r#"
            SELECT
                number AS l1_batch_number
            FROM l1_batches
            WHERE
                number > $1
                AND number <= $2
                AND eth_commit_tx_id IS NOT NULL
                AND eth_execute_tx_id IS NULL
            ORDER BY number ASC
            LIMIT 1
            "#,
        )
        .bind(min_batch_exclusive)
        .bind(max_allowed)
        .fetch_optional(&self.pool)
        .await
        .context("DB query failed while fetching next ready execute call")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let l1_batch_number: i64 = row
            .try_get("l1_batch_number")
            .context("Missing/invalid l1_batch_number column")?;

        Ok(Some(ReadyExecuteCall { l1_batch_number }))
    }

    async fn get_latest_executed_batch_with_l1_tx_number(&self) -> Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT
                number AS l1_batch_number
            FROM l1_batches
            WHERE
                eth_execute_tx_id IS NOT NULL
                AND l1_tx_count > 0
            ORDER BY number DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .context("DB query failed while fetching latest executed batch with L1 tx number")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let l1_batch_number: i64 = row
            .try_get("l1_batch_number")
            .context("Missing/invalid l1_batch_number column")?;

        Ok(Some(l1_batch_number))
    }

    async fn get_execution_tx_hash_for_batch(&self, batch_number: i64) -> Result<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT
                eth_execute_tx_id
            FROM l1_batches
            WHERE
                number = $1
            "#,
        )
        .bind(batch_number)
        .fetch_optional(&self.pool)
        .await
        .context("DB query failed while fetching execution tx hash for batch")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let eth_execute_tx_id: Option<i32> = row
            .try_get("eth_execute_tx_id")
            .context("Missing/invalid eth_execute_tx_id column")?;

        let Some(eth_execute_tx_id) = eth_execute_tx_id else {
            return Ok(None);
        };

        // Now get tx_hash from the eth_txs_history, based off eth_execute_tx_id.
        let row = sqlx::query(
            r#"
            SELECT
                tx_hash
            FROM eth_txs_history
            WHERE
                eth_tx_id = $1
            "#,
        )
        .bind(eth_execute_tx_id)
        .fetch_optional(&self.pool)
        .await
        .context("DB query failed while fetching tx hash for execution tx id")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let tx_hash: String = row
            .try_get("tx_hash")
            .context("Missing/invalid tx_hash column")?;

        Ok(Some(tx_hash))
    }

    async fn get_consistency_checker_last_verified_batch(&self) -> Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT last_processed_l1_batch AS last_batch
            FROM consistency_checker_info
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .context("DB query failed while fetching consistency_checker_info")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let last_batch: i64 = row
            .try_get("last_batch")
            .context("Missing/invalid last_processed_l1_batch column")?;

        Ok(Some(last_batch))
    }

    async fn get_l1_transactions_hashes_in_range(
        &self,
        start_id: usize,
        end_id: usize,
    ) -> Result<Vec<H256>> {
        let rows = sqlx::query(
            r#" SELECT hash
                FROM transactions
                WHERE priority_op_id BETWEEN $1 AND $2
                    AND is_priority = TRUE
                ORDER BY priority_op_id
            "#,
        )
        .bind(start_id as i64)
        .bind((end_id - 1) as i64)
        .fetch_all(&self.pool)
        .await
        .context("DB query failed while fetching L1 transaction hashes in range")?;

        let mut hashes = Vec::new();
        for row in rows {
            let hash = row.get::<Vec<u8>, _>("hash");
            hashes.push(H256::from_slice(hash.as_slice()));
        }

        if hashes.len() != end_id - start_id {
            anyhow::bail!(
                "Some priority ops in range [{}, {}) are missing in the DB: found {} of {}. \
                 This node is likely snapshot-recovered without the required priority-op history; \
                 the Merkle tree should have been seeded from L1 during initialization.",
                start_id,
                end_id,
                hashes.len(),
                end_id - start_id
            );
        }

        Ok(hashes)
    }

    async fn get_min_priority_op_id(&self) -> Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT MIN(priority_op_id) AS id
            FROM transactions
            WHERE is_priority = TRUE
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .context("DB query failed while fetching min priority_op_id")?;

        let id: Option<i64> = row
            .try_get("id")
            .context("Missing/invalid priority_op_id column")?;

        Ok(id)
    }
}
