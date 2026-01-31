use anyhow::{Context, Result};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone)]
pub struct ReadyExecuteCall {
    pub l1_batch_number: i64,
}

/// Minimal DB interface so the rest of the program stays clean.
#[async_trait::async_trait]
pub trait BatchDb: Send + Sync {
    async fn fetch_next_ready_execute_call(&self, min_batch_exclusive: i64) -> Result<Option<ReadyExecuteCall>>;
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
    async fn fetch_next_ready_execute_call(&self, min_batch_exclusive: i64) -> Result<Option<ReadyExecuteCall>> {
        let row = sqlx::query(
            r#"
            SELECT
                number AS l1_batch_number
            FROM l1_batches
            WHERE
                number > $1
                AND eth_execute_tx_id IS NOT NULL
            ORDER BY number ASC
            LIMIT 1
            "#,
        )
        .bind(min_batch_exclusive)
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
}
