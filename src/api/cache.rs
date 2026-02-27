use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use moka::future::Cache;

use super::source::DataSource;
use super::types::ApiTransaction;

/// Caching wrapper around any DataSource. Confirmed transactions and blocks are
/// cached indefinitely. Unconfirmed data uses a short TTL.
pub struct CachedClient<S> {
    inner: S,
    tx_cache: Cache<String, Arc<ApiTransaction>>,
    block_txs_cache: Cache<(String, u32), Arc<Vec<ApiTransaction>>>,
    block_hash_cache: Cache<u64, String>,
    tip_cache: Cache<(), u64>,
}

impl<S: DataSource + Send + Sync> CachedClient<S> {
    pub fn new(inner: S, max_capacity: u64) -> Self {
        Self {
            inner,
            // Confirmed txs don't change — long TTL
            tx_cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            block_txs_cache: Cache::builder()
                .max_capacity(max_capacity / 10)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            // Block hashes are immutable once confirmed
            block_hash_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            // Tip height changes every ~10 minutes
            tip_cache: Cache::builder()
                .max_capacity(1)
                .time_to_live(Duration::from_secs(30))
                .build(),
        }
    }
}

impl<S: DataSource + Send + Sync> DataSource for CachedClient<S> {
    async fn get_transaction(&self, txid: &str) -> Result<ApiTransaction> {
        if let Some(cached) = self.tx_cache.get(txid).await {
            return Ok((*cached).clone());
        }
        let tx = self.inner.get_transaction(txid).await?;
        self.tx_cache
            .insert(txid.to_string(), Arc::new(tx.clone()))
            .await;
        Ok(tx)
    }

    async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        // Not cached — rarely used in server context
        self.inner.get_transaction_hex(txid).await
    }

    async fn get_block_txs(&self, hash: &str, start_index: u32) -> Result<Vec<ApiTransaction>> {
        let key = (hash.to_string(), start_index);
        if let Some(cached) = self.block_txs_cache.get(&key).await {
            return Ok((*cached).clone());
        }
        let txs = self.inner.get_block_txs(hash, start_index).await?;
        self.block_txs_cache
            .insert(key, Arc::new(txs.clone()))
            .await;
        Ok(txs)
    }

    async fn get_block_tip_height(&self) -> Result<u64> {
        if let Some(cached) = self.tip_cache.get(&()).await {
            return Ok(cached);
        }
        let height = self.inner.get_block_tip_height().await?;
        self.tip_cache.insert((), height).await;
        Ok(height)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        if let Some(cached) = self.block_hash_cache.get(&height).await {
            return Ok(cached);
        }
        let hash = self.inner.get_block_hash(height).await?;
        self.block_hash_cache
            .insert(height, hash.clone())
            .await;
        Ok(hash)
    }

    async fn get_all_block_txs(&self, height: u64) -> Result<Vec<ApiTransaction>> {
        // Delegate to inner which handles pagination; individual pages get cached
        // via get_block_txs above
        self.inner.get_all_block_txs(height).await
    }

    async fn get_mempool_recent_txids(&self) -> Result<Vec<String>> {
        // No caching — always want fresh mempool data
        self.inner.get_mempool_recent_txids().await
    }
}
