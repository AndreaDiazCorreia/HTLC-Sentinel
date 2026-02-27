use anyhow::Result;

use super::types::ApiTransaction;

pub trait DataSource {
    fn get_transaction(
        &self,
        txid: &str,
    ) -> impl std::future::Future<Output = Result<ApiTransaction>> + Send;

    fn get_transaction_hex(
        &self,
        txid: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    fn get_block_txs(
        &self,
        hash: &str,
        start_index: u32,
    ) -> impl std::future::Future<Output = Result<Vec<ApiTransaction>>> + Send;

    fn get_block_tip_height(&self) -> impl std::future::Future<Output = Result<u64>> + Send;

    fn get_block_hash(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Fetch all transactions in a block, handling pagination automatically.
    fn get_all_block_txs(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = Result<Vec<ApiTransaction>>> + Send;

    /// Fetch txids of recent unconfirmed transactions from the mempool.
    fn get_mempool_recent_txids(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
}
