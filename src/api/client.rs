use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use tokio::time::sleep;

use serde::Deserialize;

use super::source::DataSource;
use super::types::ApiTransaction;

#[derive(Deserialize)]
struct MempoolRecentEntry {
    txid: String,
}

pub struct MempoolClient {
    client: reqwest::Client,
    base_url: String,
    request_delay: Duration,
    max_retries: u32,
}

impl MempoolClient {
    pub fn new(base_url: &str, request_delay: Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            request_delay,
            max_retries: 5,
        }
    }

    pub fn default() -> Self {
        Self::new("https://mempool.space", Duration::from_millis(250))
    }

    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response> {
        let mut delay = self.request_delay;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                sleep(delay).await;
                delay *= 2; // exponential backoff
            }

            let resp = self
                .client
                .get(url)
                .send()
                .await
                .with_context(|| format!("request to {url}"))?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                if attempt == self.max_retries {
                    bail!("rate limited after {} retries: {url}", self.max_retries);
                }
                eprintln!("rate limited, backing off {delay:?}...");
                continue;
            }

            if !resp.status().is_success() {
                bail!("HTTP {} for {url}", resp.status());
            }

            return Ok(resp);
        }

        unreachable!()
    }

    async fn throttle(&self) {
        sleep(self.request_delay).await;
    }
}

impl DataSource for MempoolClient {
    async fn get_transaction(&self, txid: &str) -> Result<ApiTransaction> {
        let url = format!("{}/api/tx/{txid}", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let tx = resp
            .json::<ApiTransaction>()
            .await
            .context("deserializing transaction")?;
        Ok(tx)
    }

    async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        let url = format!("{}/api/tx/{txid}/hex", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let hex = resp.text().await.context("reading transaction hex")?;
        Ok(hex)
    }

    async fn get_block_txs(&self, hash: &str, start_index: u32) -> Result<Vec<ApiTransaction>> {
        let url = format!("{}/api/block/{hash}/txs/{start_index}", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let txs = resp
            .json::<Vec<ApiTransaction>>()
            .await
            .context("deserializing block transactions")?;
        Ok(txs)
    }

    async fn get_block_tip_height(&self) -> Result<u64> {
        let url = format!("{}/api/blocks/tip/height", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let height = resp
            .text()
            .await
            .context("reading tip height")?
            .trim()
            .parse::<u64>()
            .context("parsing tip height")?;
        Ok(height)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        let url = format!("{}/api/block-height/{height}", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let hash = resp
            .text()
            .await
            .context("reading block hash")?
            .trim()
            .to_string();
        Ok(hash)
    }

    async fn get_all_block_txs(&self, height: u64) -> Result<Vec<ApiTransaction>> {
        let hash = self.get_block_hash(height).await?;
        self.throttle().await;

        let mut all_txs = Vec::new();
        let mut start_index: u32 = 0;

        loop {
            let page = self.get_block_txs(&hash, start_index).await?;
            let count = page.len() as u32;
            all_txs.extend(page);

            if count < 25 {
                break;
            }

            start_index += count;
            self.throttle().await;
        }

        Ok(all_txs)
    }

    async fn get_mempool_recent_txids(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/mempool/recent", self.base_url);
        let resp = self.get_with_retry(&url).await?;
        let entries = resp
            .json::<Vec<MempoolRecentEntry>>()
            .await
            .context("deserializing mempool recent transactions")?;
        Ok(entries.into_iter().map(|e| e.txid).collect())
    }
}
