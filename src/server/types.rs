use serde::{Deserialize, Serialize};

use crate::lightning::types::LightningClassification;
use crate::security::types::Alert;
use crate::timelock::types::TransactionAnalysis;

/// Full analysis result for a single transaction (all phases combined).
#[derive(Debug, Clone, Serialize)]
pub struct TxAnalysisResponse {
    pub timelock: TransactionAnalysis,
    pub lightning: LightningClassification,
    pub alerts: Vec<Alert>,
}

/// Block scanning response.
#[derive(Debug, Clone, Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub total_transactions: usize,
    pub returned_transactions: usize,
    pub transactions: Vec<TxAnalysisResponse>,
}

/// Security scan response.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResponse {
    pub start_height: u64,
    pub end_height: u64,
    pub current_tip: u64,
    pub total_alerts: usize,
    pub alerts: Vec<Alert>,
}

/// Lightning activity summary response.
#[derive(Debug, Clone, Serialize)]
pub struct LightningResponse {
    pub start_height: u64,
    pub end_height: u64,
    pub total_transactions_scanned: usize,
    pub commitments: usize,
    pub htlc_timeouts: usize,
    pub htlc_successes: usize,
    pub transactions: Vec<LightningTxEntry>,
    pub cltv_expiry_distribution: Vec<ExpiryBucket>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LightningTxEntry {
    pub txid: String,
    pub classification: LightningClassification,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpiryBucket {
    pub block_height: u32,
    pub count: usize,
}

/// Query parameters for block endpoint.
#[derive(Debug, Deserialize)]
pub struct BlockQuery {
    /// Filter: "all", "timelocks", "alerts" (default: "timelocks")
    pub filter: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// Query parameters for scan endpoint.
#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    pub start: u64,
    pub end: Option<u64>,
    pub severity: Option<String>,
    pub detection_type: Option<String>,
}

/// Query parameters for lightning endpoint.
#[derive(Debug, Deserialize)]
pub struct LightningQuery {
    pub start: u64,
    pub end: Option<u64>,
}
