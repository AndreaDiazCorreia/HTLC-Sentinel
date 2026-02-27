use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::response::sse::{Event, KeepAlive, KeepAliveStream, Sse};

use crate::api::source::DataSource;
use crate::lightning::detector::classify_lightning;
use crate::lightning::types::LightningTxType;
use crate::security::analyzer;
use crate::security::types::{DetectionType, SecurityConfig, Severity};
use crate::timelock::extractor::analyze_transaction;

use super::types::*;

pub type AppState<S> = Arc<ServerState<S>>;

pub struct ServerState<S> {
    pub client: S,
    pub config: SecurityConfig,
}

pub async fn get_transaction<S: DataSource + Send + Sync>(
    State(state): State<AppState<S>>,
    Path(txid): Path<String>,
) -> Result<Json<TxAnalysisResponse>, (StatusCode, String)> {
    let tx = state
        .client
        .get_transaction(&txid)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch error: {e}")))?;

    let tip = state
        .client
        .get_block_tip_height()
        .await
        .unwrap_or(0);

    let timelock = analyze_transaction(&tx);
    let lightning = classify_lightning(&tx);
    let alerts = analyzer::analyze_transaction(&timelock, &lightning, tip, &state.config);

    Ok(Json(TxAnalysisResponse {
        timelock,
        lightning,
        alerts,
    }))
}

pub async fn get_block<S: DataSource + Send + Sync>(
    State(state): State<AppState<S>>,
    Path(height): Path<u64>,
    Query(params): Query<BlockQuery>,
) -> Result<Json<BlockResponse>, (StatusCode, String)> {
    let txs = state
        .client
        .get_all_block_txs(height)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch error: {e}")))?;

    let tip = state.client.get_block_tip_height().await.unwrap_or(0);
    let total_transactions = txs.len();

    let mut analyzed: Vec<TxAnalysisResponse> = txs
        .iter()
        .map(|tx| {
            let timelock = analyze_transaction(tx);
            let lightning = classify_lightning(tx);
            let alerts =
                analyzer::analyze_transaction(&timelock, &lightning, tip, &state.config);
            TxAnalysisResponse {
                timelock,
                lightning,
                alerts,
            }
        })
        .collect();

    // Apply filter
    let filter = params.filter.as_deref().unwrap_or("timelocks");
    match filter {
        "alerts" => {
            analyzed.retain(|a| !a.alerts.is_empty());
        }
        "timelocks" => {
            analyzed.retain(|a| a.timelock.summary.has_active_timelocks);
        }
        // "all" or anything else — no filtering
        _ => {}
    }

    // Apply pagination
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100);
    let returned_transactions = analyzed.len();
    let paginated: Vec<_> = analyzed.into_iter().skip(offset).take(limit).collect();

    Ok(Json(BlockResponse {
        height,
        total_transactions,
        returned_transactions,
        transactions: paginated,
    }))
}

pub async fn get_scan<S: DataSource + Send + Sync>(
    State(state): State<AppState<S>>,
    Query(params): Query<ScanQuery>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let start = params.start;
    let end = params.end.unwrap_or(start);
    let tip = state.client.get_block_tip_height().await.unwrap_or(0);

    let mut all_alerts = Vec::new();
    let mut htlc_expiries = Vec::new();

    for height in start..=end {
        let txs = state
            .client
            .get_all_block_txs(height)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch error at block {height}: {e}")))?;

        for tx in &txs {
            let timelock = analyze_transaction(tx);
            let lightning = classify_lightning(tx);

            if lightning.tx_type == Some(LightningTxType::HtlcTimeout) {
                if let Some(expiry) = lightning.params.cltv_expiry {
                    htlc_expiries.push(expiry);
                }
            }

            let mut alerts =
                analyzer::analyze_transaction(&timelock, &lightning, tip, &state.config);
            all_alerts.append(&mut alerts);
        }
    }

    let mut cluster_alerts = analyzer::detect_htlc_clustering(&htlc_expiries, &state.config);
    all_alerts.append(&mut cluster_alerts);
    all_alerts.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Apply severity filter
    if let Some(ref sev) = params.severity {
        let filter_sev = parse_severity(sev);
        if let Some(s) = filter_sev {
            all_alerts.retain(|a| a.severity == s);
        }
    }

    // Apply detection type filter
    if let Some(ref dt) = params.detection_type {
        let filter_dt = parse_detection_type(dt);
        if let Some(d) = filter_dt {
            all_alerts.retain(|a| a.detection_type == d);
        }
    }

    let total_alerts = all_alerts.len();

    Ok(Json(ScanResponse {
        start_height: start,
        end_height: end,
        current_tip: tip,
        total_alerts,
        alerts: all_alerts,
    }))
}

pub async fn get_lightning<S: DataSource + Send + Sync>(
    State(state): State<AppState<S>>,
    Query(params): Query<LightningQuery>,
) -> Result<Json<LightningResponse>, (StatusCode, String)> {
    let start = params.start;
    let end = params.end.unwrap_or(start);

    let mut total_scanned = 0;
    let mut commitments = 0;
    let mut htlc_timeouts = 0;
    let mut htlc_successes = 0;
    let mut ln_txs = Vec::new();
    let mut expiry_counts: HashMap<u32, usize> = HashMap::new();

    for height in start..=end {
        let txs = state
            .client
            .get_all_block_txs(height)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch error at block {height}: {e}")))?;

        total_scanned += txs.len();

        for tx in &txs {
            let classification = classify_lightning(tx);
            match classification.tx_type {
                Some(LightningTxType::Commitment) => {
                    commitments += 1;
                    ln_txs.push(LightningTxEntry {
                        txid: tx.txid.clone(),
                        classification,
                    });
                }
                Some(LightningTxType::HtlcTimeout) => {
                    htlc_timeouts += 1;
                    if let Some(expiry) = classification.params.cltv_expiry {
                        *expiry_counts.entry(expiry).or_insert(0) += 1;
                    }
                    ln_txs.push(LightningTxEntry {
                        txid: tx.txid.clone(),
                        classification,
                    });
                }
                Some(LightningTxType::HtlcSuccess) => {
                    htlc_successes += 1;
                    ln_txs.push(LightningTxEntry {
                        txid: tx.txid.clone(),
                        classification,
                    });
                }
                None => {}
            }
        }
    }

    let mut cltv_expiry_distribution: Vec<ExpiryBucket> = expiry_counts
        .into_iter()
        .map(|(block_height, count)| ExpiryBucket {
            block_height,
            count,
        })
        .collect();
    cltv_expiry_distribution.sort_by_key(|b| b.block_height);

    Ok(Json(LightningResponse {
        start_height: start,
        end_height: end,
        total_transactions_scanned: total_scanned,
        commitments,
        htlc_timeouts,
        htlc_successes,
        transactions: ln_txs,
        cltv_expiry_distribution,
    }))
}

pub async fn get_monitor<S: DataSource + Send + Sync + 'static>(
    State(state): State<AppState<S>>,
    Query(params): Query<MonitorQuery>,
) -> Sse<KeepAliveStream<std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Event, Infallible>> + Send>>>> {
    let interval = Duration::from_secs(params.interval.unwrap_or(10));
    let min_sev = match params.min_severity.as_deref() {
        Some("critical") => Severity::Critical,
        Some("warning") => Severity::Warning,
        _ => Severity::Informational,
    };

    let s = stream! {
        let mut seen: HashSet<String> = HashSet::new();

        loop {
            let tip = state.client.get_block_tip_height().await.unwrap_or(0);

            if let Ok(txids) = state.client.get_mempool_recent_txids().await {
                for txid in txids {
                    if !seen.insert(txid.clone()) {
                        continue;
                    }

                    let tx = match state.client.get_transaction(&txid).await {
                        Ok(t) => t,
                        Err(_) => continue,
                    };

                    let timelock = analyze_transaction(&tx);
                    let lightning = classify_lightning(&tx);
                    let alerts: Vec<_> = analyzer::analyze_transaction(
                        &timelock, &lightning, tip, &state.config,
                    )
                    .into_iter()
                    .filter(|a| a.severity >= min_sev)
                    .collect();

                    let has_findings = !alerts.is_empty()
                        || lightning.tx_type.is_some()
                        || timelock.summary.has_active_timelocks;

                    if !has_findings {
                        continue;
                    }

                    let payload = serde_json::json!({
                        "txid": txid,
                        "timelock": timelock,
                        "lightning": lightning,
                        "alerts": alerts,
                    });

                    if let Ok(data) = serde_json::to_string(&payload) {
                        let event: Result<Event, Infallible> = Ok(Event::default().event("tx").data(data));
                        yield event;
                    }
                }
            }

            if seen.len() > 10_000 {
                seen.clear();
            }

            tokio::time::sleep(interval).await;
        }
    };

    let boxed: std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Event, Infallible>> + Send>> = Box::pin(s);
    Sse::new(boxed).keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "warning" => Some(Severity::Warning),
        "informational" | "info" => Some(Severity::Informational),
        _ => None,
    }
}

fn parse_detection_type(s: &str) -> Option<DetectionType> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "timelock_mixing" => Some(DetectionType::TimelockMixing),
        "short_cltv_delta" => Some(DetectionType::ShortCltvDelta),
        "htlc_clustering" => Some(DetectionType::HtlcClustering),
        "anomalous_sequence" => Some(DetectionType::AnomalousSequence),
        _ => None,
    }
}
