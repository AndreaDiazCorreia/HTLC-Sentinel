use std::sync::Mutex;

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use cltv_scan::api::source::DataSource;
use cltv_scan::api::types::*;
use cltv_scan::security::types::SecurityConfig;
use cltv_scan::server;

// ─── Mock DataSource ─────────────────────────────────────────────────────────

struct MockClient {
    transactions: Mutex<Vec<ApiTransaction>>,
}

impl MockClient {
    fn new(txs: Vec<ApiTransaction>) -> Self {
        Self {
            transactions: Mutex::new(txs),
        }
    }
}

impl DataSource for MockClient {
    async fn get_transaction(&self, txid: &str) -> Result<ApiTransaction> {
        let txs = self.transactions.lock().unwrap();
        txs.iter()
            .find(|tx| tx.txid == txid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tx not found: {txid}"))
    }

    async fn get_transaction_hex(&self, _txid: &str) -> Result<String> {
        Ok("00".to_string())
    }

    async fn get_block_txs(&self, _hash: &str, _start_index: u32) -> Result<Vec<ApiTransaction>> {
        let txs = self.transactions.lock().unwrap();
        Ok(txs.clone())
    }

    async fn get_block_tip_height(&self) -> Result<u64> {
        Ok(886100)
    }

    async fn get_block_hash(&self, _height: u64) -> Result<String> {
        Ok("00000000deadbeef".to_string())
    }

    async fn get_all_block_txs(&self, _height: u64) -> Result<Vec<ApiTransaction>> {
        let txs = self.transactions.lock().unwrap();
        Ok(txs.clone())
    }

    async fn get_mempool_recent_txids(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_status() -> ApiStatus {
    ApiStatus {
        confirmed: true,
        block_height: Some(886000),
        block_hash: Some("00000000".to_string()),
        block_time: Some(1700000000),
    }
}

fn make_vout(value: u64, script_type: &str) -> ApiVout {
    ApiVout {
        scriptpubkey: "00".to_string(),
        scriptpubkey_asm: "OP_0".to_string(),
        scriptpubkey_type: script_type.to_string(),
        scriptpubkey_address: None,
        value,
    }
}

fn make_vin(sequence: u32) -> ApiVin {
    ApiVin {
        txid: Some("aa".repeat(32)),
        vout: Some(0),
        prevout: None,
        scriptsig: None,
        scriptsig_asm: None,
        inner_redeemscript_asm: None,
        inner_witnessscript_asm: None,
        witness: None,
        is_coinbase: false,
        sequence,
    }
}

fn make_tx(txid: &str, locktime: u32, vins: Vec<ApiVin>, vouts: Vec<ApiVout>) -> ApiTransaction {
    ApiTransaction {
        txid: txid.to_string(),
        version: 2,
        locktime,
        vin: vins,
        vout: vouts,
        size: 200,
        weight: 800,
        fee: Some(1000),
        status: make_status(),
    }
}

fn sample_txs() -> Vec<ApiTransaction> {
    let mut cltv_vin = make_vin(0xFFFFFFFD);
    cltv_vin.inner_witnessscript_asm = Some(
        "886110 OP_CHECKLOCKTIMEVERIFY OP_DROP 144 OP_CHECKSEQUENCEVERIFY".to_string(),
    );

    vec![
        // Regular tx — no timelocks
        make_tx(
            "aaa111",
            0,
            vec![make_vin(0xFFFFFFFF)],
            vec![make_vout(50_000, "v0_p2wpkh")],
        ),
        // Tx with nLockTime
        make_tx(
            "bbb222",
            886000,
            vec![make_vin(0xFFFFFFFD)],
            vec![make_vout(50_000, "v0_p2wpkh")],
        ),
        // Tx with CLTV + CSV (short CLTV delta → alert)
        make_tx(
            "ccc333",
            886110,
            vec![cltv_vin],
            vec![make_vout(50_000, "v0_p2wsh")],
        ),
        // Lightning commitment tx
        make_tx(
            "ddd444",
            0x20000042,
            vec![make_vin(0x80000001)],
            vec![
                make_vout(100_000, "v0_p2wsh"),
                make_vout(330, "v0_p2wsh"),
                make_vout(330, "v0_p2wsh"),
            ],
        ),
    ]
}

async fn response_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

fn test_app() -> axum::Router {
    let client = MockClient::new(sample_txs());
    server::create_router(client, SecurityConfig::default())
}

// ─── Transaction endpoint ────────────────────────────────────────────────────

#[tokio::test]
async fn test_tx_endpoint_returns_full_analysis() {
    let (status, json) = response_json(test_app(), "/api/tx/bbb222").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("timelock").is_some());
    assert!(json.get("lightning").is_some());
    assert!(json.get("alerts").is_some());
    assert_eq!(json["timelock"]["txid"], "bbb222");
}

#[tokio::test]
async fn test_tx_endpoint_not_found() {
    let app = test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/tx/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn test_tx_endpoint_includes_alerts() {
    // ccc333 has a short CLTV delta → should generate alert
    let (status, json) = response_json(test_app(), "/api/tx/ccc333").await;
    assert_eq!(status, StatusCode::OK);
    let alerts = json["alerts"].as_array().unwrap();
    assert!(!alerts.is_empty());
    assert_eq!(alerts[0]["detection_type"], "short_cltv_delta");
}

// ─── Block endpoint ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_block_endpoint_default_filter() {
    // Default filter = "timelocks" → only txs with active timelocks
    let (status, json) = response_json(test_app(), "/api/block/886000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["height"], 886000);
    assert_eq!(json["total_transactions"], 4);
    // aaa111 has no timelocks, so returned < total
    let returned = json["returned_transactions"].as_u64().unwrap();
    assert!(returned < 4);
}

#[tokio::test]
async fn test_block_endpoint_all_filter() {
    let (status, json) = response_json(test_app(), "/api/block/886000?filter=all").await;
    assert_eq!(status, StatusCode::OK);
    let txs = json["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 4); // all 4 txs
}

#[tokio::test]
async fn test_block_endpoint_alerts_filter() {
    let (status, json) = response_json(test_app(), "/api/block/886000?filter=alerts").await;
    assert_eq!(status, StatusCode::OK);
    let txs = json["transactions"].as_array().unwrap();
    // Only ccc333 should have alerts
    assert!(txs.len() >= 1);
    for tx in txs {
        assert!(!tx["alerts"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_block_endpoint_pagination() {
    let (status, json) =
        response_json(test_app(), "/api/block/886000?filter=all&offset=1&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    let txs = json["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 2);
}

// ─── Scan endpoint ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_scan_endpoint_returns_alerts() {
    let (status, json) = response_json(test_app(), "/api/scan?start=886000").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("alerts").is_some());
    assert!(json.get("total_alerts").is_some());
    assert_eq!(json["start_height"], 886000);
    assert_eq!(json["end_height"], 886000);
}

#[tokio::test]
async fn test_scan_endpoint_severity_filter() {
    let (_, json) = response_json(test_app(), "/api/scan?start=886000&severity=critical").await;
    let alerts = json["alerts"].as_array().unwrap();
    for alert in alerts {
        assert_eq!(alert["severity"], "critical");
    }
}

#[tokio::test]
async fn test_scan_endpoint_detection_type_filter() {
    let (_, json) = response_json(
        test_app(),
        "/api/scan?start=886000&detection_type=short_cltv_delta",
    )
    .await;
    let alerts = json["alerts"].as_array().unwrap();
    for alert in alerts {
        assert_eq!(alert["detection_type"], "short_cltv_delta");
    }
}

// ─── Lightning endpoint ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_lightning_endpoint_summary() {
    let (status, json) = response_json(test_app(), "/api/lightning?start=886000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_transactions_scanned"], 4);
    assert!(json["commitments"].as_u64().unwrap() >= 1); // ddd444
    assert!(json.get("cltv_expiry_distribution").is_some());
    assert!(json.get("transactions").is_some());
}

#[tokio::test]
async fn test_lightning_endpoint_includes_ln_txs() {
    let (_, json) = response_json(test_app(), "/api/lightning?start=886000").await;
    let txs = json["transactions"].as_array().unwrap();
    assert!(!txs.is_empty());
    // ddd444 should be identified as commitment
    let has_commitment = txs
        .iter()
        .any(|t| t["txid"] == "ddd444" && t["classification"]["tx_type"] == "commitment");
    assert!(has_commitment);
}

// ─── CORS ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_cors_headers_present() {
    let app = test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/tx/bbb222")
                .header("Origin", "http://localhost:5173")
                .header("Access-Control-Request-Method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // CORS layer should respond to OPTIONS
    assert!(response.status().is_success() || response.status() == StatusCode::NO_CONTENT);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_some());
}
