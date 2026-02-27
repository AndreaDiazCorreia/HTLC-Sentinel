use cltv_scan::api::types::*;
use cltv_scan::lightning::detector::classify_lightning;
use cltv_scan::security::analyzer::{analyze_transaction, detect_htlc_clustering};
use cltv_scan::security::types::*;
use cltv_scan::timelock::extractor::analyze_transaction as extract_timelocks;

// ─── Test helpers ────────────────────────────────────────────────────────────

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

fn make_tx(locktime: u32, vins: Vec<ApiVin>, vouts: Vec<ApiVout>) -> ApiTransaction {
    ApiTransaction {
        txid: "bb".repeat(32),
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

fn default_config() -> SecurityConfig {
    SecurityConfig::default()
}

fn run_analysis(tx: &ApiTransaction, current_height: u64) -> Vec<Alert> {
    let timelock = extract_timelocks(tx);
    let lightning = classify_lightning(tx);
    analyze_transaction(&timelock, &lightning, current_height, &default_config())
}

// ═══════════════════════════════════════════════════════════════════════════
// Goal 1: Timelock mixing detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_no_mixing_same_domain_timelocks() {
    // CLTV with block height + CSV with block count → same domain, no mixing
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886000 OP_CHECKLOCKTIMEVERIFY OP_DROP 144 OP_CHECKSEQUENCEVERIFY".to_string(),
    );
    let tx = make_tx(886000, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    let mixing_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::TimelockMixing)
        .collect();
    assert!(mixing_alerts.is_empty());
}

#[test]
fn test_mixing_cltv_height_csv_time() {
    // CLTV with block height + CSV with time-based (bit 22 set) → MIXING → critical
    // 0x400090 = bit 22 set + 144 in lower bits → time-based CSV
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886000 OP_CHECKLOCKTIMEVERIFY OP_DROP 4194448 OP_CHECKSEQUENCEVERIFY".to_string(),
    );
    // 4194448 = 0x400090 = (1 << 22) | 144 → time-based relative timelock
    let tx = make_tx(886000, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    let mixing_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::TimelockMixing)
        .collect();
    assert_eq!(mixing_alerts.len(), 1);
    assert_eq!(mixing_alerts[0].severity, Severity::Critical);
}

#[test]
fn test_mixing_nlocktime_height_vs_cltv_timestamp() {
    // nLockTime as block height + CLTV as timestamp → mixing across tx
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "1700000000 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(886000, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]); // locktime = block height
    let alerts = run_analysis(&tx, 886100);
    let mixing_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::TimelockMixing)
        .collect();
    assert_eq!(mixing_alerts.len(), 1);
    assert_eq!(mixing_alerts[0].severity, Severity::Critical);
}

#[test]
fn test_mixing_nsequence_height_vs_csv_time() {
    // nSequence encodes block-based relative timelock, but CSV in script is time-based
    let mut vin = make_vin(10); // BIP 68: 10 blocks relative timelock (block-based)
    vin.inner_witnessscript_asm = Some(
        "4194448 OP_CHECKSEQUENCEVERIFY OP_DROP".to_string(), // time-based CSV
    );
    let tx = make_tx(0, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    let mixing_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::TimelockMixing)
        .collect();
    assert_eq!(mixing_alerts.len(), 1);
    assert_eq!(mixing_alerts[0].severity, Severity::Critical);
}

#[test]
fn test_no_timelocks_no_mixing() {
    let tx = make_tx(
        0,
        vec![make_vin(0xFFFFFFFF)],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let mixing_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::TimelockMixing)
        .collect();
    assert!(mixing_alerts.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Goal 2: Short CLTV delta detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cltv_expiry_critical_below_18() {
    // HTLC-timeout with CLTV expiry only 10 blocks ahead → critical
    let mut vin = make_vin(0);
    vin.witness = Some(vec!["".to_string(), "3045".to_string()]);
    vin.inner_witnessscript_asm = Some(
        "886110 OP_CHECKLOCKTIMEVERIFY OP_DROP 1 OP_CHECKSEQUENCEVERIFY".to_string(),
    );
    let tx = make_tx(886110, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100); // 10 blocks remaining
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert_eq!(cltv_alerts.len(), 1);
    assert_eq!(cltv_alerts[0].severity, Severity::Critical);
}

#[test]
fn test_cltv_expiry_warning_below_34() {
    // CLTV expiry 25 blocks ahead → warning
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886125 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(886125, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100); // 25 blocks remaining
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert_eq!(cltv_alerts.len(), 1);
    assert_eq!(cltv_alerts[0].severity, Severity::Warning);
}

#[test]
fn test_cltv_expiry_info_below_72() {
    // CLTV expiry 50 blocks ahead → informational
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886150 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(886150, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100); // 50 blocks remaining
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert_eq!(cltv_alerts.len(), 1);
    assert_eq!(cltv_alerts[0].severity, Severity::Informational);
}

#[test]
fn test_cltv_expiry_safe_no_alert() {
    // CLTV expiry 100 blocks ahead → no alert
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886200 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(886200, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100); // 100 blocks remaining
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert!(cltv_alerts.is_empty());
}

#[test]
fn test_cltv_already_expired() {
    // CLTV expiry in the past → critical
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886050 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(886050, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100); // already expired 50 blocks ago
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert_eq!(cltv_alerts.len(), 1);
    assert_eq!(cltv_alerts[0].severity, Severity::Critical);
}

#[test]
fn test_cltv_timestamp_domain_skipped() {
    // CLTV with timestamp domain shouldn't trigger short delta detection
    // (we can only compare block heights meaningfully)
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "1700000100 OP_CHECKLOCKTIMEVERIFY OP_DROP".to_string(),
    );
    let tx = make_tx(1700000100, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    let cltv_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::ShortCltvDelta)
        .collect();
    assert!(cltv_alerts.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Goal 3: HTLC timeout clustering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_clustering_below_threshold_no_alert() {
    // 10 HTLC timeouts in a 6-block window → below default threshold of 85
    let expiries: Vec<u32> = (886100..886106).flat_map(|h| vec![h; 2]).collect(); // 2 per height = 12
    let config = default_config();
    let alerts = detect_htlc_clustering(&expiries, &config);
    assert!(alerts.is_empty());
}

#[test]
fn test_clustering_above_threshold_alert() {
    // 90 HTLC timeouts clustered in a 6-block window → above threshold
    let mut expiries = Vec::new();
    for h in 886100..886106 {
        for _ in 0..15 {
            expiries.push(h); // 15 per height × 6 heights = 90
        }
    }
    let config = default_config();
    let alerts = detect_htlc_clustering(&expiries, &config);
    assert!(!alerts.is_empty());
    assert_eq!(alerts[0].detection_type, DetectionType::HtlcClustering);
    assert_eq!(alerts[0].severity, Severity::Warning);
}

#[test]
fn test_clustering_custom_threshold() {
    // Custom threshold of 10, 12 HTLCs in window → triggers
    let expiries: Vec<u32> = (886100..886106).flat_map(|h| vec![h; 2]).collect();
    let config = SecurityConfig {
        clustering_count_threshold: 10,
        ..default_config()
    };
    let alerts = detect_htlc_clustering(&expiries, &config);
    assert!(!alerts.is_empty());
}

#[test]
fn test_clustering_spread_out_no_alert() {
    // 100 HTLC timeouts but spread across 100 different heights → no clustering
    let expiries: Vec<u32> = (886100..886200).collect();
    let config = SecurityConfig {
        clustering_count_threshold: 10,
        ..default_config()
    };
    let alerts = detect_htlc_clustering(&expiries, &config);
    assert!(alerts.is_empty());
}

#[test]
fn test_clustering_empty_input() {
    let alerts = detect_htlc_clustering(&[], &default_config());
    assert!(alerts.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Goal 4: Anomalous nSequence detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_standard_sequences_no_alert() {
    // 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD → all standard, no alerts
    let tx = make_tx(
        0,
        vec![
            make_vin(0xFFFFFFFF),
            make_vin(0xFFFFFFFE),
            make_vin(0xFFFFFFFD),
        ],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert!(seq_alerts.is_empty());
}

#[test]
fn test_very_short_relative_timelock() {
    // Sequence = 2 → relative timelock of 2 blocks → very short → informational
    let tx = make_tx(
        0,
        vec![make_vin(2)],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert_eq!(seq_alerts.len(), 1);
    assert_eq!(seq_alerts[0].severity, Severity::Informational);
    if let AlertDetails::AnomalousSequence { anomaly, .. } = &seq_alerts[0].details {
        assert_eq!(*anomaly, SequenceAnomaly::VeryShortRelativeTimelock);
    } else {
        panic!("expected AnomalousSequence details");
    }
}

#[test]
fn test_very_long_relative_timelock() {
    // Sequence = 2000 → relative timelock of 2000 blocks → very long → warning
    let tx = make_tx(
        0,
        vec![make_vin(2000)],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert_eq!(seq_alerts.len(), 1);
    assert_eq!(seq_alerts[0].severity, Severity::Warning);
    if let AlertDetails::AnomalousSequence { anomaly, .. } = &seq_alerts[0].details {
        assert_eq!(*anomaly, SequenceAnomaly::VeryLongRelativeTimelock);
    } else {
        panic!("expected AnomalousSequence details");
    }
}

#[test]
fn test_time_based_relative_timelock() {
    // Sequence with bit 22 set → time-based relative timelock → warning (rare in practice)
    let seq = (1 << 22) | 100; // time-based, 100 × 512s
    let tx = make_tx(
        0,
        vec![make_vin(seq)],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert_eq!(seq_alerts.len(), 1);
    if let AlertDetails::AnomalousSequence { anomaly, .. } = &seq_alerts[0].details {
        assert_eq!(*anomaly, SequenceAnomaly::TimeBasedRelativeTimelock);
    } else {
        panic!("expected AnomalousSequence details");
    }
}

#[test]
fn test_normal_csv_144_no_anomaly() {
    // Sequence = 144 → standard Lightning CSV delay → no anomaly
    let tx = make_tx(
        0,
        vec![make_vin(144)],
        vec![make_vout(50_000, "v0_p2wpkh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert!(seq_alerts.is_empty());
}

#[test]
fn test_lightning_sequence_0x80_no_anomaly() {
    // Lightning commitment sequence (0x80 upper byte) → recognized, not anomalous
    let tx = make_tx(
        0x20000042,
        vec![make_vin(0x80000001)],
        vec![make_vout(50_000, "v0_p2wsh")],
    );
    let alerts = run_analysis(&tx, 886100);
    let seq_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.detection_type == DetectionType::AnomalousSequence)
        .collect();
    assert!(seq_alerts.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Goal 5: Alert system structure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alert_has_required_fields() {
    // Any alert produced should have all required fields populated
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886000 OP_CHECKLOCKTIMEVERIFY OP_DROP 4194448 OP_CHECKSEQUENCEVERIFY".to_string(),
    );
    let tx = make_tx(886000, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    assert!(!alerts.is_empty());
    for alert in &alerts {
        assert!(!alert.id.is_empty());
        assert!(!alert.txid.is_empty());
        assert!(!alert.description.is_empty());
    }
}

#[test]
fn test_alert_serializes_to_json() {
    let mut vin = make_vin(2); // short relative timelock
    vin.inner_witnessscript_asm = None;
    let tx = make_tx(0, vec![vin], vec![make_vout(50_000, "v0_p2wpkh")]);
    let alerts = run_analysis(&tx, 886100);
    assert!(!alerts.is_empty());
    let json = serde_json::to_string_pretty(&alerts);
    assert!(json.is_ok());
}

#[test]
fn test_mixing_alert_has_reference() {
    // Timelock mixing alerts should reference Kanjalkar & Poelstra
    let mut vin = make_vin(0xFFFFFFFD);
    vin.inner_witnessscript_asm = Some(
        "886000 OP_CHECKLOCKTIMEVERIFY OP_DROP 4194448 OP_CHECKSEQUENCEVERIFY".to_string(),
    );
    let tx = make_tx(886000, vec![vin], vec![make_vout(50_000, "v0_p2wsh")]);
    let alerts = run_analysis(&tx, 886100);
    let mixing = alerts
        .iter()
        .find(|a| a.detection_type == DetectionType::TimelockMixing)
        .expect("should have mixing alert");
    assert!(mixing.reference.is_some());
    let reference = mixing.reference.as_ref().unwrap();
    assert!(reference.authors.contains("Kanjalkar"));
}
