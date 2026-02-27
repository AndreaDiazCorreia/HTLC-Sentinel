use super::types::*;
use crate::lightning::types::{Confidence, LightningClassification, LightningTxType};
use crate::timelock::types::{TimelockDomain, TransactionAnalysis};

/// Run all security detections on a single transaction.
pub fn analyze_transaction(
    timelock: &TransactionAnalysis,
    lightning: &LightningClassification,
    current_height: u64,
    config: &SecurityConfig,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let txid = &timelock.txid;

    detect_timelock_mixing(txid, timelock, &mut alerts);
    detect_short_cltv_delta(txid, timelock, current_height, config, &mut alerts);
    detect_anomalous_sequences(txid, timelock, lightning, config, &mut alerts);

    alerts
}

/// Detect HTLC timeout clustering across multiple transactions.
pub fn detect_htlc_clustering(htlc_expiries: &[u32], config: &SecurityConfig) -> Vec<Alert> {
    if htlc_expiries.is_empty() {
        return Vec::new();
    }

    let mut sorted = htlc_expiries.to_vec();
    sorted.sort();

    let mut alerts = Vec::new();

    // Sliding window: count expiries within each window of `clustering_window_size` blocks
    let min_height = sorted[0];
    let max_height = *sorted.last().unwrap();

    let mut window_start = min_height;
    while window_start <= max_height {
        let window_end = window_start + config.clustering_window_size - 1;
        let count = sorted
            .iter()
            .filter(|&&h| h >= window_start && h <= window_end)
            .count();

        if count >= config.clustering_count_threshold {
            alerts.push(Alert {
                id: format!("htlc-cluster-{window_start}-{window_end}"),
                severity: Severity::Warning,
                detection_type: DetectionType::HtlcClustering,
                txid: String::new(), // clustering is cross-transaction
                input_index: None,
                description: format!(
                    "HTLC timeout clustering: {count} HTLCs expiring in blocks {window_start}–{window_end} \
                     (threshold: {}). Consistent with flood-and-loot attack staging.",
                    config.clustering_count_threshold
                ),
                details: AlertDetails::HtlcClustering {
                    window_start,
                    window_end,
                    count,
                    threshold: config.clustering_count_threshold,
                },
                reference: Some(AttackReference {
                    name: "Flood & Loot".to_string(),
                    authors: "Harris & Zohar".to_string(),
                    year: 2020,
                    url: Some("https://arxiv.org/abs/2006.08513".to_string()),
                }),
            });
            // Skip ahead past this window to avoid duplicate alerts for overlapping windows
            window_start = window_end + 1;
        } else {
            window_start += 1;
        }
    }

    alerts
}

// ─── Timelock mixing ─────────────────────────────────────────────────────────

fn detect_timelock_mixing(txid: &str, timelock: &TransactionAnalysis, alerts: &mut Vec<Alert>) {
    // Check 1: CLTV vs CSV domain mixing within scripts
    for cltv in &timelock.cltv_timelocks {
        for csv in &timelock.csv_timelocks {
            // CLTV is absolute (height vs timestamp), CSV is relative (height vs time)
            // Mixing = one is height-based, the other is time-based
            if cltv.domain != csv.domain {
                alerts.push(make_mixing_alert(
                    txid,
                    Some(cltv.input_index),
                    &format!("{:?}", cltv.domain),
                    &format!("{:?}", csv.domain),
                    Some(cltv.script_field.clone()),
                ));
                return; // One mixing alert per tx is enough
            }
        }
    }

    // Check 2: nLockTime domain vs CLTV domain
    if let Some(nlocktime_domain) = timelock.nlocktime.domain {
        if timelock.nlocktime.active {
            for cltv in &timelock.cltv_timelocks {
                if nlocktime_domain != cltv.domain {
                    alerts.push(make_mixing_alert(
                        txid,
                        Some(cltv.input_index),
                        &format!("nLockTime={:?}", nlocktime_domain),
                        &format!("CLTV={:?}", cltv.domain),
                        Some(cltv.script_field.clone()),
                    ));
                    return;
                }
            }
        }
    }

    // Check 3: nSequence domain vs CSV domain
    for input in &timelock.inputs {
        if let Some(ref rtl) = input.relative_timelock {
            for csv in &timelock.csv_timelocks {
                if rtl.domain != csv.domain {
                    alerts.push(make_mixing_alert(
                        txid,
                        Some(input.input_index),
                        &format!("nSequence={:?}", rtl.domain),
                        &format!("CSV={:?}", csv.domain),
                        Some(csv.script_field.clone()),
                    ));
                    return;
                }
            }
        }
    }
}

fn make_mixing_alert(
    txid: &str,
    input_index: Option<usize>,
    absolute_domain: &str,
    relative_domain: &str,
    script_field: Option<String>,
) -> Alert {
    Alert {
        id: format!("mixing-{txid}-{}", input_index.unwrap_or(0)),
        severity: Severity::Critical,
        detection_type: DetectionType::TimelockMixing,
        txid: txid.to_string(),
        input_index,
        description: format!(
            "Dangerous timelock mixing detected: {absolute_domain} vs {relative_domain}. \
             Funds may be permanently unspendable."
        ),
        details: AlertDetails::TimelockMixing {
            absolute_domain: absolute_domain.to_string(),
            relative_domain: relative_domain.to_string(),
            script_field,
        },
        reference: Some(AttackReference {
            name: "Don't Mix Your Timelocks".to_string(),
            authors: "Kanjalkar & Poelstra (Blockstream Research)".to_string(),
            year: 2022,
            url: Some(
                "https://blog.blockstream.com/dont-mix-your-timelocks/".to_string(),
            ),
        }),
    }
}

// ─── Short CLTV delta ────────────────────────────────────────────────────────

fn detect_short_cltv_delta(
    txid: &str,
    timelock: &TransactionAnalysis,
    current_height: u64,
    config: &SecurityConfig,
    alerts: &mut Vec<Alert>,
) {
    for cltv in &timelock.cltv_timelocks {
        // Only check block-height domain (can't compare timestamps to block heights)
        if cltv.domain != TimelockDomain::BlockHeight {
            continue;
        }

        let expiry = cltv.raw_value as u32;
        let blocks_remaining = expiry as i64 - current_height as i64;

        let severity = if blocks_remaining <= 0 {
            Severity::Critical
        } else if (blocks_remaining as u32) < config.cltv_critical_threshold {
            Severity::Critical
        } else if (blocks_remaining as u32) < config.cltv_warning_threshold {
            Severity::Warning
        } else if (blocks_remaining as u32) < config.cltv_info_threshold {
            Severity::Informational
        } else {
            continue; // Safe, no alert
        };

        let desc = if blocks_remaining <= 0 {
            format!(
                "CLTV timelock at block {expiry} has expired ({} blocks ago). \
                 Time-sensitive spending condition is now active.",
                -blocks_remaining
            )
        } else {
            format!(
                "CLTV timelock at block {expiry} expires in {blocks_remaining} blocks. \
                 Below safe threshold for on-chain resolution."
            )
        };

        alerts.push(Alert {
            id: format!("short-cltv-{txid}-{}-{expiry}", cltv.input_index),
            severity,
            detection_type: DetectionType::ShortCltvDelta,
            txid: txid.to_string(),
            input_index: Some(cltv.input_index),
            description: desc,
            details: AlertDetails::ShortCltvDelta {
                cltv_expiry: expiry,
                current_height,
                blocks_remaining,
            },
            reference: None,
        });
    }
}

// ─── Anomalous nSequence ─────────────────────────────────────────────────────

const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

fn detect_anomalous_sequences(
    txid: &str,
    timelock: &TransactionAnalysis,
    lightning: &LightningClassification,
    config: &SecurityConfig,
    alerts: &mut Vec<Alert>,
) {
    // Skip Lightning commitment transactions — their sequences are expected to be non-standard
    if lightning.tx_type == Some(LightningTxType::Commitment)
        && lightning.confidence >= Confidence::Possible
    {
        return;
    }

    for input in &timelock.inputs {
        let seq = input.raw_value;

        // Standard values — skip
        if matches!(seq, 0xFFFFFFFF | 0xFFFFFFFE | 0xFFFFFFFD) {
            continue;
        }

        // Bit 31 set means no relative timelock (but it's not a standard value)
        if seq & SEQUENCE_DISABLE_FLAG != 0 {
            // Lightning commitment sequences (0x80 upper byte) are handled above
            // Any other disabled-but-nonstandard pattern
            if (seq >> 24) != 0x80 {
                alerts.push(make_sequence_alert(
                    txid,
                    input.input_index,
                    seq,
                    SequenceAnomaly::UnknownPattern,
                    Severity::Informational,
                ));
            }
            continue;
        }

        // BIP 68 relative timelock — check for anomalies
        let is_time_based = seq & SEQUENCE_TYPE_FLAG != 0;
        let value = (seq & SEQUENCE_LOCKTIME_MASK) as u16;

        if is_time_based {
            alerts.push(make_sequence_alert(
                txid,
                input.input_index,
                seq,
                SequenceAnomaly::TimeBasedRelativeTimelock,
                Severity::Warning,
            ));
        } else if value < config.sequence_short_threshold {
            alerts.push(make_sequence_alert(
                txid,
                input.input_index,
                seq,
                SequenceAnomaly::VeryShortRelativeTimelock,
                Severity::Informational,
            ));
        } else if value > config.sequence_long_threshold {
            alerts.push(make_sequence_alert(
                txid,
                input.input_index,
                seq,
                SequenceAnomaly::VeryLongRelativeTimelock,
                Severity::Warning,
            ));
        }
        // Normal range (6–1000 blocks) → no alert
    }
}

fn make_sequence_alert(
    txid: &str,
    input_index: usize,
    raw_value: u32,
    anomaly: SequenceAnomaly,
    severity: Severity,
) -> Alert {
    let desc = match anomaly {
        SequenceAnomaly::VeryShortRelativeTimelock => format!(
            "Input {input_index} has a very short relative timelock ({} blocks). \
             May indicate minimized revocation window.",
            raw_value & SEQUENCE_LOCKTIME_MASK
        ),
        SequenceAnomaly::VeryLongRelativeTimelock => format!(
            "Input {input_index} has a very long relative timelock ({} blocks ≈ {:.0} days). \
             Unusual — may indicate specialized custody or misconfiguration.",
            raw_value & SEQUENCE_LOCKTIME_MASK,
            (raw_value & SEQUENCE_LOCKTIME_MASK) as f64 * 10.0 / 1440.0
        ),
        SequenceAnomaly::TimeBasedRelativeTimelock => format!(
            "Input {input_index} uses time-based relative timelock (rare). \
             Value: {} × 512s.",
            raw_value & SEQUENCE_LOCKTIME_MASK
        ),
        SequenceAnomaly::UnknownPattern => format!(
            "Input {input_index} has non-standard sequence 0x{raw_value:08X} that doesn't match \
             any known pattern."
        ),
    };

    Alert {
        id: format!("seq-{txid}-{input_index}"),
        severity,
        detection_type: DetectionType::AnomalousSequence,
        txid: txid.to_string(),
        input_index: Some(input_index),
        description: desc,
        details: AlertDetails::AnomalousSequence {
            raw_value,
            raw_hex: format!("0x{raw_value:08X}"),
            anomaly,
        },
        reference: None,
    }
}
