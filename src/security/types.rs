use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    TimelockMixing,
    ShortCltvDelta,
    HtlcClustering,
    AnomalousSequence,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackReference {
    pub name: String,
    pub authors: String,
    pub year: u16,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: String,
    pub severity: Severity,
    pub detection_type: DetectionType,
    pub txid: String,
    pub input_index: Option<usize>,
    pub description: String,
    pub details: AlertDetails,
    pub reference: Option<AttackReference>,
}

/// Detection-specific data attached to each alert.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertDetails {
    TimelockMixing {
        absolute_domain: String,
        relative_domain: String,
        script_field: Option<String>,
    },
    ShortCltvDelta {
        cltv_expiry: u32,
        current_height: u64,
        blocks_remaining: i64,
    },
    HtlcClustering {
        window_start: u32,
        window_end: u32,
        count: usize,
        threshold: usize,
    },
    AnomalousSequence {
        raw_value: u32,
        raw_hex: String,
        anomaly: SequenceAnomaly,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceAnomaly {
    VeryShortRelativeTimelock,
    VeryLongRelativeTimelock,
    TimeBasedRelativeTimelock,
    UnknownPattern,
}

/// Configurable thresholds for security detections.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// CLTV delta thresholds (blocks remaining)
    pub cltv_critical_threshold: u32,
    pub cltv_warning_threshold: u32,
    pub cltv_info_threshold: u32,

    /// HTLC clustering
    pub clustering_window_size: u32,
    pub clustering_count_threshold: usize,

    /// Sequence anomalies
    pub sequence_short_threshold: u16,
    pub sequence_long_threshold: u16,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            cltv_critical_threshold: 18,  // below minimum final hop delta
            cltv_warning_threshold: 34,   // below BOLT recommendation
            cltv_info_threshold: 72,      // congestion risk range

            clustering_window_size: 6,
            clustering_count_threshold: 85, // from Harris & Zohar 2020

            sequence_short_threshold: 6,
            sequence_long_threshold: 1000,
        }
    }
}
