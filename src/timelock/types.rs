use serde::Serialize;

/// Domain of a timelock value: block height or Unix timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockDomain {
    BlockHeight,
    Timestamp,
}

/// Classification of the nLockTime field.
#[derive(Debug, Clone, Serialize)]
pub struct NLocktimeInfo {
    pub raw_value: u32,
    pub domain: Option<TimelockDomain>,
    /// Whether nLockTime is enforced (at least one input has sequence != 0xFFFFFFFF).
    pub active: bool,
    pub human_readable: String,
}

/// Classification of a single input's nSequence field.
#[derive(Debug, Clone, Serialize)]
pub struct SequenceInfo {
    pub input_index: usize,
    pub raw_value: u32,
    pub raw_hex: String,
    /// What this sequence value means in practice.
    pub meaning: SequenceMeaning,
    /// BIP 68 relative timelock, if encoded.
    pub relative_timelock: Option<RelativeTimelock>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceMeaning {
    /// 0xFFFFFFFF — final, disables nLockTime, no RBF.
    Final,
    /// 0xFFFFFFFE — enables nLockTime, no RBF signaling.
    LocktimeEnabled,
    /// 0xFFFFFFFD — enables nLockTime and RBF signaling.
    RbfEnabled,
    /// Has BIP 68 relative timelock.
    RelativeTimelock,
    /// Non-standard value without BIP 68 encoding (bit 31 set but not a standard value).
    NonStandard,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelativeTimelock {
    pub domain: TimelockDomain,
    pub value: u16,
    pub human_readable: String,
}

/// A timelock opcode found in a script.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptTimelock {
    pub input_index: usize,
    pub script_field: String,
    pub opcode: String,
    pub raw_value: u64,
    pub domain: TimelockDomain,
    pub human_readable: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub has_active_timelocks: bool,
    pub nlocktime_active: bool,
    pub relative_timelock_count: usize,
    pub cltv_count: usize,
    pub csv_count: usize,
}

/// Complete timelock analysis for a single transaction.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionAnalysis {
    pub txid: String,
    pub nlocktime: NLocktimeInfo,
    pub inputs: Vec<SequenceInfo>,
    pub cltv_timelocks: Vec<ScriptTimelock>,
    pub csv_timelocks: Vec<ScriptTimelock>,
    pub summary: AnalysisSummary,
}
