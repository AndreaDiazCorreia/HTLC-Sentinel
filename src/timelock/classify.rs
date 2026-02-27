use chrono::{DateTime, Utc};

use super::types::{RelativeTimelock, TimelockDomain};

/// Threshold separating block heights from Unix timestamps in nLockTime/CLTV.
const LOCKTIME_THRESHOLD: u64 = 500_000_000;

/// Classify a locktime/CLTV value as block height or timestamp.
pub fn classify_absolute(value: u64) -> TimelockDomain {
    if value < LOCKTIME_THRESHOLD {
        TimelockDomain::BlockHeight
    } else {
        TimelockDomain::Timestamp
    }
}

/// Human-readable description of an absolute timelock value.
pub fn format_absolute(value: u64, domain: TimelockDomain) -> String {
    match domain {
        TimelockDomain::BlockHeight => format!("block {value}"),
        TimelockDomain::Timestamp => {
            let dt = DateTime::<Utc>::from_timestamp(value as i64, 0);
            match dt {
                Some(dt) => format!("{} (Unix {})", dt.format("%Y-%m-%d %H:%M UTC"), value),
                None => format!("timestamp {value} (invalid)"),
            }
        }
    }
}

/// Human-readable description of an nLockTime value including active/disabled status.
pub fn format_nlocktime(value: u32, active: bool) -> String {
    if value == 0 {
        return "none (0)".to_string();
    }

    let domain = classify_absolute(value as u64);
    let base = format_absolute(value as u64, domain);

    if active {
        base
    } else {
        format!("{base} [disabled — all inputs final]")
    }
}

// BIP 68 constants
const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

/// Parse BIP 68 relative timelock from a sequence value.
/// Returns None if bit 31 is set (relative timelock disabled).
pub fn parse_relative_timelock(sequence: u32) -> Option<RelativeTimelock> {
    if sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return None;
    }

    let value = (sequence & SEQUENCE_LOCKTIME_MASK) as u16;

    if sequence & SEQUENCE_TYPE_FLAG != 0 {
        // Time-based: each unit = 512 seconds
        let total_seconds = value as u64 * 512;
        let human = format_duration_approx(total_seconds);
        Some(RelativeTimelock {
            domain: TimelockDomain::Timestamp,
            value,
            human_readable: format!("{value} × 512s ({human})"),
        })
    } else {
        // Block-based
        let human = format_blocks_approx(value as u64);
        Some(RelativeTimelock {
            domain: TimelockDomain::BlockHeight,
            value,
            human_readable: format!("{value} blocks ({human})"),
        })
    }
}

/// Approximate human-readable duration from seconds.
fn format_duration_approx(seconds: u64) -> String {
    if seconds < 3600 {
        format!("~{} min", seconds / 60)
    } else if seconds < 86400 {
        format!("~{:.1} hours", seconds as f64 / 3600.0)
    } else {
        format!("~{:.1} days", seconds as f64 / 86400.0)
    }
}

/// Approximate human-readable duration from block count (~10 min/block).
fn format_blocks_approx(blocks: u64) -> String {
    let minutes = blocks * 10;
    if minutes < 60 {
        format!("~{minutes} min")
    } else if minutes < 1440 {
        format!("~{:.1} hours", minutes as f64 / 60.0)
    } else {
        format!("~{:.1} days", minutes as f64 / 1440.0)
    }
}
