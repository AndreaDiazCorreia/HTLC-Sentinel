use super::classify::{classify_absolute, format_absolute, format_nlocktime, parse_relative_timelock};
use super::types::*;
use crate::api::types::ApiTransaction;

/// Analyze a transaction for all four timelock types.
pub fn analyze_transaction(tx: &ApiTransaction) -> TransactionAnalysis {
    let nlocktime = extract_nlocktime(tx);
    let inputs = extract_sequences(tx);
    let cltv_timelocks = extract_script_timelocks(tx, TimelockOpcode::Cltv);
    let csv_timelocks = extract_script_timelocks(tx, TimelockOpcode::Csv);

    let relative_timelock_count = inputs.iter().filter(|i| i.relative_timelock.is_some()).count();

    let summary = AnalysisSummary {
        has_active_timelocks: nlocktime.active && nlocktime.raw_value > 0
            || relative_timelock_count > 0
            || !cltv_timelocks.is_empty()
            || !csv_timelocks.is_empty(),
        nlocktime_active: nlocktime.active && nlocktime.raw_value > 0,
        relative_timelock_count,
        cltv_count: cltv_timelocks.len(),
        csv_count: csv_timelocks.len(),
    };

    TransactionAnalysis {
        txid: tx.txid.clone(),
        nlocktime,
        inputs,
        cltv_timelocks,
        csv_timelocks,
        summary,
    }
}

fn extract_nlocktime(tx: &ApiTransaction) -> NLocktimeInfo {
    let value = tx.locktime;
    let active = tx.vin.iter().any(|input| input.sequence != 0xFFFFFFFF);

    let (domain, human_readable) = if value == 0 {
        (None, format_nlocktime(value, active))
    } else {
        let d = classify_absolute(value as u64);
        (Some(d), format_nlocktime(value, active))
    };

    NLocktimeInfo {
        raw_value: value,
        domain,
        active,
        human_readable,
    }
}

fn extract_sequences(tx: &ApiTransaction) -> Vec<SequenceInfo> {
    tx.vin
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let seq = input.sequence;
            let relative_timelock = parse_relative_timelock(seq);

            let meaning = match seq {
                0xFFFFFFFF => SequenceMeaning::Final,
                0xFFFFFFFE => SequenceMeaning::LocktimeEnabled,
                0xFFFFFFFD => SequenceMeaning::RbfEnabled,
                _ if relative_timelock.is_some() => SequenceMeaning::RelativeTimelock,
                _ => SequenceMeaning::NonStandard,
            };

            SequenceInfo {
                input_index: i,
                raw_value: seq,
                raw_hex: format!("0x{seq:08X}"),
                meaning,
                relative_timelock,
            }
        })
        .collect()
}

enum TimelockOpcode {
    Cltv,
    Csv,
}

impl TimelockOpcode {
    fn patterns(&self) -> &[&str] {
        match self {
            Self::Cltv => &["OP_CHECKLOCKTIMEVERIFY", "OP_CLTV"],
            Self::Csv => &["OP_CHECKSEQUENCEVERIFY", "OP_CSV"],
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Cltv => "OP_CHECKLOCKTIMEVERIFY",
            Self::Csv => "OP_CHECKSEQUENCEVERIFY",
        }
    }
}

fn extract_script_timelocks(tx: &ApiTransaction, opcode: TimelockOpcode) -> Vec<ScriptTimelock> {
    let mut results = Vec::new();

    for (input_idx, input) in tx.vin.iter().enumerate() {
        let script_fields: Vec<(&str, &Option<String>)> = vec![
            ("scriptsig_asm", &input.scriptsig_asm),
            ("inner_redeemscript_asm", &input.inner_redeemscript_asm),
            ("inner_witnessscript_asm", &input.inner_witnessscript_asm),
        ];

        for (field_name, field_value) in script_fields {
            if let Some(asm) = field_value {
                let found = extract_timelock_from_asm(asm, &opcode);
                for value in found {
                    let domain = match &opcode {
                        TimelockOpcode::Cltv => classify_absolute(value),
                        TimelockOpcode::Csv => {
                            // CSV values use BIP 68 encoding
                            if value & (1 << 22) != 0 {
                                TimelockDomain::Timestamp
                            } else {
                                TimelockDomain::BlockHeight
                            }
                        }
                    };

                    let human_readable = match &opcode {
                        TimelockOpcode::Cltv => format_absolute(value, domain),
                        TimelockOpcode::Csv => {
                            let masked = (value & 0xFFFF) as u16;
                            if domain == TimelockDomain::Timestamp {
                                let secs = masked as u64 * 512;
                                format!("{masked} × 512s (~{:.1} hours)", secs as f64 / 3600.0)
                            } else {
                                format!("{masked} blocks (~{:.1} hours)", masked as f64 * 10.0 / 60.0)
                            }
                        }
                    };

                    results.push(ScriptTimelock {
                        input_index: input_idx,
                        script_field: field_name.to_string(),
                        opcode: opcode.name().to_string(),
                        raw_value: value,
                        domain,
                        human_readable,
                    });
                }
            }
        }
    }

    results
}

/// Extract timelock values from an ASM string by finding the push immediately before the opcode.
fn extract_timelock_from_asm(asm: &str, opcode: &TimelockOpcode) -> Vec<u64> {
    let tokens: Vec<&str> = asm.split_whitespace().collect();
    let mut values = Vec::new();

    for (i, token) in tokens.iter().enumerate() {
        let is_match = opcode.patterns().iter().any(|p| token == p);
        if is_match && i > 0 {
            // The preceding token should be the numeric push
            let prev = tokens[i - 1];
            // Try parsing as decimal first, then as hex with OP_PUSHBYTES prefix stripped
            if let Ok(v) = prev.parse::<u64>() {
                values.push(v);
            } else if let Ok(v) = parse_script_number(prev) {
                values.push(v);
            }
        }
    }

    values
}

/// Parse a hex-encoded script number (little-endian) as used in Bitcoin Script.
fn parse_script_number(hex: &str) -> Result<u64, ()> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;

    if bytes.is_empty() {
        return Err(());
    }

    // Bitcoin script numbers are little-endian with sign bit in the MSB of the last byte
    let negative = bytes.last().map_or(false, |b| b & 0x80 != 0);
    if negative {
        return Err(()); // Timelock values shouldn't be negative
    }

    let mut value: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        value |= (byte as u64) << (8 * i);
    }

    Ok(value)
}
