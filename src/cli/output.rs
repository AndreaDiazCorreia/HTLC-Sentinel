use crate::timelock::types::{SequenceMeaning, TransactionAnalysis};

pub fn print_transaction_analysis(analysis: &TransactionAnalysis) {
    println!("Transaction: {}", analysis.txid);
    println!("{}", "─".repeat(72));

    // nLockTime
    println!(
        "nLockTime:   {} {}",
        analysis.nlocktime.human_readable,
        if analysis.nlocktime.raw_value > 0 {
            format!("(raw: {})", analysis.nlocktime.raw_value)
        } else {
            String::new()
        }
    );
    println!();

    // Inputs / sequences
    println!("Inputs ({}):", analysis.inputs.len());
    for input in &analysis.inputs {
        let meaning = match &input.meaning {
            SequenceMeaning::Final => "final".to_string(),
            SequenceMeaning::LocktimeEnabled => "locktime enabled".to_string(),
            SequenceMeaning::RbfEnabled => "RBF + locktime".to_string(),
            SequenceMeaning::RelativeTimelock => {
                if let Some(ref rtl) = input.relative_timelock {
                    format!("relative timelock: {}", rtl.human_readable)
                } else {
                    "relative timelock".to_string()
                }
            }
            SequenceMeaning::NonStandard => "non-standard".to_string(),
        };
        println!("  [{}] {} — {}", input.input_index, input.raw_hex, meaning);
    }

    // CLTV
    if !analysis.cltv_timelocks.is_empty() {
        println!();
        println!("OP_CHECKLOCKTIMEVERIFY ({}):", analysis.cltv_timelocks.len());
        for tl in &analysis.cltv_timelocks {
            println!(
                "  input[{}] {}: {} (raw: {})",
                tl.input_index, tl.script_field, tl.human_readable, tl.raw_value
            );
        }
    }

    // CSV
    if !analysis.csv_timelocks.is_empty() {
        println!();
        println!("OP_CHECKSEQUENCEVERIFY ({}):", analysis.csv_timelocks.len());
        for tl in &analysis.csv_timelocks {
            println!(
                "  input[{}] {}: {} (raw: {})",
                tl.input_index, tl.script_field, tl.human_readable, tl.raw_value
            );
        }
    }

    // Summary
    println!();
    if analysis.summary.has_active_timelocks {
        let mut parts = Vec::new();
        if analysis.summary.nlocktime_active {
            parts.push("nLockTime".to_string());
        }
        if analysis.summary.relative_timelock_count > 0 {
            parts.push(format!("{} nSequence", analysis.summary.relative_timelock_count));
        }
        if analysis.summary.cltv_count > 0 {
            parts.push(format!("{} CLTV", analysis.summary.cltv_count));
        }
        if analysis.summary.csv_count > 0 {
            parts.push(format!("{} CSV", analysis.summary.csv_count));
        }
        println!("Active timelocks: {}", parts.join(", "));
    } else {
        println!("No active timelocks.");
    }
}

pub fn print_block_summary(height: u64, analyses: &[TransactionAnalysis]) {
    let total = analyses.len();
    let with_timelocks: Vec<_> = analyses.iter().filter(|a| a.summary.has_active_timelocks).collect();

    println!("Block {height}");
    println!("{}", "═".repeat(72));
    println!(
        "{total} transactions, {} with active timelocks",
        with_timelocks.len()
    );
    println!();

    if with_timelocks.is_empty() {
        println!("No active timelocks found in this block.");
        return;
    }

    for analysis in &with_timelocks {
        print_transaction_analysis(analysis);
        println!();
    }
}
