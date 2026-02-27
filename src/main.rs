use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;

use cltv_scan::api::cache::CachedClient;
use cltv_scan::api::client::MempoolClient;
use cltv_scan::api::source::DataSource;
use cltv_scan::cli::output;
use cltv_scan::lightning::detector::classify_lightning;
use cltv_scan::lightning::types::LightningTxType;
use cltv_scan::security::analyzer;
use cltv_scan::security::types::{SecurityConfig, Severity};
use cltv_scan::server;
use cltv_scan::timelock::extractor::analyze_transaction;

#[derive(Parser)]
#[command(name = "cltv-scan", about = "Bitcoin timelock vulnerability scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze timelocks in a single transaction
    Tx {
        /// Transaction ID to analyze
        txid: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Scan all transactions in a block for timelocks
    Block {
        /// Block height to scan
        height: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Lightning Network transaction identification
    Lightning {
        #[command(subcommand)]
        command: LightningCommands,
    },
    /// Start HTTP server exposing all analysis as JSON API
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value_t = 3001)]
        port: u16,
        /// mempool.space API base URL
        #[arg(long, default_value = "https://mempool.space")]
        mempool_url: String,
        /// Request delay in milliseconds (rate limiting)
        #[arg(long, default_value_t = 250)]
        request_delay_ms: u64,
    },
    /// Monitor the mempool in real-time for timelock activity
    Monitor {
        /// Polling interval in seconds
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Minimum severity to display (info, warning, critical)
        #[arg(long)]
        min_severity: Option<String>,
        /// CLTV critical threshold (blocks remaining)
        #[arg(long, default_value_t = 18)]
        cltv_critical: u32,
        /// CLTV warning threshold (blocks remaining)
        #[arg(long, default_value_t = 34)]
        cltv_warning: u32,
        /// CLTV info threshold (blocks remaining)
        #[arg(long, default_value_t = 72)]
        cltv_info: u32,
    },
    /// Security scan for attack patterns and vulnerabilities
    Scan {
        /// Start block height
        start: u64,
        /// End block height (inclusive). Defaults to start (single block).
        #[arg(short, long)]
        end: Option<u64>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// CLTV critical threshold (blocks remaining)
        #[arg(long, default_value_t = 18)]
        cltv_critical: u32,
        /// CLTV warning threshold (blocks remaining)
        #[arg(long, default_value_t = 34)]
        cltv_warning: u32,
        /// CLTV info threshold (blocks remaining)
        #[arg(long, default_value_t = 72)]
        cltv_info: u32,
        /// HTLC clustering window size (blocks)
        #[arg(long, default_value_t = 6)]
        cluster_window: u32,
        /// HTLC clustering count threshold
        #[arg(long, default_value_t = 85)]
        cluster_threshold: usize,
    },
}

#[derive(Subcommand)]
enum LightningCommands {
    /// Classify a single transaction as Lightning-related
    Tx {
        /// Transaction ID to classify
        txid: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Scan a block for Lightning Network activity
    Block {
        /// Block height to scan
        height: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = MempoolClient::default();

    match cli.command {
        Commands::Tx { txid, json } => {
            let tx = client.get_transaction(&txid).await?;
            let analysis = analyze_transaction(&tx);

            if json {
                println!("{}", serde_json::to_string_pretty(&analysis)?);
            } else {
                output::print_transaction_analysis(&analysis);
            }
        }
        Commands::Block { height, json } => {
            eprintln!("Fetching block {height}...");
            let txs = client.get_all_block_txs(height).await?;
            eprintln!("Analyzing {} transactions...", txs.len());

            let analyses: Vec<_> = txs.iter().map(|tx| analyze_transaction(tx)).collect();

            if json {
                println!("{}", serde_json::to_string_pretty(&analyses)?);
            } else {
                output::print_block_summary(height, &analyses);
            }
        }
        Commands::Lightning { command } => match command {
            LightningCommands::Tx { txid, json } => {
                let tx = client.get_transaction(&txid).await?;
                let result = classify_lightning(&tx);

                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    output::print_lightning_classification(&txid, &result);
                }
            }
            LightningCommands::Block { height, json } => {
                eprintln!("Fetching block {height}...");
                let txs = client.get_all_block_txs(height).await?;
                eprintln!("Classifying {} transactions...", txs.len());

                let results: Vec<_> = txs
                    .iter()
                    .map(|tx| (tx.txid.clone(), classify_lightning(tx)))
                    .collect();

                if json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    output::print_lightning_block_summary(height, &results);
                }
            }
        },
        Commands::Serve {
            port,
            mempool_url,
            request_delay_ms,
        } => {
            let client = MempoolClient::new(&mempool_url, Duration::from_millis(request_delay_ms));
            let cached = CachedClient::new(client, 10_000);
            let config = SecurityConfig::default();
            let app = server::create_router(cached, config);

            let addr = format!("0.0.0.0:{port}");
            eprintln!("Starting server on {addr}");
            eprintln!("  mempool.space: {mempool_url}");
            eprintln!("  Endpoints:");
            eprintln!("    GET /api/tx/{{txid}}");
            eprintln!("    GET /api/block/{{height}}?filter=timelocks&offset=0&limit=100");
            eprintln!("    GET /api/scan?start={{height}}&end={{height}}&severity=critical&detection_type=timelock_mixing");
            eprintln!("    GET /api/lightning?start={{height}}&end={{height}}");

            let listener = TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
            return Ok(());
        }
        Commands::Monitor {
            interval,
            json,
            min_severity,
            cltv_critical,
            cltv_warning,
            cltv_info,
        } => {
            let min_sev = match min_severity.as_deref() {
                Some("critical") => Severity::Critical,
                Some("warning") => Severity::Warning,
                _ => Severity::Informational,
            };
            let config = SecurityConfig {
                cltv_critical_threshold: cltv_critical,
                cltv_warning_threshold: cltv_warning,
                cltv_info_threshold: cltv_info,
                ..SecurityConfig::default()
            };

            eprintln!("Monitoring mempool (every {interval}s, Ctrl+C to stop)...");
            eprintln!();

            let mut seen = HashSet::new();
            let poll_interval = Duration::from_secs(interval);

            loop {
                let current_height = match client.get_block_tip_height().await {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("error fetching tip: {e}");
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };

                let txids = match client.get_mempool_recent_txids().await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("error fetching mempool: {e}");
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };

                for txid in &txids {
                    if !seen.insert(txid.clone()) {
                        continue;
                    }

                    let tx = match client.get_transaction(txid).await {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("error fetching tx {txid}: {e}");
                            continue;
                        }
                    };

                    let timelock = analyze_transaction(&tx);
                    let lightning = classify_lightning(&tx);
                    let alerts = analyzer::analyze_transaction(
                        &timelock,
                        &lightning,
                        current_height,
                        &config,
                    );

                    let alerts: Vec<_> = alerts
                        .into_iter()
                        .filter(|a| a.severity >= min_sev)
                        .collect();

                    let dominated =
                        !alerts.is_empty()
                        || lightning.tx_type.is_some()
                        || timelock.summary.has_active_timelocks;

                    if !dominated {
                        continue;
                    }

                    if json {
                        let entry = serde_json::json!({
                            "txid": txid,
                            "timelock": timelock,
                            "lightning": lightning,
                            "alerts": alerts,
                        });
                        println!("{}", serde_json::to_string(&entry)?);
                    } else {
                        output::print_monitor_hit(&timelock, &lightning, &alerts);
                    }
                }

                // Cap seen set to avoid unbounded growth
                if seen.len() > 10_000 {
                    seen.clear();
                }

                tokio::time::sleep(poll_interval).await;
            }
        }
        Commands::Scan {
            start,
            end,
            json,
            cltv_critical,
            cltv_warning,
            cltv_info,
            cluster_window,
            cluster_threshold,
        } => {
            let end = end.unwrap_or(start);
            let config = SecurityConfig {
                cltv_critical_threshold: cltv_critical,
                cltv_warning_threshold: cltv_warning,
                cltv_info_threshold: cltv_info,
                clustering_window_size: cluster_window,
                clustering_count_threshold: cluster_threshold,
                ..SecurityConfig::default()
            };

            let current_height = client.get_block_tip_height().await?;
            eprintln!("Current tip: block {current_height}");

            let mut all_alerts = Vec::new();
            let mut htlc_expiries = Vec::new();

            for height in start..=end {
                eprintln!("Scanning block {height}...");
                let txs = client.get_all_block_txs(height).await?;
                eprintln!("  {} transactions", txs.len());

                for tx in &txs {
                    let timelock = analyze_transaction(tx);
                    let lightning = classify_lightning(tx);

                    // Collect HTLC expiries for clustering analysis
                    if lightning.tx_type == Some(LightningTxType::HtlcTimeout) {
                        if let Some(expiry) = lightning.params.cltv_expiry {
                            htlc_expiries.push(expiry);
                        }
                    }

                    let mut alerts =
                        analyzer::analyze_transaction(&timelock, &lightning, current_height, &config);
                    all_alerts.append(&mut alerts);
                }
            }

            // Cross-transaction clustering analysis
            let mut cluster_alerts = analyzer::detect_htlc_clustering(&htlc_expiries, &config);
            all_alerts.append(&mut cluster_alerts);

            // Sort by severity (critical first)
            all_alerts.sort_by(|a, b| b.severity.cmp(&a.severity));

            if json {
                println!("{}", serde_json::to_string_pretty(&all_alerts)?);
            } else {
                output::print_security_scan(start, end, &all_alerts);
            }
        }
    }

    Ok(())
}
