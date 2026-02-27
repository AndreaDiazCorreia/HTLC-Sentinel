# Bitcoin timelock analysis: tools, attacks, and the technical landscape

**No dedicated Bitcoin timelock security analyzer exists today.** Despite a rich body of research documenting at least nine distinct timelock-related attack vectors — from flood-and-loot to replacement cycling — the ecosystem lacks a single tool that systematically scans transactions or scripts for timelock vulnerabilities. The space is instead covered by a patchwork of script debuggers, Miniscript compilers, block explorers, and Lightning monitoring tools that each address a fragment of the problem. The building blocks for such a tool are mature: rust-bitcoin provides comprehensive timelock parsing, mempool.space exposes all timelock-relevant transaction fields via its API, and Shakespeare.diy can rapidly prototype a frontend dashboard. This report maps the full landscape.

---

## No dedicated timelock security tool exists, but the fragments are there

After extensive searching across GitHub, academic sources, and Bitcoin developer forums, **no standalone tool specifically performs security analysis of Bitcoin timelocks for attack vectors**. No automated scanner identifies misconfigured timelocks, dangerously short CLTV deltas, mixed height/time timelocks, or simulates timelock attacks.

What does exist falls into several categories. **Script debuggers** like btcdeb (github.com/bitcoin-core/btcdeb, ~532 stars) can step through OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY execution with full transaction context. **Miniscript tools** — Pieter Wuille's compiler at bitcoin.sipa.be/miniscript, rust-miniscript, @bitcoinerlab/miniscript, and Miniscript Studio at adys.dev/miniscript — provide the closest thing to timelock security analysis by detecting dangerous timelock mixing (height + timestamp in the same script path) that can make scripts permanently unspendable. This vulnerability was documented in Blockstream Research's "Don't Mix Your Timelocks" by Sanket Kanjalkar and Andrew Poelstra.

**Block explorers** display timelock fields but don't analyze them. Both mempool.space and blockstream.info show nLockTime, per-input nSequence, and decoded scripts containing CLTV/CSV opcodes for every transaction. The CLI tool `hal` (github.com/stevenroose/hal) decodes transactions to JSON with locktime and sequence fields and includes Miniscript inspection commands. Bitcoin Core's own `decoderawtransaction` RPC remains the canonical tool for raw timelock field inspection.

**Liana Wallet** (github.com/wizardsardine/liana) represents the most practical deployment of timelock analysis in production — it uses Miniscript extensively for OP_CSV recovery paths, shows users which funds have expired timelocks, and enforces timelock refreshing. NCC Group's **FastBTCParser** (github.com/nccgroup/FastBTCParser) can fingerprint and count CLTV/CSV usage across the entire blockchain, making it useful for prevalence analysis.

On the monitoring side, **mempool.observer** by 0xb10c (github.com/0xB10C/memo) visualizes mempool fee dynamics and congestion but does **not** track timelocks specifically. 0xb10c's **transactionfee.info** tracks protocol-layer statistics including script types. Lightning Network tools like **Amboss Space** and **1ML** display channel policies including `cltv_expiry_delta` values per node, but perform no security analysis. **LND's built-in watchtower** is directly security-critical — it monitors for revoked commitment transactions during the CSV contestation window.

---

## Nine documented attack vectors exploit timelocks in Bitcoin and Lightning

The research literature documents a surprisingly deep catalog of timelock-related attacks, spanning the Lightning Network whitepaper through cutting-edge 2023 disclosures.

**Flood-and-loot** (Harris & Zohar, 2020; arxiv.org/abs/2006.08513) is the most well-known systemic attack. An attacker opens many channels, routes HTLCs through victims, then force-closes all channels simultaneously. The resulting blockchain congestion prevents victims from claiming HTLCs before CLTV timelocks expire. The researchers showed **just 85 simultaneously attacked channels** suffice to guarantee profit. Anchor outputs — which allow dynamic fee bumping via CPFP after broadcast — are the primary deployed mitigation.

**Forced expiration spam**, described in Section 9 of the original Lightning whitepaper (Poon & Dryja, 2016), is the foundational concern: mass forced channel closures drive fees high enough that timelock refund paths become valid before preimage claims confirm. The whitepaper called this "the greatest systemic risk when using the Lightning Network." A proposed consensus-level fix, **Feerate-Dependent Timelocks (FDTs)** by John Law (github.com/JohnLaw2/ln-fdts, December 2023), would automatically extend timelocks when on-chain feerates spike, but this requires a soft fork.

**Time-dilation attacks** (Riard & Naumenko, 2020; arxiv.org/abs/2006.01418) exploit eclipse attacks to manipulate a victim's perception of blockchain height. By feeding blocks at a slower rate, the attacker makes the victim believe timelocks haven't expired when they actually have. Three variants target CSV contestation periods, CLTV HTLC expiry, and preimage theft. The researchers found that **eclipsing a node for as little as 2 hours** can steal total channel capacity, and running just 500 Sybil nodes can eclipse 47% of newly deployed light clients.

**Transaction pinning** (documented extensively by Bastien Teinturier at github.com/t-bast/lightning-docs/blob/master/pinning-attacks.md) prevents counterparties from getting transactions confirmed within timelock windows. An attacker attaches large, low-feerate child transactions to shared commitment transactions, making fee-bumping prohibitively expensive. Mitigations include anchor outputs (deployed), CPFP carve-out (deployed in Bitcoin Core), and v3 transaction relay (in development).

**Replacement cycling** (Antoine Riard, disclosed October 2023; CVE-2023-40231 through CVE-2023-40234) is the most recent major discovery. The attacker repeatedly replaces a victim's HTLC-timeout transaction with an HTLC-preimage transaction, then replaces that with an unrelated transaction, clearing all HTLC-spending transactions from mempools. If cycling continues until the incoming HTLC's CLTV expires, the attacker profits. All major LN implementations are patched with frequent rebroadcasting, but Riard considers deployed mitigations insufficient against advanced attackers and disclosed a miner-level variant in January 2025.

Additional attacks include **congestion attacks** (Mizrahi & Zohar, 2020; arxiv.org/abs/2002.06564) that lock HTLC slots until expiration with less than 0.5 BTC; **channel jamming** exploiting maximum HTLC timelock durations; **timelocked bribing** (Nadahalli et al., FC 2021) where miners are incentivized to censor hashlock transactions; and the **time warp attack** (~2011) where majority-hashrate miners manipulate timestamps to slow MTP progression, affecting all timelocks. A fix for time warp is proposed in the Great Consensus Cleanup (BIP-094).

---

## rust-bitcoin provides comprehensive timelock parsing

The **rust-bitcoin** library (github.com/rust-bitcoin/rust-bitcoin, current version 0.32.8) offers complete support for parsing all four timelock mechanisms from raw transactions and scripts.

For **absolute timelocks (nLockTime)**, the `Transaction` struct exposes a `lock_time` field typed as `absolute::LockTime` — an enum with variants `Blocks(Height)` and `Seconds(Time)`, automatically distinguishing height-based (< 500,000,000) from time-based values. Key methods include `from_consensus(u32)`, `is_satisfied_by(height, time)`, and `is_block_height()`. The `Transaction` struct also provides `is_lock_time_enabled()` (checks if any input's sequence ≠ 0xFFFFFFFF) and `is_absolute_timelock_satisfied()`.

For **relative timelocks (nSequence/BIP 68)**, the `Sequence` struct wraps the raw u32 and provides `to_relative_lock_time() -> Option<relative::LockTime>`, which parses BIP 68 encoding by checking bit 31 (disable flag), bit 22 (type flag), and the lower 16 bits. The `relative::LockTime` enum has variants `Blocks(Height)` (u16 block count) and `Time(MTPInterval)` (u16 × 512-second intervals).

For **script-level timelocks**, the library defines `OP_CLTV` (opcode 0xb1) and `OP_CSV` (opcode 0xb2) in `bitcoin::opcodes::all`. Scripts can be iterated via `script.instructions()`, which yields `Instruction::Op(Opcode)` and `Instruction::PushBytes(&PushBytes)` — the preceding push before OP_CLTV/OP_CSV contains the timelock value, parseable via `absolute::LockTime::from_consensus()` or `relative::LockTime` constructors. **Raw transactions decode from hex** in one call via `consensus::deserialize_hex::<Transaction>(hex_string)`.

The companion crate **rust-miniscript** adds security analysis capabilities through its `TimelockInfo` struct, which tracks `csv_with_time`, `csv_with_height`, `cltv_with_time`, `cltv_with_height`, and `contains_combination` — directly detecting the dangerous timelock mixing vulnerability. Its interpreter module can determine "the specific keys, hash preimages and timelocks used to spend coins in a given Bitcoin transaction." **LDK (rust-lightning)** uses CLTV extensively with constants like `CLTV_CLAIM_BUFFER` and configurable `cltv_expiry_delta`, though it often works with raw u32 values rather than rust-bitcoin's LockTime types.

---

## mempool.space API exposes every timelock field needed for scanning

Both mempool.space and Blockstream's Esplora API share the same underlying transaction format and **include all fields necessary for timelock analysis**: `locktime` (nLockTime), per-input `sequence` (nSequence), `scriptsig_asm`, `inner_redeemscript_asm`, `inner_witnessscript_asm` (revealing CLTV/CSV opcodes in P2SH/P2WSH scripts), and raw `witness[]` data.

The most relevant endpoints on mempool.space (`https://mempool.space/api`) are:

- **`GET /api/tx/{txid}`** — Full transaction with all timelock fields, decoded scripts, and prevout data
- **`GET /api/tx/{txid}/hex`** — Raw transaction hex for custom local parsing
- **`GET /api/block/{hash}/txs/{start_index}`** — Paginated block transactions (25 per page), each with full timelock data; ideal for scanning entire blocks
- **`GET /api/block/{hash}/txids`** — All txids in a block for selective fetching
- **`GET /api/mempool/txids`** — All current mempool txids (requires follow-up individual fetches for timelock data)
- **`GET /api/mempool/recent`** — Last 10 mempool entries but only simplified format (no timelock fields; must follow up with `/tx/{txid}`)
- **WebSocket at `wss://mempool.space/api/v1/ws`** — Event-driven subscriptions for new blocks, address tracking, and RBF monitoring; not a raw transaction firehose

**Rate limits are intentionally undisclosed.** Maintainer @wiz stated: "if you have to ask then you will hit them." HTTP 429 responses indicate violations, and repeated violations may result in IP bans. An enterprise tier exists with higher limits and bulk endpoints like `/api/v1/blocks-bulk/{minHeight}/{maxHeight}`.

**Self-hosting eliminates rate limits entirely.** The full mempool.space stack is open source (github.com/mempool/mempool) with one-click installs on Umbrel, RaspiBlitz, Start9, and MyNode, or Docker deployment. Requirements: Bitcoin Core full node + electrs + MariaDB. The self-hosted instance exposes the identical API. Blockstream's Esplora (blockstream.info/api) provides equivalent endpoints with reportedly more permissive rate limits but lacks WebSocket support.

---

## Lightning HTLC timelocks use a layered CLTV/CSV architecture

Lightning's timelock design uses **CLTV for HTLC expiry deadlines** and **CSV for revocation enforcement windows**, creating a layered security model defined in the BOLT specifications.

When routing payments, CLTV timelocks are calculated backward from the destination. Each hop subtracts its `cltv_expiry_delta` from the incoming HTLC's expiry to set the outgoing expiry. The BOLT #2 recommended formula is `cltv_expiry_delta ≥ 3R + 2G + 2S` (R=resolution blocks, G=grace period, S=broadcast-to-inclusion estimate), yielding at least **34 blocks**. Default values vary by implementation: **LND uses 80** (lowered from 144 in 2019), **CLN uses 34**, **Eclair uses 144**, and **LDK uses 36**. Approximately 91% of channels advertise `cltv_delta` = 40 (legacy LND default). The minimum `final_cltv_expiry_delta` for the last hop is **18 blocks** (updated from 9 by BOLTs #785). Maximum total CLTV across all hops is capped at **2,016 blocks** (~2 weeks).

Commitment transactions use CSV via the `to_self_delay` parameter, typically **144 blocks** (~1 day) across all major implementations, with a spec-recommended maximum of 2,016. The `to_local` output script enforces this: the broadcaster must wait `to_self_delay` blocks before claiming funds, while the counterparty can spend immediately via the revocation path.

**HTLC-timeout and HTLC-success are distinct second-stage transactions.** HTLC-timeout has `nLockTime = cltv_expiry` (specific block height) and an empty preimage slot in the witness. HTLC-success has `nLockTime = 0` and reveals a **32-byte payment preimage** in the witness. Both produce outputs with the same CSV-delayed revocation script. This preimage presence/absence is the primary heuristic for on-chain identification.

Force-closed Lightning channels are identifiable on-chain through several signals: commitment transactions have distinctive `locktime` values in the 0x20XXXXXX range (≥ 500,000,000) encoding obscured commitment numbers, `sequence` values with upper byte 0x80, anchor outputs of exactly **330 satoshis**, and P2WSH outputs matching HTLC script templates. The offered HTLC script is 133 bytes and the received HTLC script is 139 bytes, both containing OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKMULTISIG, and the characteristic `OP_SIZE 32 OP_EQUAL` pattern for preimage size checking.

---

## Shakespeare.diy can prototype a dashboard but has real constraints

**Shakespeare.diy** is an open-source, AI-powered web app builder (AGPL 3.0) launched July 2025 by Alex Gleason / Soapbox, with a major "Act 2" update in October 2025. It runs entirely in the browser using IndexedDB, isomorphic-git, and esbuild-wasm for TypeScript compilation. Users describe applications in natural language, and AI generates React 18 / TypeScript / TailwindCSS / ShadCN UI applications with live preview. It supports **40+ AI models** including Claude Sonnet 4.5, Gemini, and local models via Ollama.

For a Bitcoin timelock dashboard, Shakespeare can handle API fetching (standard `fetch()` calls to mempool.space, which supports CORS), data tables (ShadCN UI includes table components), charts (AI can include Recharts, Chart.js, or D3.js), and interactive filtering (React state management). Deployment is straightforward: built-in free hosting on *.shakespeare.wtf subdomains, one-click ZIP export, or Git push to any provider.

The critical limitations are **client-side only execution** (no backend for caching, scheduled fetching, or heavy data processing), **no server-side proxy** (direct API calls from the browser will hit mempool.space rate limits under heavy use), and **AI-dependent quality** requiring multiple refinement iterations for complex technical applications. It's well-suited for **rapid prototyping** but a production-grade timelock analyzer would likely need the exported code enhanced with a proper backend service.

---

## Conclusion

The Bitcoin timelock analysis space has a clear gap between rich academic attack research and practical tooling. Nine documented attack vectors exploit timelocks through blockchain congestion, eclipse attacks, transaction pinning, mempool manipulation, and timestamp gaming — yet no tool systematically scans for these vulnerabilities. The technical infrastructure for building such a tool is fully mature: rust-bitcoin parses all four timelock types with type-safe APIs, rust-miniscript detects dangerous timelock mixing, mempool.space's API exposes every relevant transaction field, and Lightning's BOLT specifications precisely define the script templates and timelock values that would need monitoring. The most actionable approach would combine rust-bitcoin's parsing capabilities with a self-hosted mempool.space instance (avoiding rate limits) to build a scanner that checks for misconfigured CLTV deltas, mixed timelocks, anomalous nSequence patterns, and HTLC timeout clustering that could indicate flood-and-loot staging. Shakespeare.diy could accelerate frontend prototyping, but the analytical backend would need dedicated engineering.