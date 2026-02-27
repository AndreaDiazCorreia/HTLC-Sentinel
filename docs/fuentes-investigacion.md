# Fuentes de Investigación — Timelock Attack Visualizer

---

## Ataques y Vulnerabilidades Documentadas

### Flood-and-Loot Attack
- **Paper:** Harris & Zohar, 2020
- **URL:** https://arxiv.org/abs/2006.08513
- **Cobertura:** https://cryptobriefing.com/bitcoins-lightning-network-faces-existential-risk-flood-loot-attack/

### Time-Dilation Attacks
- **Paper:** Riard & Naumenko, 2020 — "Time-Dilation Attacks on the Lightning Network"
- **URL:** https://arxiv.org/pdf/2006.01418

### Replacement Cycling Attack
- **Disclosure:** Antoine Riard, October 2023 (CVE-2023-40231 through CVE-2023-40234)
- **Bitcoin Optech coverage:** https://bitcoinops.org/en/newsletters/2023/11/01/
- **Blockchain News coverage:** https://blockchain.news/news/new-bitcoin-lightning-network-vulnerability-exposed-the-replacement-cycling-attack
- **Bitcoin Magazine postmortem:** https://bitcoinmagazine.com/technical/postmortem-on-the-lightning-replacement-cycling-attack

### Congestion Attacks
- **Paper:** Mizrahi & Zohar, 2020 — "Congestion Attacks in Payment Channel Networks"
- **URL:** https://ui.adsabs.harvard.edu/abs/2020arXiv200206564M/abstract

### Transaction Pinning
- **Documentation:** Bastien Teinturier
- **URL:** https://github.com/t-bast/lightning-docs/blob/master/pinning-attacks.md
- **Anchor Outputs (mitigation):** https://bitcoinops.org/en/topics/anchor-outputs/

### Timelocked Bribing
- **Paper:** Nadahalli et al., Financial Cryptography 2021
- **URL:** https://link.springer.com/chapter/10.1007/978-3-662-64322-8_3

### Lightning Network Vulnerabilities Overview
- **CoinDesk:** https://www.coindesk.com/tech/2020/10/27/4-bitcoin-lightning-network-vulnerabilities-that-havent-been-exploited-yet

### Feerate-Dependent Timelocks (FDTs) — Proposed Mitigation
- **Proposal:** John Law, December 2023
- **URL:** https://github.com/JohnLaw2/ln-fdts

---

## Lightning Network — BOLT Specifications & Timelocks

### BOLT Specifications
- **BOLT #2 — Peer Protocol (cltv_expiry_delta):** https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
- **BOLT #3 — Transactions (HTLC scripts, commitment tx):** https://github.com/lightning/bolts/blob/master/03-transactions.md
- **BOLT #4 — Onion Routing:** https://github.com/lightning/bolts/blob/master/04-onion-routing.md
- **BOLT #785 — More conservative cltv_expiry_delta:** https://github.com/lightning/bolts/pull/785
- **BOLT #252 — cltv_expiry_delta on open/accept:** https://github.com/lightning/bolts/pull/252

### Lightning Timelocks Documentation
- **Lightning Engineering — Timelocks:** https://docs.lightning.engineering/the-lightning-network/multihop-payments/timelocks
- **Lightning Engineering — HTLC:** https://github.com/lightninglabs/docs.lightning.engineering/blob/master/the-lightning-network/multihop-payments/hash-time-lock-contract-htlc.md
- **Lightning Engineering — Routing Node Configuration:** https://docs.lightning.engineering/lightning-network-tools/lnd/optimal-configuration-of-a-routing-node
- **Stacker News — CLTV delta discussion:** https://stacker.news/items/26503
- **CLTV expiry delta — Bitcoin Optech:** https://bitcoinops.org/en/topics/cltv-expiry-delta/

### Lightning Transactions — Educational
- **"Lightning transactions: from Zero to Hero":** https://gist.github.com/Deadlyelder/39697a51343da5e64a4beba5a32d535c

---

## rust-bitcoin & Related Crates

### rust-bitcoin (Core Library)
- **Repository:** https://github.com/rust-bitcoin/rust-bitcoin
- **Transaction struct:** https://docs.rs/bitcoin/latest/bitcoin/blockdata/transaction/struct.Transaction.html
- **transaction.rs source:** https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/src/blockdata/transaction.rs
- **absolute::LockTime enum:** https://docs.rs/bitcoin/latest/bitcoin/absolute/enum.LockTime.html
- **LockTime PR (#994):** https://github.com/rust-bitcoin/rust-bitcoin/pull/994
- **Opcodes (OP_CLTV, OP_CSV):** https://docs.rs/syscoin/latest/src/bitcoin/blockdata/opcodes.rs.html
- **Consensus encoding:** https://docs.rs/bitcoin/latest/src/bitcoin/consensus/encode.rs.html

### rust-miniscript
- **Repository:** https://github.com/rust-bitcoin/rust-miniscript
- **Docs:** https://docs.rs/miniscript
- **RelLockTime struct:** https://docs.rs/miniscript/latest/miniscript/struct.RelLockTime.html
- **Timelock mixing detection (PR #121):** https://github.com/rust-bitcoin/rust-miniscript/pull/121

### BDK (Bitcoin Dev Kit)
- **LockTime in BDK:** https://bitcoindevkit.org/docs-rs/bdk/nightly/latest/bdk_chain/bitcoin/blockdata/locktime/absolute/enum.LockTime.html

### Other Rust Tools
- **hal — Bitcoin CLI multitool:** https://crates.io/crates/hal
- **bitcoin-explorer — Script struct:** https://docs.rs/bitcoin-explorer/latest/bitcoin_explorer/struct.Script.html
- **LDK (rust-lightning):** https://github.com/lightningdevkit/rust-lightning/releases/tag/v0.0.105

---

## BIPs (Bitcoin Improvement Proposals)

### BIP 68 — Relative Lock-time Using Sequence
- **Spec:** https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
- **Reference:** http://shcoins.com/wiki/bip68

### LOCK_TIME_THRESHOLD
- **Reference (500,000,000 threshold):** https://docs.rs/elements/latest/elements/locktime/constant.LOCK_TIME_THRESHOLD.html

---

## Data Sources — APIs

### mempool.space
- **Website:** https://mempool.space/
- **API documentation:** https://mempool.dinerosinreglas.com/docs/api
- **GitHub repository:** https://github.com/mempool/mempool
- **Rate limits discussion:** https://github.com/mempool/mempool/discussions/752
- **Rate limits documentation issue:** https://github.com/mempool/mempool/issues/4106

### Blockstream Esplora
- **API documentation:** https://github.com/Blockstream/esplora/blob/master/API.md

### Bitcoin Core RPC
- **decoderawtransaction:** https://developer.bitcoin.org/reference/rpc/decoderawtransaction.html

---

## Existing Tools (Landscape Analysis)

### 0xb10c Projects
- **mempool.observer:** https://github.com/0xB10C/memo
- **peer-observer:** https://github.com/0xB10C/peer-observer
- **fork-observer:** https://github.com/0xb10c/fork-observer
- **find-non-standard-tx:** https://github.com/0xB10C/find-non-standard-tx
- **Blog & Projects:** https://b10c.me/ — https://b10c.me/projects/ — https://b10c.me/observations/

### Lightning Network Monitoring
- **Amboss Space:** https://docs.amboss.tech/space

### Anchor Outputs
- **Explainer:** https://encrypthos.com/term/anchor-outputs/

---

## Shakespeare.diy (Frontend Platform)

- **Website:** https://shakespeare.diy/
- **Soapbox product page:** https://soapbox.pub/tools/shakespeare/
- **Announcement blog (Act 1):** https://soapbox.pub/blog/announcing-shakespeare/
- **Act 2 update:** https://soapbox.pub/blog/announcing-shakespeare-act-2/
- **AI model selection guide:** https://www.soapbox.pub/blog/shakespeare-ai-model-selection/
- **Local AI models guide:** https://www.soapbox.pub/blog/shakespeare-local-ai-model/
- **Press release:** https://www.prnewswire.com/news-releases/shakespeare-launches-as-open-source-competitor-to-ai-site-builders-302503727.html
- **Third party reviews:** https://theresanaiforthat.com/ai/shakespeare-diy/

---

## Bitcoin++ Hackathon

- **Event page (source document):** Bitcoin++ Exploits Edition Hackathon, Florianopolis, Brazil — February 26-28, 2026
- **Shakespeare credits faucet:** https://faucet.shakespeare.diy/pjqhthtx
- **Code of conduct:** https://hackcodeofconduct.org/
