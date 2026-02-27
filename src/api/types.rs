use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ApiTransaction {
    pub txid: String,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<ApiVin>,
    pub vout: Vec<ApiVout>,
    pub size: u64,
    pub weight: u64,
    pub fee: Option<u64>,
    pub status: ApiStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiVin {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    pub prevout: Option<ApiPrevout>,
    pub scriptsig: Option<String>,
    pub scriptsig_asm: Option<String>,
    pub inner_redeemscript_asm: Option<String>,
    pub inner_witnessscript_asm: Option<String>,
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiPrevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiVout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}
