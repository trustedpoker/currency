use candid::{CandidType, Deserialize};
use serde::Serialize;

/// Tron address (Base58Check encoded, starts with 'T')
pub type TronAddress = String;

/// Transaction hash on Tron blockchain
pub type TxHash = String;

/// TRC-20 USDT contract address on Tron mainnet
pub const USDT_CONTRACT_ADDRESS: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

/// TRC-20 USDT contract address on Shasta testnet
pub const USDT_CONTRACT_ADDRESS_TESTNET: &str = "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs";

/// Tron blockchain transaction details
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct TronTxInfo {
    pub tx_id: String,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub from: String,
    pub to: String,
    pub value: String, // Amount in smallest unit (6 decimals for USDT)
    pub confirmed: bool,
}

/// Response from TronGrid API for transaction info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronGridTransactionResponse {
    pub ret: Vec<TronGridRet>,
    #[serde(rename = "txID")]
    pub tx_id: String,
    pub raw_data: TronGridRawData,
    #[serde(default)]
    pub blockNumber: Option<u64>,
    #[serde(default)]
    pub block_timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronGridRet {
    #[serde(rename = "contractRet")]
    pub contract_ret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronGridRawData {
    pub contract: Vec<TronGridContract>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronGridContract {
    pub parameter: TronGridParameter,
    #[serde(rename = "type")]
    pub contract_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronGridParameter {
    pub value: serde_json::Value,
}

/// Response from TronGrid API for broadcasting transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResponse {
    pub result: bool,
    #[serde(rename = "txid")]
    pub tx_id: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
}

/// Transaction to be signed and broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    #[serde(rename = "txID")]
    pub tx_id: String,
    pub raw_data: TronGridRawData,
    pub raw_data_hex: String,
}

/// Signed transaction ready for broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    #[serde(rename = "txID")]
    pub tx_id: String,
    pub raw_data: TronGridRawData,
    pub raw_data_hex: String,
    pub signature: Vec<String>,
}

