use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: String,
    #[serde(rename = "logIndex")]
    pub log_index: String,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,
    #[serde(rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: String,
    #[serde(rename = "effectiveGasPrice")]
    pub effective_gas_price: String,
    pub from: String,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    pub logs: Vec<Log>,
    #[serde(rename = "logsBloom")]
    pub logs_bloom: String,
    pub status: String,
    pub to: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
}

impl TransactionReceipt {
    pub fn new(
        block_hash: String,
        block_number: String,
        contract_address: Option<String>,
        cumulative_gas_used: String,
        effective_gas_price: String,
        from: String,
        gas_used: String,
        logs: Vec<Log>,
        logs_bloom: String,
        status: String,
        to: String,
        transaction_hash: String,
        transaction_index: String,
        transaction_type: String,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            contract_address,
            cumulative_gas_used,
            effective_gas_price,
            from,
            gas_used,
            logs,
            logs_bloom,
            status,
            to,
            transaction_hash,
            transaction_index,
            transaction_type,
        }
    }
} 