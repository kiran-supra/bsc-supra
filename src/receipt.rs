use serde::{Deserialize, Serialize};
use rlp::{Encodable, RlpStream};
use ethereum_types::{H160, H256, Bloom};
use hex;
use std::str::FromStr;

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

impl Encodable for Log {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        // Convert hex string to H160
        let address = H160::from_slice(&hex::decode(&self.address[2..]).unwrap());
        s.append(&address);

        // Convert hex strings to H256
        let topics: Vec<H256> = self.topics.iter()
            .map(|t| H256::from_slice(&hex::decode(&t[2..]).unwrap()))
            .collect();
        s.append_list(&topics);

        // Convert hex string to bytes
        let data = hex::decode(&self.data[2..]).unwrap();
        s.append(&data);
    }
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

impl Encodable for TransactionReceipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        
        // 1. Status (convert hex to u64)
        let status = u64::from_str_radix(&self.status[2..], 16).unwrap();
        s.append(&status);

        // 2. Cumulative gas used (convert hex to u64)
        let cumulative_gas_used = u64::from_str_radix(&self.cumulative_gas_used[2..], 16).unwrap();
        s.append(&cumulative_gas_used);

        // 3. Logs bloom (convert hex to Bloom)
        let logs_bloom = Bloom::from_slice(&hex::decode(&self.logs_bloom[2..]).unwrap());
        s.append(&logs_bloom);

        // 4. Logs array
        s.append_list(&self.logs);
    }
}

impl TransactionReceipt {
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        self.rlp_append(&mut stream);
        stream.out().to_vec()
    }
} 