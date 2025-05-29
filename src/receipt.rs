use serde::{Deserialize, Serialize};
use rlp::{Encodable, Decodable, RlpStream, Rlp};
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

impl Decodable for Log {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Log {
            address: format!("0x{}", hex::encode(rlp.val_at::<H160>(0)?)),
            topics: rlp.list_at::<H256>(1)?.iter().map(|t| format!("0x{}", hex::encode(t))).collect(),
            data: format!("0x{}", hex::encode(rlp.val_at::<Vec<u8>>(2)?)),
            block_hash: "0x0".to_string(),
            block_number: "0x0".to_string(),
            transaction_hash: "0x0".to_string(),
            transaction_index: "0x0".to_string(),
            log_index: "0x0".to_string(),
            removed: false,
        })
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

impl Decodable for TransactionReceipt {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(TransactionReceipt {
            status: format!("0x{:x}", rlp.val_at::<u64>(0)?),
            cumulative_gas_used: format!("0x{:x}", rlp.val_at::<u64>(1)?),
            logs_bloom: format!("0x{}", hex::encode(rlp.val_at::<Bloom>(2)?)),
            logs: rlp.list_at(3)?,
            block_hash: "0x0".to_string(),
            block_number: "0x0".to_string(),
            contract_address: None,
            effective_gas_price: "0x0".to_string(),
            from: "0x0".to_string(),
            gas_used: "0x0".to_string(),
            to: "0x0".to_string(),
            transaction_hash: "0x0".to_string(),
            transaction_index: "0x0".to_string(),
            transaction_type: "0x0".to_string(),
        })
    }
} 