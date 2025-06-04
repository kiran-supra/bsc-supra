// use alloy::primitives::B256;
// use alloy_consensus::{Receipt, ReceiptWithBloom, TxReceipt, TxType, Transaction};
// use alloy_rlp::encode;
// use alloy_rlp::{Buf, Decodable};
// use alloy_rpc_types::TransactionReceipt;
// use eth_trie::{EthTrie, MemoryDB, Trie};
// use reqwest;
// use serde::{Deserialize, Serialize};
// use serde_json::{Value, json};
// use std::cmp::Ordering;
// use std::error::Error;
// use std::str::FromStr;
// use std::sync::Arc;
// // use alloy::const_hex::ToHex;
// use hex::ToHex;

#[derive(Debug)]
pub enum ProofGeneratorError {
    EncodingError(String),
    TrieError(String),
    TransactionNotFound(String),
    EncodeReceiptError(String),
}

impl std::fmt::Display for ProofGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofGeneratorError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            ProofGeneratorError::TrieError(e) => write!(f, "Trie error: {}", e),
            ProofGeneratorError::TransactionNotFound(e) => {
                write!(f, "Transaction not found: {}", e)
            }
            ProofGeneratorError::EncodeReceiptError(e) => {
                write!(f, "Receipt encoding error: {}", e)
            }
        }
    }
}

impl std::error::Error for ProofGeneratorError {}

// async fn get_block_receipts(block_number: &str) -> Result<Vec<TransactionReceipt>, Box<dyn Error>> {
//     let client = reqwest::Client::new();

//     let request_body = json!({
//         "method": "eth_getBlockReceipts",
//         "params": [block_number],
//         "id": 1,
//         "jsonrpc": "2.0"
//     });

//     let response = client
//         .post("https://bsc-testnet-rpc.publicnode.com/")
//         .header("Content-Type", "application/json")
//         .json(&request_body)
//         .send()
//         .await?;

//     let json_response: Value = response.json().await?;
//     let receipts: Vec<TransactionReceipt> =
//         serde_json::from_value(json_response["result"].clone())?;
//     Ok(receipts)
// }

// use std::fmt::Error;
use std::{error::Error, str::FromStr, sync::Arc};

use alloy_primitives::B256;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Buf, Decodable};
use alloy_rlp::{BufMut, Encodable, RlpEncodable, encode};
use eth_trie::{EthTrie, MemoryDB, Trie};
use serde_json::{Value, json};

#[derive(Debug)]
struct AccessListItem {
    address: Address,
    storage_keys: Vec<U256>,
}

impl Encodable for AccessListItem {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut list = vec![];
        self.address.encode(&mut list);
        self.storage_keys.encode(&mut list);
        list.encode(out);
    }
}

#[derive(Debug)]
struct AccessList(pub Vec<AccessListItem>);

impl Encodable for AccessList {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.encode(out);
    }
}

async fn get_block_by_number(block_number: &str) -> Result<Value, Box<dyn Error>> {
    let client = reqwest::Client::new();

    let request_body = json!({
        "method": "eth_getBlockByNumber",
        "params": [block_number, true],
        "id": 1,
        "jsonrpc": "2.0"
    });

    let response = client
        .post("https://bsc-rpc.publicnode.com/") // Use same RPC for consistency
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let block_data: Value = response.json().await?;
    Ok(block_data)
}

// pub fn build_trie<T>(
//     leaves: Vec<T>,
//     encode_fn: fn(&T) -> Result<Vec<u8>, ProofGeneratorError>,
// ) -> Result<(EthTrie<MemoryDB>, B256), ProofGeneratorError> {
//     let memdb = Arc::new(MemoryDB::new(true));
//     let mut trie = EthTrie::new(Arc::clone(&memdb));

//     for (i, leaf) in leaves.iter().enumerate() {
//         // Use RLP encoding for the key (transaction index)
//         let key = encode(&i);
//         let value = encode_fn(leaf)?;

//         println!(
//             "Inserting key {} (encoded: {:?}) with value length: {}",
//             i,
//             key,
//             value.len()
//         );

//         trie.insert(key.as_slice(), value.as_slice()).map_err(|e| {
//             ProofGeneratorError::TrieError(format!("Failed to insert into trie: {:?}", e))
//         })?;
//     }

//     // Get the root hash of our constructed trie
//     let root = trie
//         .root_hash()
//         .map_err(|e| ProofGeneratorError::TrieError(format!("Failed to get root hash: {:?}", e)))?;

//     let root_b256 = B256::from_slice(root.as_slice());
//     println!("Constructed trie root: {}", root_b256);

//     Ok((trie, root_b256))
// }

// pub fn get_tx_index(
//     receipts: &[TransactionReceipt],
//     tx_hash: &B256,
// ) -> Result<u64, ProofGeneratorError> {
//     let tx_index = receipts.iter().position(|r| r.transaction_hash == *tx_hash);

//     match tx_index {
//         Some(index) => Ok(index as u64),
//         None => Err(ProofGeneratorError::TransactionNotFound(
//             tx_hash.to_string(),
//         )),
//     }
// }

// pub async fn print_receipt_proof(
//     receipts: &[TransactionReceipt],
//     tx_hash: &B256,
// ) -> Result<(Vec<Vec<u8>>, B256), ProofGeneratorError> {
//     let tx_index = get_tx_index(receipts, tx_hash)?;
//     let (mut trie, constructed_root) = build_trie(receipts.to_vec(), encode_receipt)?;
//     let tx_index_encoded = encode(&tx_index);

//     println!("Transaction index: {}", tx_index);
//     println!("Constructed trie root: {}", constructed_root);

//     let proof = trie
//         .get_proof(tx_index_encoded.as_slice())
//         .map_err(|e| ProofGeneratorError::TrieError(format!("Failed to get proof: {:?}", e)))?;

//     println!("Proof has {} nodes", proof.len());
//     for (i, node) in proof.iter().enumerate() {
//         println!("Proof node {}: {} bytes", i, node.len());
//     }

//     Ok((proof, constructed_root))
// }

// pub fn encode_receipt(receipt: &TransactionReceipt) -> Result<Vec<u8>, ProofGeneratorError> {
//     let tx_type = receipt.transaction_type();

//     if receipt.inner.as_receipt_with_bloom().is_none() {
//         return Err(ProofGeneratorError::EncodeReceiptError(
//             "receipt_with_bloom is none".to_string(),
//         ));
//     }

//     let receipt_bloom = receipt.inner.as_receipt_with_bloom().unwrap();
//     let logs = receipt_bloom
//         .logs()
//         .iter()
//         .map(|l| l.inner.clone())
//         .collect::<Vec<_>>();

//     let consensus_receipt = Receipt {
//         cumulative_gas_used: receipt_bloom.cumulative_gas_used(),
//         status: receipt_bloom.status_or_post_state(),
//         logs: logs.clone(), // Clone to avoid move issue
//     };

//     let rwb = ReceiptWithBloom::new(consensus_receipt, receipt_bloom.bloom());

//     // For debugging - print receipt details
//     println!("Receipt details:");
//     println!("  Type: {:?}", tx_type);
//     println!(
//         "  Cumulative gas used: {}",
//         receipt_bloom.cumulative_gas_used()
//     );
//     println!("  Status: {:?}", receipt_bloom.status_or_post_state());
//     println!("  Logs count: {}", logs.len());

//     let encoded = alloy_rlp::encode(&rwb);
//     println!("  RLP encoded length: {}", encoded.len());

//     let final_encoded = match tx_type {
//         TxType::Legacy => {
//             println!("  Using legacy encoding (no type prefix)");
//             encoded
//         }
//         _ => {
//             println!(
//                 "  Using typed encoding (with type prefix: {})",
//                 tx_type as u8
//             );
//             [vec![tx_type as u8], encoded].concat()
//         }
//     };

//     println!("  Final encoded length: {}", final_encoded.len());
//     Ok(final_encoded)
// }

// pub fn verify_trie_proof(
//     root: B256,
//     key: u64,
//     proof_bytes: Vec<Vec<u8>>,
// ) -> Result<Vec<u8>, ProofGeneratorError> {
//     let memdb = Arc::new(MemoryDB::new(true));
//     let trie = EthTrie::new(Arc::clone(&memdb));

//     println!("Root: {}", root);
//     println!("Key: {}", key);
//     println!("Proof length: {}", proof_bytes.len());

//     let proof = trie.verify_proof(root.0.into(), encode(&key).as_slice(), proof_bytes);

//     match proof {
//         Ok(Some(value)) => Ok(value),
//         Ok(None) => Err(ProofGeneratorError::TrieError(
//             "Proof verification returned None".to_string(),
//         )),
//         Err(e) => Err(ProofGeneratorError::TrieError(format!(
//             "Trie proof verification error: {:?}",
//             e
//         ))),
//     }
// }

// // Helper function to get receipt root from block
// pub async fn get_receipt_root(block_number: &str) -> Result<B256, Box<dyn Error>> {
//     let block_data = get_block_by_number(block_number).await?;

//     // Write block data to JSON file
//     let file_name = format!("block_{}.json", block_number);
//     std::fs::write(
//         &file_name,
//         serde_json::to_string_pretty(&block_data)?,
//     )?;
//     println!("Block data written to {}", file_name);

//     let receipt_root_str = block_data["result"]["receiptsRoot"]
//         .as_str()
//         .ok_or("receiptsRoot not found in block data")?;

//     let receipt_root = B256::from_str(receipt_root_str)?;
//     Ok(receipt_root)
// }

// #[derive(Default, Debug, Clone, Deserialize, Serialize)]
// pub struct ExtractedLog {
//     pub address: [u8; 20],
//     pub topics: Vec<[u8; 32]>,
//     pub data: Vec<u8>,
// }

// /// A collection of extracted logs from an Ethereum receipt.
// ///
// /// # Fields
// ///
// /// * `0` - A vector containing multiple `ExtractedLog` entries.
// #[derive(Default, Debug)]
// pub struct ExtractedLogs(pub Vec<ExtractedLog>);

// /// Implements decoding for `ExtractedLogs` using RLP (Recursive Length Prefix).
// ///
// /// # Errors
// ///
// /// Returns an `alloy_rlp::Error` if decoding fails due to invalid structure or unexpected data.
// impl Decodable for ExtractedLogs {
//     fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
//         let rlp_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
//             "cannot decode a receipt from empty bytes",
//         ))?;
//         match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
//             Ordering::Less => {
//                 let _header = alloy_rlp::Header::decode(buf)?;
//                 let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
//                     "cannot decode receipt logs from empty list",
//                 ))?;

//                 if receipt_type > 3 {
//                     return Err(alloy_rlp::Error::Custom("Invalid Receipt Type"));
//                 }
//                 buf.advance(1);
//             }
//             Ordering::Equal => {
//                 return Err(alloy_rlp::Error::Custom(
//                     "an empty list is not a valid receipt encoding",
//                 ));
//             }
//             _ => {}
//         };

//         let mut logs_list: ExtractedLogs = ExtractedLogs::default();

//         let b = &mut &**buf;
//         let rlp_head = alloy_rlp::Header::decode(b)?;
//         if !rlp_head.list {
//             return Err(alloy_rlp::Error::UnexpectedString);
//         }

//         for _i in 0..3 {
//             // skip fields success, cumulative_gas_used, bloom
//             let head = alloy_rlp::Header::decode(b)?;
//             b.advance(head.payload_length);
//         }

//         let logs_head = alloy_rlp::Header::decode(b)?;
//         if !logs_head.list {
//             return Err(alloy_rlp::Error::UnexpectedString);
//         }

//         while !b.is_empty() {
//             let mut log: ExtractedLog = ExtractedLog::default();
//             let item_head = alloy_rlp::Header::decode(b)?;
//             if !item_head.list {
//                 return Err(alloy_rlp::Error::UnexpectedString);
//             }

//             log.address = alloy_rlp::Decodable::decode(b)?;

//             let topic_list_head = alloy_rlp::Header::decode(b)?;
//             for _i in 0..(topic_list_head.payload_length / 32) {
//                 log.topics.push(alloy_rlp::Decodable::decode(b)?);
//             }

//             log.data = Vec::from(alloy_rlp::Header::decode_bytes(b, false)?);

//             logs_list.0.push(log);
//         }

//         Ok(logs_list)
//     }
// }

// pub fn get_logs_from_receipt(receipt: &[u8]) -> Result<ExtractedLogs, ProofGeneratorError> {
//     let logs: ExtractedLogs = alloy_rlp::Decodable::decode(&mut &receipt[..])
//         .map_err(|_| ProofGeneratorError::TrieError("Failed to decode receipt".to_string()))?;
//     Ok(logs)
// }

// pub fn encode_bsc_transaction(tx: &Value) -> Result<Vec<u8>, ProofGeneratorError> {
//     // Helper function to decode hex with proper padding
//     fn decode_hex(hex: &str) -> Result<Vec<u8>, ProofGeneratorError> {
//         let hex = hex.strip_prefix("0x").unwrap_or(hex);
//         // Pad with leading zero if odd length
//         let hex = if hex.len() % 2 != 0 {
//             format!("0{}", hex)
//         } else {
//             hex.to_string()
//         };
//         hex::decode(&hex)
//             .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode hex: {}", e)))
//     }

//     // Get transaction type
//     let tx_type = tx["type"].as_str().unwrap_or("0x0");
//     let tx_type_num = u8::from_str_radix(tx_type.strip_prefix("0x").unwrap_or(tx_type), 16)
//         .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to parse transaction type: {}", e)))?;

//     // Common fields for all transaction types
//     let nonce = decode_hex(tx["nonce"].as_str().unwrap_or("0x0"))?;
//     let gas = decode_hex(tx["gas"].as_str().unwrap_or("0x0"))?;
//     let to = decode_hex(tx["to"].as_str().unwrap_or("0x0"))?;
//     let value = decode_hex(tx["value"].as_str().unwrap_or("0x0"))?;
//     let input = decode_hex(tx["input"].as_str().unwrap_or("0x"))?;
//     let v = decode_hex(tx["v"].as_str().unwrap_or("0x0"))?;
//     let r = decode_hex(tx["r"].as_str().unwrap_or("0x0"))?;
//     let s = decode_hex(tx["s"].as_str().unwrap_or("0x0"))?;

//     // Create transaction list based on type
//     let mut tx_list = Vec::new();

//     match tx_type_num {
//         0 => {
//             // Legacy transaction
//             let gas_price = decode_hex(tx["gasPrice"].as_str().unwrap_or("0x0"))?;
//             tx_list.push(nonce);
//             tx_list.push(gas_price);
//             tx_list.push(gas);
//             tx_list.push(to);
//             tx_list.push(value);
//             tx_list.push(input);
//             tx_list.push(v);
//             tx_list.push(r);
//             tx_list.push(s);
//         }
//         2 => {
//             // EIP-1559 transaction
//             let max_priority_fee = decode_hex(tx["maxPriorityFeePerGas"].as_str().unwrap_or("0x0"))?;
//             let max_fee = decode_hex(tx["maxFeePerGas"].as_str().unwrap_or("0x0"))?;

//             // Create and encode empty access list
//             let access_list: Vec<Vec<u8>> = Vec::new();
//             let encoded_access_list = alloy_rlp::encode(&access_list);

//             tx_list.push(nonce);
//             tx_list.push(max_priority_fee);
//             tx_list.push(max_fee);
//             tx_list.push(gas);
//             tx_list.push(to);
//             tx_list.push(value);
//             tx_list.push(input);
//             tx_list.push(encoded_access_list);
//             tx_list.push(v);
//             tx_list.push(r);
//             tx_list.push(s);
//         }
//         _ => return Err(ProofGeneratorError::EncodingError(format!("Unsupported transaction type: {}", tx_type_num))),
//     }

//     // Encode transaction
//     let encoded = alloy_rlp::encode(&tx_list);

//     // Add type prefix if not legacy transaction
//     let final_encoded = if tx_type_num == 0 {
//         encoded
//     } else {
//         [vec![tx_type_num], encoded].concat()
//     };

//     Ok(final_encoded)
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     let block_number = "0x3275CED";
//     let tx_hash =
//         B256::from_str("0xfb24129e36ced650e37b9a4ac02c3eb5dfe91131f9b4f6e085c52544731995d5")?;

//     // Get block data
//     println!("Fetching block data...");
//     let block_data = get_block_by_number(block_number).await?;

//     // Get transactions from block
//     let transactions = block_data["result"]["transactions"].as_array()
//         .ok_or("No transactions found in block")?;
//     println!("Found {} transactions in block", transactions.len());

//     // Build transaction trie
//     println!("\nBuilding transaction trie...");
//     let memdb = Arc::new(MemoryDB::new(true));
//     let mut trie = EthTrie::new(Arc::clone(&memdb));

//     for (i, tx) in transactions.iter().enumerate() {
//         // Use simple byte array for the key (transaction index)
//         let key = vec![i as u8];
//         let value = encode_bsc_transaction(tx)?;

//         println!(
//             "Inserting transaction {} (encoded key: {:?}) with value length: {}",
//             i,
//             key,
//             value.len()
//         );

//         trie.insert(key.as_slice(), value.as_slice()).map_err(|e| {
//             ProofGeneratorError::TrieError(format!("Failed to insert into trie: {:?}", e))
//         })?;
//     }

//     // Get the root hash
//     let root = trie
//         .root_hash()
//         .map_err(|e| ProofGeneratorError::TrieError(format!("Failed to get root hash: {:?}", e)))?;

//     let root_b256 = B256::from_slice(root.as_slice());
//     println!("\nTransaction trie root comparison:");
//     println!("Constructed root: {}", root_b256);
//     println!("Expected root:    0x801ab75552816c3669a6d26d8164c32cd7e542e61c25d0950c52c3d372e00c4e");
//     println!("Roots match: {}", root_b256 == B256::from_str("0x801ab75552816c3669a6d26d8164c32cd7e542e61c25d0950c52c3d372e00c4e")?);

//     Ok(())
// }

pub fn encode_bsc_transaction(tx: &Value) -> Result<Vec<u8>, ProofGeneratorError> {
    // Helper to decode hex and convert to minimal bytes
    fn decode_hex_minimal(hex_str: &str) -> Result<Vec<u8>, ProofGeneratorError> {
        let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex.is_empty() || hex == "0" {
            return Ok(vec![]);
        }

        let hex = if hex.len() % 2 != 0 {
            format!("0{}", hex)
        } else {
            hex.to_string()
        };

        let mut bytes = hex::decode(&hex)
            .map_err(|e| ProofGeneratorError::EncodingError(format!("Hex decode error: {}", e)))?;

        // Remove leading zeros for RLP minimal encoding
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }

        Ok(bytes)
    }

    // Helper to get U256 from hex string
    fn get_u256_from_hex(hex_str: &str) -> Result<U256, ProofGeneratorError> {
        if hex_str == "0x" || hex_str.is_empty() {
            return Ok(U256::ZERO);
        }
        U256::from_str_radix(hex_str.strip_prefix("0x").unwrap_or(hex_str), 16)
            .map_err(|e| ProofGeneratorError::EncodingError(format!("U256 parse error: {}", e)))
    }

    // Extract transaction fields
    let tx_type = tx["type"].as_str().unwrap_or("0x0");
    let tx_type_num = if tx_type == "0x" || tx_type.is_empty() {
        0u8
    } else {
        u8::from_str_radix(tx_type.strip_prefix("0x").unwrap_or(tx_type), 16).map_err(|e| {
            ProofGeneratorError::EncodingError(format!("Transaction type parse error: {}", e))
        })?
    };

    let nonce = get_u256_from_hex(tx["nonce"].as_str().unwrap_or("0x0"))?;
    let gas_limit = get_u256_from_hex(tx["gas"].as_str().unwrap_or("0x0"))?;
    let value = get_u256_from_hex(tx["value"].as_str().unwrap_or("0x0"))?;

    // Handle 'to' field - can be null for contract creation
    let to = if tx["to"].is_null() {
        None
    } else {
        let to_str = tx["to"].as_str().unwrap_or("");
        if to_str.is_empty() {
            None
        } else {
            Some(Address::from_str(to_str).map_err(|e| {
                ProofGeneratorError::EncodingError(format!("Address parse error: {}", e))
            })?)
        }
    };

    let input = Bytes::from(decode_hex_minimal(tx["input"].as_str().unwrap_or("0x"))?);

    // Signature components
    let v = get_u256_from_hex(tx["v"].as_str().unwrap_or("0x0"))?;
    let r = get_u256_from_hex(tx["r"].as_str().unwrap_or("0x0"))?;
    let s = get_u256_from_hex(tx["s"].as_str().unwrap_or("0x0"))?;

    match tx_type_num {
        0 => {
            // Legacy transaction encoding
            let gas_price = get_u256_from_hex(tx["gasPrice"].as_str().unwrap_or("0x0"))?;

            #[derive(RlpEncodable)]
            #[rlp(trailing)]
            struct LegacyTransaction {
                nonce: U256,
                gas_price: U256,
                gas_limit: U256,
                to: Option<Address>,
                value: Option<U256>,
                input: Option<Bytes>,
                v: Option<U256>,
                r: Option<U256>,
                s: Option<U256>,
            }

            let legacy_tx = LegacyTransaction {
                nonce,
                gas_price,
                gas_limit,
                to,
                value: Some(value),
                input: Some(input),
                v: Some(v),
                r: Some(r),
                s: Some(s),
            };

            Ok(encode(&legacy_tx))
        }
        1 => {
            // EIP-2930 Access List transaction encoding
            let chain_id = get_u256_from_hex(tx["chainId"].as_str().unwrap_or("0x61"))?; // BSC testnet
            println!("chain_id {:?}",chain_id);
            let gas_price = get_u256_from_hex(tx["gasPrice"].as_str().unwrap_or("0x0"))?;
            // Handle access list
            let access_list = if let Some(al) = tx["accessList"].as_array() {
                let mut items = Vec::new();
                for item in al {
                    let address = Address::from_str(item["address"].as_str().unwrap_or(""))
                        .map_err(|e| {
                            ProofGeneratorError::EncodingError(format!(
                                "Access list address error: {}",
                                e
                            ))
                        })?;
                    let storage_keys: Result<Vec<U256>, _> = item["storageKeys"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|key| get_u256_from_hex(key.as_str().unwrap_or("0x0")))
                        .collect();
                    items.push(AccessListItem {
                        address,
                        storage_keys: storage_keys?,
                    });
                }
                AccessList(items)
            } else {
                AccessList(Vec::new())
            };
            // Use alloy_rlp's encoder directly
            use alloy_rlp::Encodable;
            let mut buf = Vec::new();
            
            // We need to calculate the payload length first
            let mut temp_buf = Vec::new();
            chain_id.encode(&mut temp_buf);
            nonce.encode(&mut temp_buf);
            gas_price.encode(&mut temp_buf);
            gas_limit.encode(&mut temp_buf);
            
            // Handle the 'to' field - encode as empty bytes if None
            if let Some(to_addr) = to {
                to_addr.encode(&mut temp_buf);
            } else {
                // Empty byte string for contract creation - encode as empty Vec<u8>
                let empty_bytes: Vec<u8> = Vec::new();
                empty_bytes.encode(&mut temp_buf);
            }
            
            value.encode(&mut temp_buf);
            input.encode(&mut temp_buf);
            access_list.encode(&mut temp_buf);
            v.encode(&mut temp_buf);
            r.encode(&mut temp_buf);
            s.encode(&mut temp_buf);
            
            // Now encode with correct length
            alloy_rlp::Header { list: true, payload_length: temp_buf.len() }.encode(&mut buf);
            buf.extend_from_slice(&temp_buf);
            // Prepend transaction type for EIP-2930
            Ok([vec![tx_type_num], buf].concat())
        }
        2 => {
            // EIP-1559 transaction encoding
            let chain_id = get_u256_from_hex(tx["chainId"].as_str().unwrap_or("0x61"))?; // BSC testnet
            let max_priority_fee =
                get_u256_from_hex(tx["maxPriorityFeePerGas"].as_str().unwrap_or("0x0"))?;
            let max_fee = get_u256_from_hex(tx["maxFeePerGas"].as_str().unwrap_or("0x0"))?;

            // Handle access list
            let access_list = if let Some(al) = tx["accessList"].as_array() {
                let mut items = Vec::new();
                for item in al {
                    let address = Address::from_str(item["address"].as_str().unwrap_or(""))
                        .map_err(|e| {
                            ProofGeneratorError::EncodingError(format!(
                                "Access list address error: {}",
                                e
                            ))
                        })?;

                    let storage_keys: Result<Vec<U256>, _> = item["storageKeys"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|key| get_u256_from_hex(key.as_str().unwrap_or("0x0")))
                        .collect();

                    items.push(AccessListItem {
                        address,
                        storage_keys: storage_keys?,
                    });
                }
                AccessList(items)
            } else {
                AccessList(Vec::new())
            };

            #[derive(RlpEncodable)]
            #[rlp(trailing)]
            struct Eip1559Transaction {
                chain_id: U256,
                nonce: U256,
                max_priority_fee_per_gas: U256,
                max_fee_per_gas: U256,
                gas_limit: U256,
                to: Option<Address>,
                value: Option<U256>,
                input: Option<Bytes>,
                access_list: Option<AccessList>,
                v: Option<U256>,
                r: Option<U256>,
                s: Option<U256>,
            }

            let eip1559_tx = Eip1559Transaction {
                chain_id,
                nonce,
                max_priority_fee_per_gas: max_priority_fee,
                max_fee_per_gas: max_fee,
                gas_limit,
                to,
                value: Some(value),
                input: Some(input),
                access_list: Some(access_list),
                v: Some(v),
                r: Some(r),
                s: Some(s),
            };

            let encoded = encode(&eip1559_tx);
            // Prepend transaction type for EIP-1559
            Ok([vec![tx_type_num], encoded].concat())
        }
        _ => Err(ProofGeneratorError::EncodingError(format!(
            "Unsupported transaction type: {}",
            tx_type_num
        ))),
    }
}

#[derive(Debug, Clone)]
pub struct DecodedTransaction {
    pub tx_type: u8,
    pub nonce: U256,
    pub gas_limit: U256,
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    // Legacy specific
    pub gas_price: Option<U256>,
    // EIP-1559 specific
    pub chain_id: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub access_list: Option<Vec<(Address, Vec<U256>)>>,
}

impl DecodedTransaction {
    pub fn to_json(&self) -> Value {
        let mut json_obj = json!({
            "type": format!("0x{:x}", self.tx_type),
            "nonce": format!("0x{:x}", self.nonce),
            "gas": format!("0x{:x}", self.gas_limit),
            "to": self.to.map(|addr| format!("0x{:x}", addr)),
            "value": format!("0x{:x}", self.value),
            "input": format!("0x{}", hex::encode(&self.input)),
            "v": format!("0x{:x}", self.v),
            "r": format!("0x{:x}", self.r),
            "s": format!("0x{:x}", self.s),
        });

        match self.tx_type {
            0 => {
                // Legacy transaction
                if let Some(gas_price) = self.gas_price {
                    json_obj["gasPrice"] = json!(format!("0x{:x}", gas_price));
                }
            }
            2 => {
                // EIP-1559 transaction
                if let Some(chain_id) = self.chain_id {
                    json_obj["chainId"] = json!(format!("0x{:x}", chain_id));
                }
                if let Some(max_priority_fee) = self.max_priority_fee_per_gas {
                    json_obj["maxPriorityFeePerGas"] = json!(format!("0x{:x}", max_priority_fee));
                }
                if let Some(max_fee) = self.max_fee_per_gas {
                    json_obj["maxFeePerGas"] = json!(format!("0x{:x}", max_fee));
                }
                if let Some(access_list) = &self.access_list {
                    let al: Vec<Value> = access_list.iter().map(|(addr, keys)| {
                        json!({
                            "address": format!("0x{:x}", addr),
                            "storageKeys": keys.iter().map(|k| format!("0x{:x}", k)).collect::<Vec<_>>()
                        })
                    }).collect();
                    json_obj["accessList"] = json!(al);
                }
            }
            _ => {}
        }

        json_obj
    }
}

pub fn decode_bsc_transaction(
    encoded_data: &[u8],
) -> Result<DecodedTransaction, ProofGeneratorError> {
    if encoded_data.is_empty() {
        return Err(ProofGeneratorError::EncodingError(
            "Empty transaction data".to_string(),
        ));
    }

    // Check if it's a typed transaction (starts with transaction type)
    let first_byte = encoded_data[0];

    if first_byte < 0x80 {
        // Typed transaction (EIP-2718)
        let tx_type = first_byte;
        let rlp_data = &encoded_data[1..];

        match tx_type {
            2 => decode_eip1559_transaction(rlp_data),
            _ => Err(ProofGeneratorError::EncodingError(format!(
                "Unsupported transaction type: {}",
                tx_type
            ))),
        }
    } else {
        // Legacy transaction (RLP encoded directly)
        decode_legacy_transaction(encoded_data)
    }
}

fn decode_legacy_transaction(data: &[u8]) -> Result<DecodedTransaction, ProofGeneratorError> {
    let mut buf = data;

    // Decode RLP list header
    let header = alloy_rlp::Header::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode RLP header: {}", e))
    })?;

    if !header.list {
        return Err(ProofGeneratorError::EncodingError(
            "Expected RLP list for transaction".to_string(),
        ));
    }

    // Decode fields in order: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    let nonce = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode nonce: {}", e))
    })?;

    let gas_price = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode gas price: {}", e))
    })?;

    let gas_limit = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode gas limit: {}", e))
    })?;

    // Decode 'to' field (can be empty for contract creation)
    let to = if buf.is_empty() {
        None
    } else {
        let mut temp_buf = buf;
        let header = alloy_rlp::Header::decode(&mut temp_buf).map_err(|e| {
            ProofGeneratorError::EncodingError(format!("Failed to decode address header: {}", e))
        })?;

        if header.payload_length == 0 {
            buf = temp_buf;
            None
        } else {
            let addr = Address::decode(&mut buf).map_err(|e| {
                ProofGeneratorError::EncodingError(format!("Failed to decode address: {}", e))
            })?;
            Some(addr)
        }
    };

    let value = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode value: {}", e))
    })?;

    let input = Bytes::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode input: {}", e))
    })?;

    let v = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode v: {}", e)))?;

    let r = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode r: {}", e)))?;

    let s = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode s: {}", e)))?;

    Ok(DecodedTransaction {
        tx_type: 0,
        nonce,
        gas_limit,
        to,
        value,
        input,
        v,
        r,
        s,
        gas_price: Some(gas_price),
        chain_id: None,
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        access_list: None,
    })
}

fn decode_eip1559_transaction(data: &[u8]) -> Result<DecodedTransaction, ProofGeneratorError> {
    let mut buf = data;

    // Decode RLP list header
    let header = alloy_rlp::Header::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode RLP header: {}", e))
    })?;

    if !header.list {
        return Err(ProofGeneratorError::EncodingError(
            "Expected RLP list for EIP-1559 transaction".to_string(),
        ));
    }

    // Decode fields: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]
    let chain_id = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode chain ID: {}", e))
    })?;

    let nonce = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode nonce: {}", e))
    })?;

    let max_priority_fee_per_gas = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode max priority fee: {}", e))
    })?;

    let max_fee_per_gas = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode max fee: {}", e))
    })?;

    let gas_limit = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode gas limit: {}", e))
    })?;

    let to = decode_optional_address(&mut buf)?;

    let value = U256::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode value: {}", e))
    })?;

    let input = Bytes::decode(&mut buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode input: {}", e))
    })?;

    // Decode access list
    let access_list = decode_access_list(&mut buf)?;

    let v = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode v: {}", e)))?;

    let r = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode r: {}", e)))?;

    let s = U256::decode(&mut buf)
        .map_err(|e| ProofGeneratorError::EncodingError(format!("Failed to decode s: {}", e)))?;

    Ok(DecodedTransaction {
        tx_type: 2,
        nonce,
        gas_limit,
        to,
        value,
        input,
        v,
        r,
        s,
        gas_price: None,
        chain_id: Some(chain_id),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        max_fee_per_gas: Some(max_fee_per_gas),
        access_list: Some(access_list),
    })
}

fn decode_optional_address(buf: &mut &[u8]) -> Result<Option<Address>, ProofGeneratorError> {
    let header = alloy_rlp::Header::decode(buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode address header: {}", e))
    })?;

    if header.payload_length == 0 {
        // Empty address (contract creation)
        Ok(None)
    } else if header.payload_length == 20 {
        // Valid address
        let addr = Address::decode(buf).map_err(|e| {
            ProofGeneratorError::EncodingError(format!("Failed to decode address: {}", e))
        })?;
        Ok(Some(addr))
    } else {
        Err(ProofGeneratorError::EncodingError(format!(
            "Invalid address length: {}",
            header.payload_length
        )))
    }
}

fn decode_access_list(buf: &mut &[u8]) -> Result<Vec<(Address, Vec<U256>)>, ProofGeneratorError> {
    let header = alloy_rlp::Header::decode(buf).map_err(|e| {
        ProofGeneratorError::EncodingError(format!("Failed to decode access list header: {}", e))
    })?;

    if !header.list {
        return Err(ProofGeneratorError::EncodingError(
            "Expected list for access list".to_string(),
        ));
    }

    let mut access_list = Vec::new();
    let end_pos = buf.as_ptr() as usize + header.payload_length;

    while (buf.as_ptr() as usize) < end_pos {
        // Decode access list entry: [address, [storageKey1, storageKey2, ...]]
        let entry_header = alloy_rlp::Header::decode(buf).map_err(|e| {
            ProofGeneratorError::EncodingError(format!(
                "Failed to decode access list entry header: {}",
                e
            ))
        })?;

        if !entry_header.list {
            return Err(ProofGeneratorError::EncodingError(
                "Expected list for access list entry".to_string(),
            ));
        }

        let address = Address::decode(buf).map_err(|e| {
            ProofGeneratorError::EncodingError(format!(
                "Failed to decode access list address: {}",
                e
            ))
        })?;

        // Decode storage keys list
        let keys_header = alloy_rlp::Header::decode(buf).map_err(|e| {
            ProofGeneratorError::EncodingError(format!(
                "Failed to decode storage keys header: {}",
                e
            ))
        })?;

        if !keys_header.list {
            return Err(ProofGeneratorError::EncodingError(
                "Expected list for storage keys".to_string(),
            ));
        }

        let mut storage_keys = Vec::new();
        let keys_end_pos = buf.as_ptr() as usize + keys_header.payload_length;

        while (buf.as_ptr() as usize) < keys_end_pos {
            let key = U256::decode(buf).map_err(|e| {
                ProofGeneratorError::EncodingError(format!("Failed to decode storage key: {}", e))
            })?;
            storage_keys.push(key);
        }

        access_list.push((address, storage_keys));
    }

    Ok(access_list)
}

// Function to extract transaction from trie proof
// pub fn extract_transaction_from_proof(
//     root: B256,
//     tx_index: u64,
//     proof: Vec<Vec<u8>>,
// ) -> Result<DecodedTransaction, ProofGeneratorError> {
//     // First verify the proof and get the encoded transaction
//     // let encoded_tx = verify_trie_proof(root, tx_index, proof)?;

//     // Then decode the transaction
//     // decode_bsc_transaction(&encoded_tx)
// }

// Updated main function with correct transaction trie building
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let block_number = "0x302659E"; // Your block number

    // Get block data with transactions
    let block_data = get_block_by_number(block_number).await?;
    let transactions = block_data["result"]["transactions"]
        .as_array()
        .ok_or("No transactions found in block")?;

    println!("Found {} transactions in block", transactions.len());

    // Build transaction trie using RLP-encoded keys
    println!("Building transaction trie...");
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));

    for (i, tx) in transactions.iter().enumerate() {
        // Use RLP-encoded index as key (same as receipt trie)
        let key = encode(&i);
        let value = encode_bsc_transaction(tx)?;

        println!(
            "Inserting transaction {} (encoded key: {:?}) with value length: {}",
            i,
            key,
            value.len()
        );

        trie.insert(key.as_slice(), value.as_slice())
            .map_err(|e| format!("Failed to insert transaction {}: {:?}", i, e))?;
    }

    // Get constructed root
    let constructed_root = trie
        .root_hash()
        .map_err(|e| format!("Failed to get trie root: {:?}", e))?;
    let constructed_root_b256 = B256::from_slice(constructed_root.as_slice());

    // Get expected root from block header
    let expected_root_str = block_data["result"]["transactionsRoot"]
        .as_str()
        .ok_or("transactionsRoot not found in block data")?;
    let expected_root = B256::from_str(expected_root_str)?;

    println!("Transaction trie root comparison:");
    println!("Constructed root: {}", constructed_root_b256);
    println!("Expected root:    {}", expected_root);
    println!("Roots match: {}", constructed_root_b256 == expected_root);

    let proof = trie.get_proof(&encode(0_u8)).unwrap();
    println!("proof {:?}", proof);
    let k = trie
        .verify_proof(constructed_root, &encode(0_u8), proof)
        .unwrap();
    println!("k {:?}", k);
    let k = decode_bsc_transaction(&k.unwrap()).unwrap();
    println!("decode txn {:?}", k);

    Ok(())
}
