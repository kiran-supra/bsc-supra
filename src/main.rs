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

#[derive(RlpEncodable)]
struct AccessListEntry {
    address: Address,
    storage_keys: Vec<B256>,
}

#[derive(RlpEncodable)]
struct LegacyTransaction {
    nonce: U256,
    gas_price: U256,
    gas_limit: U256,
    to: Address,
    value: U256,
    input: Bytes,
    v: U256,
    r: U256,
    s: U256,
}

#[derive(RlpEncodable)]
struct Eip2930Transaction {
    chain_id: U256,
    nonce: U256,
    gas_price: U256,
    gas_limit: U256,
    to: Address,
    value: U256,
    input: Bytes,
    access_list: Vec<AccessListEntry>,
    v: U256,
    r: U256,
    s: U256,
}

#[derive(RlpEncodable)]
struct Eip1559Transaction {
    chain_id: U256,
    nonce: U256,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: U256,
    to: Address,
    value: U256,
    input: Bytes,
    access_list: Vec<AccessListEntry>,
    v: U256,
    r: U256,
    s: U256,
}

pub fn encode_bsc_transaction(tx: &Value) -> Result<Vec<u8>, ProofGeneratorError> {
    // Helper to decode hex and convert to minimal bytes for RLP
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
        let bytes = hex::decode(&hex)
            .map_err(|e| ProofGeneratorError::EncodingError(format!("Hex decode error: {}", e)))?;
        Ok(bytes)
    }

    // Helper to get U256 from hex string
    fn get_u256_from_hex(hex_str: &str) -> Result<U256, ProofGeneratorError> {
        if hex_str == "0x" || hex_str.is_empty() || hex_str == "0x0" {
            return Ok(U256::ZERO);
        }
        U256::from_str_radix(hex_str.strip_prefix("0x").unwrap_or(hex_str), 16)
            .map_err(|e| ProofGeneratorError::EncodingError(format!("U256 parse error: {}", e)))
    }

    // Extract transaction fields
    let tx_type = tx["type"].as_str().unwrap_or("0x0");
    let tx_type_num = if tx_type == "0x" || tx_type.is_empty() || tx_type == "0x0" {
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
            let gas_price = get_u256_from_hex(tx["gasPrice"].as_str().unwrap_or("0x0"))?;
            let legacy_tx = LegacyTransaction {
                nonce,
                gas_price,
                gas_limit,
                to: to.unwrap_or(Address::ZERO),
                value,
                input,
                v,
                r,
                s,
            };
            Ok(encode(&legacy_tx))
        }
        1 => {
            let chain_id = get_u256_from_hex(tx["chainId"].as_str().unwrap_or("0x38"))?;
            let gas_price = get_u256_from_hex(tx["gasPrice"].as_str().unwrap_or("0x0"))?;

            // Handle access list - convert to simple tuple format
            let access_list: Vec<AccessListEntry> = if let Some(al) = tx["accessList"].as_array() {
                let mut items = Vec::new();
                for item in al {
                    let address = Address::from_str(item["address"].as_str().unwrap_or(""))
                        .map_err(|e| {
                            ProofGeneratorError::EncodingError(format!(
                                "Access list address error: {}",
                                e
                            ))
                        })?;
                    let storage_keys: Result<Vec<B256>, _> = item["storageKeys"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|key| {
                            let key_str = key.as_str().unwrap_or("0x0");
                            B256::from_str(key_str).map_err(|e| {
                                ProofGeneratorError::EncodingError(format!(
                                    "Storage key parse error: {}",
                                    e
                                ))
                            })
                        })
                        .collect();
                    items.push(AccessListEntry {
                        address,
                        storage_keys: storage_keys?,
                    });
                }
                items
            } else {
                Vec::new()
            };

            let eip2930_tx = Eip2930Transaction {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to: to.unwrap_or(Address::ZERO),
                value,
                input,
                access_list,
                v,
                r,
                s,
            };
            let encoded = encode(&eip2930_tx);
            Ok([vec![0x01], encoded].concat())
        }
        2 => {
            let chain_id = get_u256_from_hex(tx["chainId"].as_str().unwrap_or("0x38"))?;
            let max_priority_fee =
                get_u256_from_hex(tx["maxPriorityFeePerGas"].as_str().unwrap_or("0x0"))?;
            let max_fee = get_u256_from_hex(tx["maxFeePerGas"].as_str().unwrap_or("0x0"))?;

            // Handle access list
            let access_list: Vec<AccessListEntry> = if let Some(al) = tx["accessList"].as_array() {
                let mut items = Vec::new();
                for item in al {
                    let address = Address::from_str(item["address"].as_str().unwrap_or(""))
                        .map_err(|e| {
                            ProofGeneratorError::EncodingError(format!(
                                "Access list address error: {}",
                                e
                            ))
                        })?;
                    let storage_keys: Result<Vec<B256>, _> = item["storageKeys"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|key| {
                            let key_str = key.as_str().unwrap_or("0x0");
                            B256::from_str(key_str).map_err(|e| {
                                ProofGeneratorError::EncodingError(format!(
                                    "Storage key parse error: {}",
                                    e
                                ))
                            })
                        })
                        .collect();
                    items.push(AccessListEntry {
                        address,
                        storage_keys: storage_keys?,
                    });
                }
                items
            } else {
                Vec::new()
            };

            let eip1559_tx = Eip1559Transaction {
                chain_id,
                nonce,
                max_priority_fee_per_gas: max_priority_fee,
                max_fee_per_gas: max_fee,
                gas_limit,
                to: to.unwrap_or(Address::ZERO),
                value,
                input,
                access_list,
                v,
                r,
                s,
            };
            let encoded = encode(&eip1559_tx);
            Ok([vec![0x02], encoded].concat())
        }
        _ => Err(ProofGeneratorError::EncodingError(format!(
            "Unsupported transaction type: {}",
            tx_type_num
        ))),
    }
}

// Add this debug function to compare individual transactions
async fn debug_transaction_encoding(
    block_number: &str,
    tx_index: usize,
) -> Result<(), Box<dyn Error>> {
    let block_data = get_block_by_number(block_number).await?;
    let transactions = block_data["result"]["transactions"]
        .as_array()
        .ok_or("No transactions found in block")?;

    if tx_index >= transactions.len() {
        return Err("Transaction index out of bounds".into());
    }

    let tx = &transactions[tx_index];
    let encoded = encode_bsc_transaction(tx)?;

    println!("Transaction {} details:", tx_index);
    println!("Type: {}", tx["type"].as_str().unwrap_or("0x0"));
    println!("Hash: {}", tx["hash"].as_str().unwrap_or(""));
    println!("Encoded length: {}", encoded.len());
    println!(
        "Encoded (first 100 bytes): {}",
        hex::encode(&encoded[..std::cmp::min(100, encoded.len())])
    );

    Ok(())
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let block_number = "0x302659E"; // Your block number

    // Debug first few transactions
    for i in 0..std::cmp::min(3, 5) {
        if let Err(e) = debug_transaction_encoding(block_number, i).await {
            println!("Debug error for tx {}: {}", i, e);
        }
    }

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

        if i < 3 {
            println!(
                "Inserting transaction {} (key: {}, value length: {})",
                i,
                hex::encode(&key),
                value.len()
            );
        }

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

    if constructed_root_b256 == expected_root {
        let proof = trie.get_proof(&encode(0_u8)).unwrap();
        println!("Proof generated successfully with {} nodes", proof.len());

        let verified_value = trie
            .verify_proof(constructed_root, &encode(0_u8), proof)
            .unwrap();

        if let Some(value) = verified_value {
            let decoded_tx = decode_bsc_transaction(&value).unwrap();
            println!("Successfully decoded transaction: {:?}", decoded_tx.tx_type);
        }
    }

    Ok(())
}
