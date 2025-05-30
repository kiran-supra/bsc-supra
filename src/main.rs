use alloy::primitives::B256;
use alloy_consensus::{Receipt, ReceiptWithBloom, TxReceipt, TxType};
use alloy_rlp::encode;
use alloy_rlp::{Buf, Decodable};
use alloy_rpc_types::TransactionReceipt;
use eth_trie::{EthTrie, MemoryDB, Trie};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;
// use alloy::const_hex::ToHex;
use hex::ToHex;

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

async fn get_block_receipts(block_number: &str) -> Result<Vec<TransactionReceipt>, Box<dyn Error>> {
    let client = reqwest::Client::new();

    let request_body = json!({
        "method": "eth_getBlockReceipts",
        "params": [block_number],
        "id": 1,
        "jsonrpc": "2.0"
    });

    let response = client
        .post("https://bsc-testnet-rpc.publicnode.com/")
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let json_response: Value = response.json().await?;
    let receipts: Vec<TransactionReceipt> =
        serde_json::from_value(json_response["result"].clone())?;
    Ok(receipts)
}

async fn get_block_by_number(block_number: &str) -> Result<Value, Box<dyn Error>> {
    let client = reqwest::Client::new();

    let request_body = json!({
        "method": "eth_getBlockByNumber",
        "params": [block_number, false],
        "id": 1,
        "jsonrpc": "2.0"
    });

    let response = client
        .post("https://bsc-testnet-rpc.publicnode.com/") // Use same RPC for consistency
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let block_data: Value = response.json().await?;
    Ok(block_data)
}

pub fn build_trie<T>(
    leaves: Vec<T>,
    encode_fn: fn(&T) -> Result<Vec<u8>, ProofGeneratorError>,
) -> Result<(EthTrie<MemoryDB>, B256), ProofGeneratorError> {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));

    for (i, leaf) in leaves.iter().enumerate() {
        // Use RLP encoding for the key (transaction index)
        let key = encode(&i);
        let value = encode_fn(leaf)?;

        println!(
            "Inserting key {} (encoded: {:?}) with value length: {}",
            i,
            key,
            value.len()
        );

        trie.insert(key.as_slice(), value.as_slice()).map_err(|e| {
            ProofGeneratorError::TrieError(format!("Failed to insert into trie: {:?}", e))
        })?;
    }

    // Get the root hash of our constructed trie
    let root = trie
        .root_hash()
        .map_err(|e| ProofGeneratorError::TrieError(format!("Failed to get root hash: {:?}", e)))?;

    let root_b256 = B256::from_slice(root.as_slice());
    println!("Constructed trie root: {}", root_b256);

    Ok((trie, root_b256))
}

pub fn get_tx_index(
    receipts: &[TransactionReceipt],
    tx_hash: &B256,
) -> Result<u64, ProofGeneratorError> {
    let tx_index = receipts.iter().position(|r| r.transaction_hash == *tx_hash);

    match tx_index {
        Some(index) => Ok(index as u64),
        None => Err(ProofGeneratorError::TransactionNotFound(
            tx_hash.to_string(),
        )),
    }
}

pub async fn print_receipt_proof(
    receipts: &[TransactionReceipt],
    tx_hash: &B256,
) -> Result<(Vec<Vec<u8>>, B256), ProofGeneratorError> {
    let tx_index = get_tx_index(receipts, tx_hash)?;
    let (mut trie, constructed_root) = build_trie(receipts.to_vec(), encode_receipt)?;
    let tx_index_encoded = encode(&tx_index);

    println!("Transaction index: {}", tx_index);
    println!("Constructed trie root: {}", constructed_root);

    let proof = trie
        .get_proof(tx_index_encoded.as_slice())
        .map_err(|e| ProofGeneratorError::TrieError(format!("Failed to get proof: {:?}", e)))?;

    println!("Proof has {} nodes", proof.len());
    for (i, node) in proof.iter().enumerate() {
        println!("Proof node {}: {} bytes", i, node.len());
    }

    Ok((proof, constructed_root))
}

pub fn encode_receipt(receipt: &TransactionReceipt) -> Result<Vec<u8>, ProofGeneratorError> {
    let tx_type = receipt.transaction_type();

    if receipt.inner.as_receipt_with_bloom().is_none() {
        return Err(ProofGeneratorError::EncodeReceiptError(
            "receipt_with_bloom is none".to_string(),
        ));
    }

    let receipt_bloom = receipt.inner.as_receipt_with_bloom().unwrap();
    let logs = receipt_bloom
        .logs()
        .iter()
        .map(|l| l.inner.clone())
        .collect::<Vec<_>>();

    let consensus_receipt = Receipt {
        cumulative_gas_used: receipt_bloom.cumulative_gas_used(),
        status: receipt_bloom.status_or_post_state(),
        logs: logs.clone(), // Clone to avoid move issue
    };

    let rwb = ReceiptWithBloom::new(consensus_receipt, receipt_bloom.bloom());

    // For debugging - print receipt details
    println!("Receipt details:");
    println!("  Type: {:?}", tx_type);
    println!(
        "  Cumulative gas used: {}",
        receipt_bloom.cumulative_gas_used()
    );
    println!("  Status: {:?}", receipt_bloom.status_or_post_state());
    println!("  Logs count: {}", logs.len());

    let encoded = alloy_rlp::encode(&rwb);
    println!("  RLP encoded length: {}", encoded.len());

    let final_encoded = match tx_type {
        TxType::Legacy => {
            println!("  Using legacy encoding (no type prefix)");
            encoded
        }
        _ => {
            println!(
                "  Using typed encoding (with type prefix: {})",
                tx_type as u8
            );
            [vec![tx_type as u8], encoded].concat()
        }
    };

    println!("  Final encoded length: {}", final_encoded.len());
    Ok(final_encoded)
}

pub fn verify_trie_proof(
    root: B256,
    key: u64,
    proof_bytes: Vec<Vec<u8>>,
) -> Result<Vec<u8>, ProofGeneratorError> {
    let memdb = Arc::new(MemoryDB::new(true));
    let trie = EthTrie::new(Arc::clone(&memdb));

    println!("Root: {}", root);
    println!("Key: {}", key);
    println!("Proof length: {}", proof_bytes.len());

    let proof = trie.verify_proof(root.0.into(), encode(&key).as_slice(), proof_bytes);

    match proof {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(ProofGeneratorError::TrieError(
            "Proof verification returned None".to_string(),
        )),
        Err(e) => Err(ProofGeneratorError::TrieError(format!(
            "Trie proof verification error: {:?}",
            e
        ))),
    }
}

// Helper function to get receipt root from block
pub async fn get_receipt_root(block_number: &str) -> Result<B256, Box<dyn Error>> {
    let block_data = get_block_by_number(block_number).await?;

    let receipt_root_str = block_data["result"]["receiptsRoot"]
        .as_str()
        .ok_or("receiptsRoot not found in block data")?;

    let receipt_root = B256::from_str(receipt_root_str)?;
    Ok(receipt_root)
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct ExtractedLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// A collection of extracted logs from an Ethereum receipt.
///
/// # Fields
///
/// * `0` - A vector containing multiple `ExtractedLog` entries.
#[derive(Default, Debug)]
pub struct ExtractedLogs(pub Vec<ExtractedLog>);

/// Implements decoding for `ExtractedLogs` using RLP (Recursive Length Prefix).
///
/// # Errors
///
/// Returns an `alloy_rlp::Error` if decoding fails due to invalid structure or unexpected data.
impl Decodable for ExtractedLogs {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        let rlp_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
            "cannot decode a receipt from empty bytes",
        ))?;
        match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
            Ordering::Less => {
                let _header = alloy_rlp::Header::decode(buf)?;
                let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
                    "cannot decode receipt logs from empty list",
                ))?;

                if receipt_type > 3 {
                    return Err(alloy_rlp::Error::Custom("Invalid Receipt Type"));
                }
                buf.advance(1);
            }
            Ordering::Equal => {
                return Err(alloy_rlp::Error::Custom(
                    "an empty list is not a valid receipt encoding",
                ));
            }
            _ => {}
        };

        let mut logs_list: ExtractedLogs = ExtractedLogs::default();

        let b = &mut &**buf;
        let rlp_head = alloy_rlp::Header::decode(b)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        for _i in 0..3 {
            // skip fields success, cumulative_gas_used, bloom
            let head = alloy_rlp::Header::decode(b)?;
            b.advance(head.payload_length);
        }

        let logs_head = alloy_rlp::Header::decode(b)?;
        if !logs_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        while !b.is_empty() {
            let mut log: ExtractedLog = ExtractedLog::default();
            let item_head = alloy_rlp::Header::decode(b)?;
            if !item_head.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }

            log.address = alloy_rlp::Decodable::decode(b)?;

            let topic_list_head = alloy_rlp::Header::decode(b)?;
            for _i in 0..(topic_list_head.payload_length / 32) {
                log.topics.push(alloy_rlp::Decodable::decode(b)?);
            }

            log.data = Vec::from(alloy_rlp::Header::decode_bytes(b, false)?);

            logs_list.0.push(log);
        }

        Ok(logs_list)
    }
}

pub fn get_logs_from_receipt(receipt: &[u8]) -> Result<ExtractedLogs, ProofGeneratorError> {
    let logs: ExtractedLogs = alloy_rlp::Decodable::decode(&mut &receipt[..])
        .map_err(|_| ProofGeneratorError::TrieError("Failed to decode receipt".to_string()))?;
    Ok(logs)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let block_number = "0x3275CED";
    let tx_hash =
        B256::from_str("0x89d7d9e273b05b7e301918f59a9ffe6d2c78560cdec2a785b64d28c960dd6e16")?;

    println!("Fetching block receipts for block {}...", block_number);
    let receipts = get_block_receipts(block_number).await?;
    println!("Found {} receipts", receipts.len());

    // Get the actual receipt root from the block
    println!("\nFetching receipt root from block...");
    let block_receipt_root = get_receipt_root(block_number).await?;
    println!("Receipt root from block header: {}", block_receipt_root);

    // Generate proof and get our constructed root
    println!("\nGenerating receipt proof...");
    let (proof, constructed_root) = print_receipt_proof(&receipts, &tx_hash).await?;

    println!("proof {:?}", proof);

    // Compare roots
    println!("\nRoot comparison:");
    println!("Block header root:   {}", block_receipt_root);
    println!("Constructed root:    {}", constructed_root);

    // Get transaction index
    let tx_index = get_tx_index(&receipts, &tx_hash)?;
    println!("\nTransaction index: {}", tx_index);

    // Try verification with both roots
    println!("\n=== Verification with block header root ===");
    match verify_trie_proof(block_receipt_root, tx_index, proof.clone()) {
        Ok(verified_data) => {
            println!("Verification successful with block header root!");
            println!("Verified data length: {} bytes", verified_data.len());

            // Compare with original receipt encoding
            let decoded = get_logs_from_receipt(&verified_data)?;
            println!("Decoded logs: {:?}", decoded);
            // println!("address {:?}",decoded.g
            let extracted_log = decoded.0.get(0 as usize).unwrap();
            println!("address {:?}", extracted_log.address.as_slice());
            let original_encoded = encode_receipt(&receipts[tx_index as usize])?;
            println!("Original receipt length: {} bytes", original_encoded.len());
            println!("Data matches: {}", verified_data == original_encoded);
        }
        Err(e) => {
            println!("Verification failed with block header root: {}", e);
        }
    }

    // println!("\n=== Verification with constructed root ===");
    // match verify_trie_proof(constructed_root, tx_index, proof.clone()) {
    //     Ok(verified_data) => {
    //         println!(" Verification successful with constructed root!");
    //         println!("Verified data length: {} bytes", verified_data.len());

    //         // Compare with original receipt encoding
    //         let original_encoded = encode_receipt(&receipts[tx_index as usize])?;
    //         println!("Original receipt length: {} bytes", original_encoded.len());
    //         println!("Data matches: {}", verified_data == original_encoded);
    //         // println!("Result: {:?}", alloy_rlp::decode::<TransactionReceipt>(&verified_data));
    //     }
    //     Err(e) => {
    //         println!(" Verification failed with constructed root: {}", e);
    //     }
    // }

    // If roots don't match, there might be an issue with receipt encoding
    // if block_receipt_root != constructed_root {

    //     for (i, receipt) in receipts.iter().take(3).enumerate() {
    //         println!("\nReceipt {}:", i);
    //         println!("  Transaction hash: {}", receipt.transaction_hash);
    //         println!("  Gas used: {}", receipt.gas_used);

    //         match encode_receipt(receipt) {
    //             Ok(encoded) => println!("  Encoded length: {} bytes", encoded.len()),
    //             Err(e) => println!("  Encoding error: {}", e),
    //         }
    //     }
    // }

    Ok(())
}
