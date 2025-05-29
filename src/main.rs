use reqwest;
use serde_json::{json, Value};
use std::error::Error;
// use eth_trie::EthTrie;
use eth_trie::{EthTrie, MemoryDB, Trie};
use std::sync::Arc;
use alloy_rlp::encode;
use alloy::primitives::B256;
use alloy_rpc_types::TransactionReceipt;
use alloy_consensus::{Receipt, ReceiptWithBloom, TxReceipt, TxType};
use std::str::FromStr;



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
            ProofGeneratorError::TransactionNotFound(e) => write!(f, "Transaction not found: {}", e),
            ProofGeneratorError::EncodeReceiptError(e) => write!(f, "Receipt encoding error: {}", e),
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
    let receipts: Vec<TransactionReceipt> = serde_json::from_value(json_response["result"].clone())?;
    Ok(receipts)
}

async fn get_block_by_number(block_number: &str) -> Result<Value, Box<dyn Error>> {
    let client = reqwest::Client::new();
    
    let request_body = json!({
        "method": "eth_getBlockByNumber",
        "params": [block_number,false],
        "id": 1,
        "jsonrpc": "2.0"
    });

    let response = client
        .post("https://go.getblock.io/7e5bdadc6d8b410fa2fda57bbfedce49/")
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
) -> Result<EthTrie<MemoryDB>, ProofGeneratorError> {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));
    for (i, leaf) in leaves.iter().enumerate() {
        let key = encode(&i);
        let value = encode_fn(leaf)?;
        trie.insert(key.as_slice(), value.as_slice()).unwrap();
    }

    Ok(trie)
}

pub fn get_tx_index(
    receipts: &[TransactionReceipt],
    tx_hash: &B256,
) -> Result<u64, ProofGeneratorError> {
    let tx_index = receipts
        .iter()
        .position(|r| format!("{:x}", r.transaction_hash) == format!("{:x}", tx_hash));

    match tx_index {
        Some(index) => Ok(index as u64),
        None => Err(ProofGeneratorError::TransactionNotFound(
            tx_hash.to_string(),
        )),
    }
}

pub async fn print_receipt_proof(receipts: &[TransactionReceipt], tx_hash:&B256) -> Result<Vec<Vec<u8>>, ProofGeneratorError> {
    let tx_index = get_tx_index(receipts, tx_hash)?;
    let mut trie = build_trie(receipts.to_vec(), encode_receipt)?;
    let tx_index = encode(&tx_index);
    let proof = trie.get_proof(tx_index.to_vec().as_slice()).unwrap();
    println!("Proof: {}", serde_json::to_string_pretty(&proof).unwrap());
    Ok(proof)
}

pub fn encode_receipt(receipt: &TransactionReceipt) -> Result<Vec<u8>, ProofGeneratorError> {
    let tx_type = receipt.transaction_type();
    if receipt.inner.as_receipt_with_bloom().is_none() {
        return Err(ProofGeneratorError::EncodeReceiptError(
            "receipt_with_bloom is none".to_string(),
        ));
    }
    let receipt = receipt.inner.as_receipt_with_bloom().unwrap();
    let logs = receipt
        .logs()
        .iter()
        .map(|l| l.inner.clone())
        .collect::<Vec<_>>();

    let consensus_receipt = Receipt {
        cumulative_gas_used: receipt.cumulative_gas_used(),
        status: receipt.status_or_post_state(),
        logs,
    };

    let rwb = ReceiptWithBloom::new(consensus_receipt, receipt.bloom());
    let encoded = alloy_rlp::encode(rwb);

    match tx_type {
        TxType::Legacy => Ok(encoded),
        _ => Ok([vec![tx_type as u8], encoded].concat()),
    }
}

pub fn verify_trie_proof(
    root: B256,
    key: u64,
    proof_bytes: Vec<Vec<u8>>,
) -> Result<Vec<u8>, ProofGeneratorError> {
    let memdb = Arc::new(MemoryDB::new(true));
    let trie = EthTrie::new(Arc::clone(&memdb));
    println!("Root: {}", root);
    let proof = trie.verify_proof(
        root.0.into(),
        encode(&key).as_slice(),
        proof_bytes,
    );

    if proof.is_err() {
        return Err(ProofGeneratorError::TrieError("Trie proof verification failure".to_string()));
    }

    match proof.unwrap() {
        Some(value) => Ok(value),
        None => Err(ProofGeneratorError::TrieError("Trie proof verification failure".to_string())),
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get block by number (example: block 0xEDA8CE)
    // println!("Fetching block 50488734...");
    // let block_data = get_block_by_number("0x33275ced").await?;
    // println!("Block data: {}", serde_json::to_string_pretty(&block_data)?);

    // Get block receipts for block 0xEDA8CE
    // println!("\nFetching block receipts for block 50488734...");
    let receipts = get_block_receipts("0x3275ced").await?;
    println!("Receipts: {}", serde_json::to_string_pretty(&receipts[0])?);
    let proof = print_receipt_proof(&receipts, &B256::from_str("0x89d7d9e273b05b7e301918f59a9ffe6d2c78560cdec2a785b64d28c960dd6e16").unwrap()).await?;
    // println!("Block receipts: {}", serde_json::to_string_pretty(&receipts)?);
    
    let tx_index = get_tx_index(&receipts,&B256::from_str("0x89d7d9e273b05b7e301918f59a9ffe6d2c78560cdec2a785b64d28c960dd6e16").unwrap() )?;
    println!("Tx index: {}", tx_index);
    let res = verify_trie_proof(B256::from_str("0x98e76b31b83bf64e6ece0ec2f5970e511b0d9a7d3dd490b878051d1c93bfa9b6").unwrap(),tx_index, proof)?;
    println!("Res: {}", serde_json::to_string_pretty(&res)?);
    Ok(())
}
