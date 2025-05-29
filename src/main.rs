use reqwest;
use serde_json::{json, Value};
use std::error::Error;
mod receipt;
mod trie;
use receipt::TransactionReceipt;
use trie::receipts_root_hash;

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
    println!("Raw response: {}", serde_json::to_string_pretty(&json_response)?);
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


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get block receipts for block 0xEDA8CE
    let receipts = get_block_receipts("0x3275ced").await?;
    println!("Receipts: {}", serde_json::to_string_pretty(&receipts[0])?);

    // Calculate and print the receipts trie root hash
    let root = trie::calculate_receipts_root_simple(&receipts);
    println!("Receipts trie root hash: 0x{:x}", root);

    let root2 = receipts_root_hash(&receipts);
    println!("Receipts trie root hash: 0x{:x}", root2);

    Ok(())
}
