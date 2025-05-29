use reqwest;
use serde_json::{json, Value};
use std::error::Error;
use rlp::{Encodable, RlpStream, encode};
use std::str::FromStr;
use eth_trie::{EthTrie, MemoryDB, Trie};
use std::sync::Arc;
use hex;
use alloy_primitives::B256;

#[derive(Debug)]
struct MyLog {
    address: Vec<u8>,
    topics: Vec<Vec<u8>>,
    data: Vec<u8>,
}

#[derive(Debug)]
struct MyReceipt {
    cumulative_gas_used: u64,
    status: u8,
    logs: Vec<MyLog>,
    bloom: Vec<u8>,
}

impl Encodable for MyLog {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.address);
        s.begin_list(self.topics.len());
        for topic in &self.topics {
            s.append(topic);
        }
        s.append(&self.data);
    }
}

impl Encodable for MyReceipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.cumulative_gas_used);
        s.append(&self.status);
        s.begin_list(self.logs.len());
        for log in &self.logs {
            s.append(log);
        }
        s.append(&self.bloom);
    }
}

async fn get_block_receipts(block_number: &str) -> Result<Vec<MyReceipt>, Box<dyn Error>> {
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
    let receipts_json = json_response["result"].as_array().ok_or("No receipts found")?;
    let mut receipts = Vec::new();
    for receipt_json in receipts_json {
        let cumulative_gas_used = u64::from_str_radix(receipt_json["cumulativeGasUsed"].as_str().unwrap().trim_start_matches("0x"), 16)?;
        let status = if receipt_json["status"].as_str().unwrap() == "0x1" { 1 } else { 0 };
        let logs_json = receipt_json["logs"].as_array().unwrap();
        let mut logs = Vec::new();
        for log_json in logs_json {
            let address = hex::decode(log_json["address"].as_str().unwrap().trim_start_matches("0x"))?;
            let topics_json = log_json["topics"].as_array().unwrap();
            let mut topics = Vec::new();
            for topic in topics_json {
                topics.push(hex::decode(topic.as_str().unwrap().trim_start_matches("0x"))?);
            }
            let data = hex::decode(log_json["data"].as_str().unwrap().trim_start_matches("0x"))?;
            logs.push(MyLog { address, topics, data });
        }
        let bloom = hex::decode(receipt_json["logsBloom"].as_str().unwrap().trim_start_matches("0x"))?;
        receipts.push(MyReceipt { cumulative_gas_used, status, logs, bloom });
    }
    Ok(receipts)
}

fn build_trie(receipts: &[MyReceipt]) -> (EthTrie<MemoryDB>, B256) {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));
    for (i, receipt) in receipts.iter().enumerate() {
        let key = encode(&i);
        let value = rlp::encode(receipt);
        trie.insert(&key, &value).unwrap();
    }
    let raw_root = trie.root_hash().unwrap();
    let root = B256::from_slice(&raw_root[..]);
    (trie, root)
}

fn generate_proof(trie: &mut EthTrie<MemoryDB>, key: &[u8]) -> Vec<Vec<u8>> {
    trie.get_proof(key).unwrap()
}

fn verify_proof(root: B256, key: &[u8], proof: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let memdb = Arc::new(MemoryDB::new(true));
    let trie = EthTrie::new(Arc::clone(&memdb));
    let root_fixed = alloy_primitives::FixedBytes::<32>::from_slice(root.as_slice());
    trie.verify_proof(root.0.into(), key, proof).unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let block_number = "0x3275ced";
    let receipts = get_block_receipts(block_number).await?;
    println!("Fetched {} receipts", receipts.len());
    let (mut trie, root) = build_trie(&receipts);
    println!("Trie root: 0x{}", hex::encode(root.as_slice()));
    let tx_index: usize = 0; // Replace with actual index if needed
    let key = encode(&tx_index);
    let proof = generate_proof(&mut trie, &key);
    let value = trie.get(&key).unwrap();
    let verified = verify_proof(root, &key, proof.clone());
    let is_verified = match (verified, value) {
        (Some(v1), Some(v2)) => v1 == v2,
        _ => false,
    };
    println!("Proof verified: {}", is_verified);
    Ok(())
}
