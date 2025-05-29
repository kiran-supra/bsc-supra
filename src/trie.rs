use std::collections::HashMap;
use sha3::{Digest, Keccak256};
use ethereum_types::H256;
use rlp::{encode, Encodable};
use crate::receipt::TransactionReceipt;

pub struct PatriciaTrie {
    nodes: HashMap<H256, Vec<u8>>,
    root: Option<H256>,
}

impl PatriciaTrie {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root: None,
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        // Simplified trie insertion - in production use a full MPT implementation
        let mut hasher = Keccak256::new();
        hasher.update(key);
        hasher.update(value);
        let hash = H256::from_slice(&hasher.finalize());
        self.nodes.insert(hash, value.to_vec());
    }

    pub fn root_hash(&mut self, items: &[(Vec<u8>, Vec<u8>)]) -> H256 {
        if items.is_empty() {
            return H256::zero();
        }

        // Build trie from key-value pairs
        let mut hasher = Keccak256::new();
        for (key, value) in items {
            hasher.update(key);
            hasher.update(value);
        }
        
        H256::from_slice(&hasher.finalize())
    }
}

/// Build a PatriciaTrie from a slice of TransactionReceipt
pub fn build_receipts_trie(receipts: &[TransactionReceipt]) -> PatriciaTrie {
    let mut trie = PatriciaTrie::new();
    for (i, receipt) in receipts.iter().enumerate() {
        let key = encode(&i).to_vec();
        let value = receipt.rlp_encode();
        trie.insert(&key, &value);
    }
    trie
}

/// Get the root hash from a slice of TransactionReceipt
pub fn receipts_root_hash(receipts: &[TransactionReceipt]) -> H256 {
    let mut items = Vec::new();
    for (i, receipt) in receipts.iter().enumerate() {
        let key = encode(&i).to_vec();
        let value = receipt.rlp_encode();
        items.push((key, value));
    }
    let mut trie = PatriciaTrie::new();
    trie.root_hash(&items)
} 

pub fn calculate_receipts_root_simple(receipts: &[TransactionReceipt]) -> H256 {
    let mut hasher = Keccak256::new();
    
    for (index, receipt) in receipts.iter().enumerate() {
        // Hash index + encoded receipt
        let index_bytes = encode(&index);
        let receipt_bytes = encode(receipt);
        
        hasher.update(&index_bytes);
        hasher.update(&receipt_bytes);
    }
    
    H256::from_slice(&hasher.finalize())
}