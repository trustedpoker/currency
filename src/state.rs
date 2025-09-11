use candid::{CandidType, Decode, Encode};
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};

const REMOVE_PERCENTAGE: usize = 20;
const MAX_VALUE_SIZE_TRANSACTION_STATE: u32 = 2_000_000;

#[derive(Debug, Clone, PartialEq, CandidType, Deserialize, Serialize)]
pub struct TransactionState {
    processed_transactions: HashSet<String>,
}

impl Default for TransactionState {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionState {
    pub fn new() -> TransactionState {
        TransactionState {
            processed_transactions: HashSet::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction_id: String) {
        if self.processed_transactions.len() >= MAX_VALUE_SIZE_TRANSACTION_STATE as usize / 100 {
            // Extract timestamps and sort
            let mut transactions: Vec<(i64, String)> = self
                .processed_transactions
                .iter()
                .filter_map(|tx| {
                    // Split by last hyphen to get timestamp
                    let parts: Vec<&str> = tx.rsplitn(2, '-').collect();
                    if parts.len() == 2 {
                        // Parse timestamp
                        if let Ok(timestamp) = parts[0].parse::<i64>() {
                            return Some((timestamp, tx.to_string()));
                        }
                    }
                    None
                })
                .collect();

            // Sort by timestamp (oldest first)
            transactions.sort_by_key(|(timestamp, _)| *timestamp);

            // Remove oldest transactions
            let remove_count = (self.processed_transactions.len() * REMOVE_PERCENTAGE) / 100;
            let keep_transactions: HashSet<String> = transactions
                .into_iter()
                .skip(remove_count) // Skip oldest transactions
                .map(|(_, tx_id)| tx_id)
                .collect();

            self.processed_transactions = keep_transactions;
        }

        self.processed_transactions.insert(transaction_id);
    }

    pub fn transaction_exists(&self, transaction_id: &str) -> bool {
        self.processed_transactions.contains(transaction_id)
    }
}

impl Storable for TransactionState {
    /// Serializes the struct into a byte array.
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        match Encode!(self) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(e) => {
                ic_cdk::println!("Serialization error: {:?}", e);
                // Return empty state bytes rather than empty vec
                let empty_state = TransactionState::new();
                Cow::Owned(Encode!(&empty_state).unwrap_or_else(|_| vec![]))
            }
        }
    }

    /// Deserializes the struct from a byte array.
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap_or_else(|e| {
            ic_cdk::println!("Deserialization error: {:?}", e);
            TransactionState::default()
        })
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_VALUE_SIZE_TRANSACTION_STATE,
        is_fixed_size: false,
    };
}
