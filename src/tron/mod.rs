/// Tron blockchain integration module for TRC-20 USDT support
///
/// This module provides:
/// - HTTP client for TronGrid API communication
/// - Transaction construction and signing
/// - Address validation and utilities
/// - Type definitions for Tron blockchain interactions

pub mod types;
pub mod http_client;
pub mod transaction;
pub mod utils;

// Re-export commonly used items
pub use types::*;
pub use http_client::TronHttpClient;
pub use transaction::{TronTransaction, create_transfer_transaction};
pub use utils::*;

