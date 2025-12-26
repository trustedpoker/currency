/// Tron blockchain integration module for TRC-20 USDT support
///
/// This module provides:
/// - HTTP client for TronGrid API communication
/// - Transaction construction and signing
/// - Address validation and utilities
/// - Type definitions for Tron blockchain interactions
/// - IC threshold ECDSA integration for per-user addresses

pub mod types;
pub mod http_client;
pub mod transaction;
pub mod utils;
pub mod ecdsa;

// Re-export commonly used items
pub use types::*;
pub use http_client::TronHttpClient;
pub use transaction::{TronTransaction, create_transfer_transaction};
pub use utils::*;
pub use ecdsa::{derive_tron_address_for_user, sign_with_threshold_ecdsa};

