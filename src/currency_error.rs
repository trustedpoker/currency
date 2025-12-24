use candid::CandidType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Define a new encompassing error type that includes GameError and LockError
#[derive(Error, Debug, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub enum CurrencyError {
    #[error("failed to acquire lock")]
    LockError,

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("Block query failed: {0}")]
    BlockQueryFailed(String),

    #[error("Block not found")]
    BlockNotFound,

    #[error("No block number provided")]
    NoBlockNumberProvided,

    #[error("No transaction signature provided")]
    NoTransactionSignatureProvided,

    #[error("Invalid transaction details")]
    InvalidTransactionDetails,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Invalid transaction type")]
    InvalidTransactionType,

    #[error("Duplicate transaction")]
    DuplicateTransaction,

    #[error("Ledger error: {0}")]
    LedgerError(String),

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Get block error: {0}")]
    GetBlockError(String),

    #[error("Canister call failed")]
    CanisterCallFailed(String),

    #[error("No deposit address found")]
    NoDepositAddress,

    #[error("Wallet not set")]
    WalletNotSet,

    #[error("Withdraw failed: {0}")]
    WithdrawalFailed(String),

    #[error("Insufficient allowance")]
    InsufficientAllowance,

    #[error("Failed to check allowance")]
    AllowanceCheckFailed(String),

    #[error("Failed to transfer from")]
    TransferFromFailed(String),

    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),

    // Tron-specific errors
    #[error("Invalid Tron address: {0}")]
    InvalidAddress(String),

    #[error("Invalid HTTP response: {0}")]
    InvalidResponse(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Transaction verification failed: {0}")]
    TransactionVerificationFailed(String),

    #[error("Hot wallet balance insufficient")]
    HotWalletInsufficientBalance,

    #[error("Tron address not linked")]
    TronAddressNotLinked,
}
