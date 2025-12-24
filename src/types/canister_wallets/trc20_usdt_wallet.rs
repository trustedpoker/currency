use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

use crate::{
    currency_error::CurrencyError,
    state::TransactionState,
    tron::{TronHttpClient, TronTxInfo},
    types::canister_wallet::CanisterWallet,
};

/// TRC-20 USDT wallet implementation
/// 
/// This wallet manages TRC-20 USDT deposits and withdrawals.
/// Unlike other wallets, it doesn't use ICRC-2 allowances.
/// Instead, it uses:
/// - On-demand deposit verification (user provides tx hash)
/// - Direct withdrawal via HTTP outcalls to Tron network
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct TRC20USDTWallet {
    /// Hot wallet address on Tron network
    pub hot_wallet_address: String,
    /// Whether to use testnet (Shasta) or mainnet
    pub is_testnet: bool,
    /// Optional TronGrid API key for higher rate limits
    pub api_key: Option<String>,
}

impl TRC20USDTWallet {
    /// Create a new TRC20USDTWallet
    pub fn new(hot_wallet_address: String, is_testnet: bool, api_key: Option<String>) -> Self {
        Self {
            hot_wallet_address,
            is_testnet,
            api_key,
        }
    }

    /// Get TronGrid HTTP client
    fn get_client(&self) -> TronHttpClient {
        if self.is_testnet {
            TronHttpClient::testnet(self.api_key.clone())
        } else {
            TronHttpClient::mainnet(self.api_key.clone())
        }
    }

    /// Verify a deposit transaction
    /// 
    /// This method is called by the user to verify their deposit.
    /// The user provides the transaction hash, and we verify:
    /// 1. Transaction exists and is confirmed
    /// 2. Sender matches user's linked Tron address
    /// 3. Recipient is our hot wallet
    /// 4. Amount matches what user claims
    /// 5. Transaction hasn't been processed before
    pub async fn verify_deposit(
        &self,
        tx_hash: &str,
        expected_amount: u64,
        from_principal: Principal,
        user_tron_address: &str,
        transaction_state: &mut TransactionState,
    ) -> Result<TronTxInfo, CurrencyError> {
        // Check if transaction was already processed
        if transaction_state.transaction_exists(tx_hash) {
            return Err(CurrencyError::DuplicateTransaction);
        }

        // Get transaction info from Tron network
        let client = self.get_client();
        let tx_info = client.get_transaction_info(tx_hash).await?;

        // Verify transaction is confirmed
        if !tx_info.confirmed {
            return Err(CurrencyError::TransactionVerificationFailed(
                "Transaction not yet confirmed".to_string(),
            ));
        }

        // Verify sender is the user's linked Tron address
        if tx_info.from != user_tron_address {
            return Err(CurrencyError::TransactionVerificationFailed(format!(
                "Transaction sender {} does not match user's linked Tron address {}",
                tx_info.from, user_tron_address
            )));
        }

        // Verify recipient is our hot wallet
        if tx_info.to != self.hot_wallet_address {
            return Err(CurrencyError::TransactionVerificationFailed(format!(
                "Transaction recipient {} does not match hot wallet {}",
                tx_info.to, self.hot_wallet_address
            )));
        }

        // Verify amount
        let tx_amount: u64 = tx_info
            .value
            .parse()
            .map_err(|_| CurrencyError::InvalidAmount("Failed to parse amount".to_string()))?;

        if tx_amount != expected_amount {
            return Err(CurrencyError::TransactionVerificationFailed(format!(
                "Amount mismatch: expected {}, got {}",
                expected_amount, tx_amount
            )));
        }

        // Mark transaction as processed
        transaction_state.add_transaction(tx_hash.to_string());

        Ok(tx_info)
    }

    /// Request a withdrawal
    /// 
    /// This method creates and broadcasts a TRC-20 transfer transaction
    /// to send USDT from the hot wallet to the user's Tron address.
    /// 
    /// Note: This is a simplified version for MVP. In production:
    /// 1. Use threshold signatures for hot wallet key management
    /// 2. Implement transaction batching
    /// 3. Add withdrawal limits and rate limiting
    pub async fn request_withdrawal(
        &self,
        to_address: &str,
        _amount: u64,
    ) -> Result<String, CurrencyError> {
        // Validate recipient address
        crate::tron::utils::validate_tron_address(to_address)?;

        // For MVP, we'll return an error indicating this needs to be implemented
        // with proper key management
        Err(CurrencyError::OperationNotSupported(
            "Withdrawal implementation pending: requires threshold signature setup".to_string(),
        ))

        // TODO: Full implementation steps:
        // 1. Get hot wallet private key from threshold signature
        // 2. Create TRC-20 transfer transaction
        // 3. Sign transaction
        // 4. Broadcast to Tron network
        // 5. Return transaction hash
    }

    /// Get hot wallet balance
    /// 
    /// Used for solvency checks to ensure virtual balances are backed 1:1
    pub async fn get_hot_wallet_balance(&self) -> Result<u64, CurrencyError> {
        let client = self.get_client();
        client.get_account_balance(&self.hot_wallet_address).await
    }
}

impl CanisterWallet for TRC20USDTWallet {
    /// Deposit implementation for TRC-20 USDT
    /// 
    /// For TRC-20, deposit doesn't use allowances like ICRC-2.
    /// Instead, this method should only be called after verify_deposit() succeeds.
    /// The actual verification happens in verify_deposit(), and this method
    /// is a placeholder to satisfy the trait.
    async fn deposit(
        &self,
        _transaction_state: &mut TransactionState,
        _from_principal: Principal,
        _amount: u64,
    ) -> Result<(), CurrencyError> {
        // For TRC-20, deposit verification is done via verify_deposit()
        // This method exists to satisfy the CanisterWallet trait
        Ok(())
    }

    /// Validate allowance - Not applicable for TRC-20
    /// 
    /// TRC-20 doesn't use the ICRC-2 allowance pattern.
    /// Users send USDT directly to the hot wallet on Tron network,
    /// then provide the transaction hash for verification.
    async fn validate_allowance(
        &self,
        _from_principal: Principal,
        _amount: u64,
    ) -> Result<(), CurrencyError> {
        // Not applicable for TRC-20 - deposits are verified on-demand
        Ok(())
    }

    /// Withdraw from hot wallet to user's Tron address
    /// 
    /// Note: For MVP, this is a placeholder. Full implementation requires:
    /// - Threshold signature setup for hot wallet key
    /// - Transaction construction and signing
    /// - Broadcasting to Tron network
    async fn withdraw(
        &self,
        _wallet_principal_id: Principal,
        _amount: u64,
    ) -> Result<(), CurrencyError> {
        // For MVP, return error - needs threshold signature implementation
        Err(CurrencyError::OperationNotSupported(
            "TRC-20 withdrawal via withdraw() not supported. Use request_withdrawal() instead."
                .to_string(),
        ))
    }

    /// Get balance - Returns virtual balance from canister state
    /// 
    /// For TRC-20, user balances are virtual (stored in canister state).
    /// The actual USDT is held in the hot wallet on Tron network.
    /// 
    /// Note: This is a placeholder. In the actual game, balances are managed
    /// by the table_canister/user_canister, not the currency crate.
    async fn get_balance(&self, _principal_id: Principal) -> Result<u128, CurrencyError> {
        // Balance management is handled by the game canisters, not the currency crate
        // This method exists to satisfy the CanisterWallet trait
        Err(CurrencyError::OperationNotSupported(
            "Balance queries for TRC-20 should be done via game canister".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wallet() {
        let wallet = TRC20USDTWallet::new(
            "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs".to_string(),
            true,
            None,
        );
        assert_eq!(wallet.hot_wallet_address, "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs");
        assert!(wallet.is_testnet);
        assert!(wallet.api_key.is_none());
    }

    #[test]
    fn test_get_client() {
        let wallet = TRC20USDTWallet::new(
            "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs".to_string(),
            true,
            Some("test-key".to_string()),
        );
        let client = wallet.get_client();
        assert!(client.api_url.contains("shasta"));
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }
}

