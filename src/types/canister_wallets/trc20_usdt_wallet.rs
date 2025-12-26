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
/// 
/// **Architecture**: Each user gets a unique Tron address derived from
/// their IC Principal using threshold ECDSA. This provides:
/// - Better UX: Users send to their own address (no tx hash copy-paste)
/// - Auto-detection: Backend checks each user's address for new deposits
/// - Security: Private keys managed by IC threshold signatures
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct TRC20USDTWallet {
    /// Whether to use testnet (Shasta) or mainnet
    pub is_testnet: bool,
    /// Whether to use production ECDSA key
    pub is_production: bool,
    /// Optional TronGrid API key for higher rate limits
    pub api_key: Option<String>,
}

impl TRC20USDTWallet {
    /// Create a new TRC20USDTWallet
    ///
    /// # Parameters
    /// * `is_testnet` - Whether to use Shasta testnet or mainnet
    /// * `is_production` - Whether to use production ECDSA key
    /// * `api_key` - Optional TronGrid API key for higher rate limits
    pub fn new(is_testnet: bool, is_production: bool, api_key: Option<String>) -> Self {
        Self {
            is_testnet,
            is_production,
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

        // NEW WORKFLOW: In the updated system, users send USDT to their own generated address
        // So we verify that the recipient (to) is the user's address
        // The sender (from) can be any external wallet the user owns
        
        // Verify recipient is the user's generated Tron address
        if tx_info.to != user_tron_address {
            return Err(CurrencyError::TransactionVerificationFailed(format!(
                "Transaction recipient {} does not match user's Tron address {}. Please send to your own address.",
                tx_info.to, user_tron_address
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
    /// Creates and signs a TRC-20 transfer transaction using IC threshold ECDSA,
    /// then broadcasts it to the Tron network.
    /// 
    /// # Parameters
    /// * `user_principal` - The user's IC Principal (for signing)
    /// * `to_address` - The recipient Tron address
    /// * `amount` - Amount to withdraw (in smallest unit, 6 decimals)
    ///
    /// # Returns
    /// * Transaction hash of the broadcasted withdrawal
    ///
    /// Note: For MVP, this returns an error. Full implementation requires:
    /// 1. Transaction construction via TronGrid API
    /// 2. Signing with threshold ECDSA
    /// 3. Broadcasting to Tron network
    pub async fn request_withdrawal(
        &self,
        user_principal: Principal,
        to_address: &str,
        _amount: u64,
    ) -> Result<String, CurrencyError> {
        // Validate recipient address
        crate::tron::utils::validate_tron_address(to_address)?;

        // For MVP, return error - full implementation needs:
        // 1. Create unsigned transaction via TronGrid
        // 2. Sign with threshold ECDSA
        // 3. Broadcast signed transaction
        let _ = user_principal; // Will be used for signing
        
        Err(CurrencyError::OperationNotSupported(
            "Withdrawal implementation pending: transaction construction and broadcasting".to_string(),
        ))

        // TODO: Full implementation:
        // let unsigned_tx = create_trc20_transfer_tx(from_address, to_address, amount).await?;
        // let signature = sign_with_threshold_ecdsa(user_principal, &unsigned_tx.hash(), self.is_production).await?;
        // let signed_tx = unsigned_tx.add_signature(signature);
        // let tx_hash = self.get_client().broadcast_transaction(&signed_tx).await?;
        // Ok(tx_hash)
    }

    /// Get total balance across all user addresses (for solvency check)
    /// 
    /// Note: This would need to query all user addresses, which is expensive.
    /// Better approach: Track deposits/withdrawals and maintain running balance.
    pub async fn get_total_balance(&self) -> Result<u64, CurrencyError> {
        // For MVP, return placeholder
        // In production: sum all user address balances or track deposits - withdrawals
        Err(CurrencyError::OperationNotSupported(
            "Total balance check not yet implemented. Use deposit/withdrawal tracking.".to_string(),
        ))
    }

    /// Get recent TRC-20 transactions for a user's Tron address
    /// 
    /// This method fetches incoming TRC-20 USDT transactions to the user's address.
    /// Used for auto-detecting deposits without requiring user to input tx hash.
    /// 
    /// # Parameters
    /// * `user_tron_address` - The user's unique Tron address
    /// * `limit` - Maximum number of transactions to fetch (default: 20)
    /// 
    /// # Returns
    /// * Vector of TronTxInfo for incoming USDT transactions
    pub async fn get_address_transactions(
        &self,
        user_tron_address: &str,
        limit: Option<u32>,
    ) -> Result<Vec<TronTxInfo>, CurrencyError> {
        let client = self.get_client();
        let transactions = client
            .get_trc20_transactions(user_tron_address, limit.unwrap_or(20))
            .await?;
        
        Ok(transactions)
    }

    /// Get TRC-20 USDT balance for an address
    /// 
    /// Queries the current TRC-20 USDT balance of a Tron address.
    /// 
    /// # Parameters
    /// * `address` - The Tron address to check
    /// 
    /// # Returns
    /// * Balance in smallest unit (6 decimals)
    pub async fn get_address_balance(&self, address: &str) -> Result<u64, CurrencyError> {
        let client = self.get_client();
        client.get_trc20_balance(address).await
    }

    /// Generate a unique Tron address for a user
    /// 
    /// Uses IC threshold ECDSA to derive a deterministic address from user's Principal.
    /// Each user gets a unique address that only the IC canister can sign for.
    /// 
    /// # Parameters
    /// * `user_principal` - The user's IC Principal
    /// 
    /// # Returns
    /// * `(tron_address, public_key)` - The derived address and public key
    pub async fn generate_user_address(
        &self,
        user_principal: Principal,
    ) -> Result<(String, Vec<u8>), CurrencyError> {
        crate::tron::ecdsa::derive_tron_address_for_user(user_principal, self.is_production).await
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
        let wallet = TRC20USDTWallet::new(true, false, None);
        assert!(wallet.is_testnet);
        assert!(!wallet.is_production);
        assert!(wallet.api_key.is_none());
    }

    #[test]
    fn test_get_client() {
        let wallet = TRC20USDTWallet::new(true, false, Some("test-key".to_string()));
        let client = wallet.get_client();
        assert!(client.api_url.contains("shasta"));
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }
}

