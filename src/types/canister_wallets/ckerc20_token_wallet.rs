use crate::{
    cketh_minter_canister_interface::{
        EventPayload, GetEventsArg, GetEventsRet, LedgerError, MinterInfo, TxFinalizedStatus,
        WithdrawErc20Arg, WithdrawErc20Error, WithdrawErc20Ret, WithdrawalDetail,
        WithdrawalSearchParameter, WithdrawalStatus,
    },
    currency_error::CurrencyError,
    icrc1_types::{Account, Allowance, AllowanceArgs, TransferFromArg, TransferFromError},
    transfer::transfer_icrc1,
};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

use crate::{
    state::TransactionState,
    types::{
        canister_wallet::CanisterWallet,
        constants::{
            ETH_DECIMALS, ETH_LEDGER_CANISTER_ID, ETH_MINTER_CANISTER_ID, USDC_DECIMALS,
            USDC_LEDGER_CANISTER_ID, USDC_MINTER_CANISTER_ID, USDT_DECIMALS,
            USDT_LEDGER_CANISTER_ID, USDT_MINTER_CANISTER_ID,
        },
        currency::{CKTokenConfig, CKTokenSymbol},
    },
    utils::get_canister_state,
};

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub enum CKTokenWithdrawalStatus {
    Pending,
    TxCreated,
    TxSent {
        transaction_hash: String,
    },
    TxFinalized {
        transaction_hash: String,
        effective_fee: Option<u64>,
    },
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct CKERC20TokenWallet {
    pub config: CKTokenConfig,
}

impl CKERC20TokenWallet {
    pub fn new(symbol: CKTokenSymbol) -> Self {
        let config = match symbol {
            CKTokenSymbol::USDC => CKTokenConfig {
                minter_id: Principal::from_text(USDC_MINTER_CANISTER_ID).unwrap(),
                ledger_id: Principal::from_text(USDC_LEDGER_CANISTER_ID).unwrap(),
                token_symbol: crate::Currency::CKETHToken(symbol),
                decimals: USDC_DECIMALS,
                fee: 10_000,
            },
            CKTokenSymbol::USDT => CKTokenConfig {
                minter_id: Principal::from_text(USDT_MINTER_CANISTER_ID).unwrap(),
                ledger_id: Principal::from_text(USDT_LEDGER_CANISTER_ID).unwrap(),
                token_symbol: crate::Currency::CKETHToken(symbol),
                decimals: USDT_DECIMALS,
                fee: 10_000,
            },
            CKTokenSymbol::ETH => CKTokenConfig {
                minter_id: Principal::from_text(ETH_MINTER_CANISTER_ID).unwrap(),
                ledger_id: Principal::from_text(ETH_LEDGER_CANISTER_ID).unwrap(),
                token_symbol: crate::Currency::CKETHToken(symbol),
                decimals: ETH_DECIMALS,
                fee: 2_000_000_000_000,
            },
        };
        Self { config }
    }

    pub async fn get_deposit_address(&self) -> Result<Option<String>, CurrencyError> {
        // Call the minter's smart_contract_address function directly
        let (deposit_address,): (Option<String>,) =
            ic_cdk::call(self.config.minter_id, "smart_contract_address", ())
                .await
                .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        Ok(deposit_address)
    }

    /// Gets the special helper contract address that allows USDC deposits to be minted as ckUSDC
    /// directly to the table canister's principal.
    ///
    /// This differs from the regular smart contract address (get_deposit_address) because:
    /// 1. Users send USDC to this helper contract instead of the regular deposit contract
    /// 2. The user must include our table canister's principal (ic_cdk::api::id()) in their transaction data
    /// 3. The helper contract will mint ckUSDC directly to the table canister rather than to the user
    ///
    /// Returns:
    /// - The Ethereum address of the helper contract that supports specifying a receiving principal
    /// - Error if the helper contract address is not configured in the minter
    pub async fn get_deposit_address_for_principal(&self) -> Result<String, CurrencyError> {
        // Get the deposit with subaccount helper contract address
        let (minter_info,): (MinterInfo,) =
            ic_cdk::call(self.config.minter_id, "get_minter_info", ())
                .await
                .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        minter_info
            .deposit_with_subaccount_helper_contract_address
            .ok_or(CurrencyError::NoDepositAddress)
    }

    /// Monitors for a ckToken minting event from a specific Ethereum transaction
    /// Returns the block number where the ckTokens were minted once found.
    /// Should be used after sending tokens to the address recieved from `get_deposit_address_for_principal`
    pub async fn get_mint_block_number(
        &self,
        eth_transaction_hash: String,
    ) -> Result<u64, CurrencyError> {
        // We'll try a few times since there might be a delay
        for _ in 0..10 {
            let events_arg = GetEventsArg {
                // Look at last 100 events - might need adjustment
                start: 0,
                length: 100,
            };

            let (events,): (GetEventsRet,) =
                ic_cdk::call(self.config.minter_id, "get_events", (events_arg,))
                    .await
                    .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

            // Look for MintedCkErc20 event with matching transaction hash
            for event in events.events {
                if let EventPayload::MintedCkErc20 {
                    event_source,
                    mint_block_index,
                    ..
                } = event.payload
                {
                    if event_source.transaction_hash == eth_transaction_hash {
                        return mint_block_index.0.try_into().map_err(|_| {
                            CurrencyError::QueryError("Block number too large".to_string())
                        });
                    }
                }
            }

            // Wait a bit before trying again
        }

        Err(CurrencyError::TransactionNotFound)
    }

    pub async fn withdraw_icrc1_token_to_eth_address(
        &self,
        eth_address: String,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        // First create withdrawal args for the minter
        let withdraw_arg = WithdrawErc20Arg {
            amount: amount.into(),
            ckerc20_ledger_id: self.config.ledger_id,
            recipient: eth_address,      // This needs to be an ETH address
            from_cketh_subaccount: None, // For gas fees
            from_ckerc20_subaccount: None,
        };

        // Call minter to initiate withdrawal
        let (result,): (WithdrawErc20Ret,) =
            ic_cdk::call(self.config.minter_id, "withdraw_erc20", (withdraw_arg,))
                .await
                .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        match result {
            WithdrawErc20Ret::Ok(_) => Ok(()),
            WithdrawErc20Ret::Err(e) => {
                let error_msg = match e {
                    WithdrawErc20Error::TokenNotSupported { supported_tokens } => {
                        format!(
                            "Token not supported. Supported tokens: {:?}",
                            supported_tokens
                                .iter()
                                .map(|t| t.ckerc20_token_symbol.clone())
                                .collect::<Vec<_>>()
                        )
                    }
                    WithdrawErc20Error::TemporarilyUnavailable(msg) => {
                        format!("Service temporarily unavailable: {}", msg)
                    }
                    WithdrawErc20Error::CkErc20LedgerError {
                        error,
                        cketh_block_index: _,
                    } => match error {
                        LedgerError::TemporarilyUnavailable(msg) => {
                            format!("Ledger temporarily unavailable: {}", msg)
                        }
                        LedgerError::InsufficientAllowance {
                            token_symbol,
                            allowance,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "Insufficient allowance for {}: have {} need {}",
                                token_symbol, allowance, failed_burn_amount
                            )
                        }
                        LedgerError::AmountTooLow {
                            minimum_burn_amount,
                            token_symbol,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "Amount too low for {}: minimum {} got {}",
                                token_symbol, minimum_burn_amount, failed_burn_amount
                            )
                        }
                        LedgerError::InsufficientFunds {
                            balance,
                            token_symbol,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "Insufficient funds for {}: have {} need {}",
                                token_symbol, balance, failed_burn_amount
                            )
                        }
                    },
                    WithdrawErc20Error::CkEthLedgerError { error } => match error {
                        LedgerError::TemporarilyUnavailable(msg) => {
                            format!("ckETH ledger temporarily unavailable: {}", msg)
                        }
                        LedgerError::InsufficientAllowance {
                            token_symbol,
                            allowance,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "Insufficient {} allowance: have {} need {}",
                                token_symbol, allowance, failed_burn_amount
                            )
                        }
                        LedgerError::AmountTooLow {
                            minimum_burn_amount,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "ckETH amount too low: minimum {} got {}",
                                minimum_burn_amount, failed_burn_amount
                            )
                        }
                        LedgerError::InsufficientFunds {
                            balance,
                            failed_burn_amount,
                            ..
                        } => {
                            format!(
                                "Insufficient ckETH funds: have {} need {}",
                                balance, failed_burn_amount
                            )
                        }
                    },
                    WithdrawErc20Error::RecipientAddressBlocked { address } => {
                        format!("Recipient address blocked: {}", address)
                    }
                };
                Err(CurrencyError::WithdrawalFailed(error_msg))
            }
        }
    }

    /// Check the status of a withdrawal after it's been initiated
    pub async fn check_withdrawal_status(
        &self,
        withdrawal_id: u64,
    ) -> Result<CKTokenWithdrawalStatus, CurrencyError> {
        let (status,): (Vec<WithdrawalDetail>,) = ic_cdk::call(
            self.config.minter_id,
            "withdrawal_status",
            (WithdrawalSearchParameter::ByWithdrawalId(withdrawal_id),),
        )
        .await
        .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        let detail = status.first().ok_or(CurrencyError::WithdrawalFailed(
            "Withdrawal not found".to_string(),
        ))?;

        Ok(match &detail.status {
            WithdrawalStatus::Pending => CKTokenWithdrawalStatus::Pending,
            WithdrawalStatus::TxCreated => CKTokenWithdrawalStatus::TxCreated,
            WithdrawalStatus::TxSent(tx) => CKTokenWithdrawalStatus::TxSent {
                transaction_hash: tx.transaction_hash.clone(),
            },
            WithdrawalStatus::TxFinalized(status) => match status {
                TxFinalizedStatus::Success {
                    transaction_hash,
                    effective_transaction_fee,
                } => CKTokenWithdrawalStatus::TxFinalized {
                    transaction_hash: transaction_hash.clone(),
                    effective_fee: effective_transaction_fee
                        .as_ref()
                        .map(|f| f.clone().0.try_into().unwrap_or(0)),
                },
                TxFinalizedStatus::Reimbursed {
                    transaction_hash, ..
                } => CKTokenWithdrawalStatus::Failed(format!(
                    "Transaction failed and was reimbursed. Tx hash: {}",
                    transaction_hash
                )),
                TxFinalizedStatus::PendingReimbursement(tx) => {
                    CKTokenWithdrawalStatus::Failed(format!(
                        "Transaction failed, reimbursement pending. Tx hash: {}",
                        tx.transaction_hash
                    ))
                }
            },
        })
    }

    // Helper functions for implementations
    pub async fn check_allowance(
        &self,
        ledger: Principal,
        account: Account,
        spender: Account,
    ) -> Result<Allowance, CurrencyError> {
        let args = AllowanceArgs { account, spender };

        let (allowance,): (Allowance,) = ic_cdk::call(ledger, "icrc2_allowance", (args,))
            .await
            .map_err(|e| CurrencyError::AllowanceCheckFailed(format!("{:?}", e)))?;

        Ok(allowance)
    }

    pub async fn transfer_from(
        &self,
        ledger: Principal,
        from: Account,
        to: Account,
        amount: u128,
    ) -> Result<u128, CurrencyError> {
        let args = TransferFromArg {
            spender_subaccount: None,
            from,
            to,
            amount,
            fee: Some(ic_ledger_types::DEFAULT_FEE.e8s().into()),
            memo: None,
            created_at_time: Some(ic_cdk::api::time()),
        };

        let (result,): (Result<u128, TransferFromError>,) =
            ic_cdk::call(ledger, "icrc2_transfer_from", (args,))
                .await
                .map_err(|e| CurrencyError::TransferFromFailed(format!("{:?}", e)))?;

        match result {
            Ok(block_index) => Ok(block_index),
            Err(e) => match e {
                TransferFromError::InsufficientAllowance { .. } => {
                    Err(CurrencyError::InsufficientAllowance)
                }
                _ => Err(CurrencyError::TransferFromFailed(format!("{:?}", e))),
            },
        }
    }

}

impl CanisterWallet for CKERC20TokenWallet {
    async fn deposit(
        &self,
        transaction_state: &mut TransactionState,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        let canister_state = get_canister_state();

        // Check allowance
        let from_account = Account {
            owner: from_principal,
            subaccount: None,
        };
        let spender_account = Account {
            owner: canister_state.owner,
            subaccount: None,
        };

        let allowance =
            self.check_allowance(self.config.ledger_id, from_account, spender_account).await?;

        if allowance.allowance < amount as u128 {
            return Err(CurrencyError::InsufficientAllowance);
        }

        let from_account = Account {
            owner: from_principal,
            subaccount: None,
        };
        let spender_account = Account {
            owner: canister_state.owner,
            subaccount: None,
        };

        // Transfer tokens using allowance
        let block_index = self.transfer_from(
            self.config.ledger_id,
            from_account,
            spender_account,
            amount.into(),
        )
        .await?;

        // Add transaction to state
        let tx_id = format!(
            "CKERC20-DEPOSIT-{}-{}-{}",
            block_index,
            from_principal,
            ic_cdk::api::time()
        );
        transaction_state.add_transaction(tx_id);

        Ok(())
    }

    async fn validate_allowance(
        &self, 
        from_principal: Principal, 
        amount: u64
    ) -> Result<(), CurrencyError> {
        let canister_state = get_canister_state();

        let from_account = Account {
            owner: from_principal,
            subaccount: None,
        };
        let spender_account = Account {
            owner: canister_state.owner,
            subaccount: None,
        };
        // Check the allowance to make sure it's sufficient
        let allowance = self.check_allowance(self.config.ledger_id, from_account, spender_account).await?;
        
        if allowance.allowance < amount as u128 {
            return Err(CurrencyError::InsufficientAllowance);
        }
        
        // Check if the allowance is expired
        if let Some(expires_at) = allowance.expires_at {
            if expires_at < ic_cdk::api::time() {
                return Err(CurrencyError::InsufficientAllowance);
            }
        }
        
        Ok(())
    }

    async fn withdraw(
        &self,
        wallet_principal_id: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        let default_subaccount = {
            let canister_state = get_canister_state();
            canister_state.default_subaccount.0
        };

        transfer_icrc1(
            self.config.ledger_id,
            amount,
            default_subaccount.to_vec(),
            wallet_principal_id,
            Some(self.config.fee)
        )
        .await?;
        Ok(())
    }

    async fn get_balance(&self, principal_id: Principal) -> Result<u128, CurrencyError> {
        let account = Account {
            owner: principal_id,
            subaccount: None,
        };
        
        let (balance,): (candid::Nat,) = ic_cdk::call(
            self.config.ledger_id,
            "icrc1_balance_of", 
            (account,)
        )
        .await
        .map_err(|e| CurrencyError::LedgerError(
            format!("Failed to query {:?} balance: {:?}", self.config.token_symbol, e)
        ))?;
        
        // Convert the candid::Nat to u128
        let balance_str = balance.0.to_string();
        let balance_u128 = match balance_str.parse::<u128>() {
            Ok(val) => val,
            Err(_) => {
                return Err(CurrencyError::LedgerError(
                    format!("Failed to convert balance '{}' to u128", balance_str)
                ));
            }
        };
        Ok(balance_u128)
    }
}
