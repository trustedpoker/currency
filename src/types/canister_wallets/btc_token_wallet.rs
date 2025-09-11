use crate::{
    ckbtc_ledger_canister_interface::{
        Account, Allowance, AllowanceArgs, TransferFromArgs, TransferFromError,
    },
    ckbtc_minter_canister_interface::{UpdateBalanceError, UpdateBalanceRet},
    currency_error::CurrencyError,
    transfer::transfer_icrc1,
};
use crate::{
    state::TransactionState,
    types::{
        canister_wallet::CanisterWallet,
        constants::{BTC_DECIMALS, BTC_LEDGER_CANISTER_ID, BTC_MINTER_CANISTER_ID},
        currency::CKTokenConfig
    },
    utils::get_canister_state,
};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

// Import the generated interfaces
use crate::ckbtc_minter_canister_interface::{GetBtcAddressArg, UpdateBalanceArg, UtxoStatus};

#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct CKBTCTokenWallet {
    pub config: CKTokenConfig,
}

impl Default for CKBTCTokenWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl CKBTCTokenWallet {
    pub fn new() -> Self {
        let config = CKTokenConfig {
            minter_id: Principal::from_text(BTC_MINTER_CANISTER_ID).unwrap(),
            ledger_id: Principal::from_text(BTC_LEDGER_CANISTER_ID).unwrap(),
            token_symbol: crate::Currency::BTC,
            decimals: BTC_DECIMALS,
            fee: 10,
        };
        Self { config }
    }

    /// Gets the Bitcoin deposit address for this canister
    pub async fn get_deposit_address(&self) -> Result<String, CurrencyError> {
        let arg = GetBtcAddressArg {
            owner: Some(ic_cdk::api::id()),
            subaccount: None,
        };

        let (address,): (String,) = ic_cdk::call(self.config.minter_id, "get_btc_address", (arg,))
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        Ok(address)
    }

    /// Check the allowance granted by a user to this canister
    pub async fn check_allowance(
        &self,
        from_principal: Principal,
    ) -> Result<Allowance, CurrencyError> {
        let args = AllowanceArgs {
            account: Account {
                owner: from_principal,
                subaccount: None,
            },
            spender: Account {
                owner: ic_cdk::api::id(),
                subaccount: None,
            },
        };

        let (allowance,): (Allowance,) =
            ic_cdk::call(self.config.ledger_id, "icrc2_allowance", (args,))
                .await
                .map_err(|e| CurrencyError::AllowanceCheckFailed(format!("{:?}", e)))?;

        Ok(allowance)
    }

    /// Transfer tokens from a user's account to this canister using ICRC-2 transfer_from
    pub async fn transfer_from(
        &self,
        from_principal: Principal,
        amount: u64,
    ) -> Result<u128, CurrencyError> {
        let canister_account = Account {
            owner: ic_cdk::api::id(),
            subaccount: None,
        };

        let from_account = Account {
            owner: from_principal,
            subaccount: None,
        };

        let args = TransferFromArgs {
            spender_subaccount: None,
            from: from_account,
            to: canister_account,
            amount: amount.into(),
            fee: Some(self.config.fee.into()),
            memo: None,
            created_at_time: Some(ic_cdk::api::time()),
        };

        let (result,): (Result<u128, TransferFromError>,) =
            ic_cdk::call(self.config.ledger_id, "icrc2_transfer_from", (args,))
                .await
                .map_err(|e| CurrencyError::TransferFromFailed(format!("{:?}", e)))?;

        match result {
            Ok(block_index) => Ok(block_index),
            Err(e) => match e {
                TransferFromError::InsufficientAllowance { .. } => {
                    Err(CurrencyError::InsufficientAllowance)
                }
                _ => match e {
                    TransferFromError::BadFee { expected_fee } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Bad fee: Expected {}, got {}",
                            expected_fee,
                            ic_ledger_types::DEFAULT_FEE.e8s()
                        )))
                    }
                    TransferFromError::BadBurn { min_burn_amount } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Bad burn: Minimum burn amount is {}",
                            min_burn_amount
                        )))
                    }
                    TransferFromError::InsufficientFunds { balance } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Insufficient funds: Balance is {}",
                            balance
                        )))
                    }
                    TransferFromError::TooOld => Err(CurrencyError::TransferFromFailed(
                        "Transaction is too old".to_string(),
                    )),
                    TransferFromError::CreatedInFuture { ledger_time } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Transaction created in the future: {}",
                            ledger_time
                        )))
                    }
                    TransferFromError::GenericError {
                        message,
                        error_code,
                    } => Err(CurrencyError::TransferFromFailed(format!(
                        "Error code {}: {}",
                        error_code, message
                    ))),
                    TransferFromError::Duplicate { duplicate_of } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Duplicate transaction: {}",
                            duplicate_of
                        )))
                    }
                    TransferFromError::TemporarilyUnavailable => {
                        Err(CurrencyError::TransferFromFailed(
                            "Service temporarily unavailable".to_string(),
                        ))
                    }
                    TransferFromError::InsufficientAllowance { allowance } => {
                        Err(CurrencyError::TransferFromFailed(format!(
                            "Insufficient allowance: {}",
                            allowance
                        )))
                    }
                },
            },
        }
    }

    /// Updates the balance by checking for new UTXOs
    async fn update_balance(&self) -> Result<Vec<UtxoStatus>, CurrencyError> {
        let args = UpdateBalanceArg {
            owner: Some(ic_cdk::api::id()),
            subaccount: None,
        };

        let (result,): (UpdateBalanceRet,) =
            ic_cdk::call(self.config.minter_id, "update_balance", (args,))
                .await
                .map_err(|e| CurrencyError::CanisterCallFailed(format!("{:?}", e)))?;

        match result {
            UpdateBalanceRet::Ok(statuses) => Ok(statuses),
            UpdateBalanceRet::Err(e) => {
                let error_msg = match e {
                    UpdateBalanceError::GenericError {
                        error_message,
                        error_code,
                    } => format!("Error code {}: {}", error_code, error_message),
                    UpdateBalanceError::TemporarilyUnavailable(msg) => {
                        format!("Service temporarily unavailable: {}", msg)
                    }
                    UpdateBalanceError::AlreadyProcessing => {
                        "Already processing balance update".to_string()
                    }
                    UpdateBalanceError::NoNewUtxos {
                        required_confirmations,
                        current_confirmations,
                        ..
                    } => format!(
                        "No new UTXOs available. Required confirmations: {}, Current: {}",
                        required_confirmations,
                        current_confirmations.unwrap_or(0)
                    ),
                };
                Err(CurrencyError::LedgerError(error_msg))
            }
        }
    }
}

impl CanisterWallet for CKBTCTokenWallet {
    async fn deposit(
        &self,
        transaction_state: &mut TransactionState,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        // First check the allowance to make sure it's sufficient
        let allowance = self.check_allowance(from_principal).await?;

        if allowance.allowance < amount as u128 {
            return Err(CurrencyError::InsufficientAllowance);
        }

        // Check if the allowance is expired
        if let Some(expires_at) = allowance.expires_at {
            if expires_at < ic_cdk::api::time() {
                return Err(CurrencyError::InsufficientAllowance);
            }
        }

        // Transfer the tokens using the allowance
        let block_index = self.transfer_from(from_principal, amount).await?;

        // Record the transaction
        let tx_id = format!(
            "CKBTC-DEPOSIT-{}-{}-{}",
            block_index,
            from_principal,
            ic_cdk::api::time()
        );

        transaction_state.add_transaction(tx_id);

        // Update the balance to make sure we have the latest state
        // This isn't strictly necessary but helps keep state consistent
        let _ = self.update_balance().await;

        Ok(())
    }

    async fn validate_allowance(
        &self, 
        from_principal: Principal, 
        amount: u64
    ) -> Result<(), CurrencyError> {
        // Check the allowance to make sure it's sufficient
        let allowance = self.check_allowance(from_principal).await?;
        
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
        let default_subaccount = get_canister_state().default_subaccount.0;

        transfer_icrc1(
            self.config.ledger_id,
            amount,
            default_subaccount.to_vec(),
            wallet_principal_id,
            Some(self.config.fee),
        )
        .await
        .map_err(|e| CurrencyError::WithdrawalFailed(e.to_string()))?;
        Ok(())
    }

    async fn get_balance(&self, principal_id: Principal) -> Result<u128, CurrencyError> {
        let account = crate::ckbtc_ledger_canister_interface::Account {
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
            format!("Failed to query ckBTC balance: {:?}", e)
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
