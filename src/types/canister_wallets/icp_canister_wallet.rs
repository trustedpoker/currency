use crate::{
    currency_error::CurrencyError,
    icrc1_types::{Account, Allowance, AllowanceArgs, TransferFromArg, TransferFromError},
    transfer::transfer_icp,
};
use candid::{CandidType, Principal};
use ic_ledger_types::MAINNET_LEDGER_CANISTER_ID;
use serde::{Deserialize, Serialize};

use crate::{
    state::TransactionState, types::canister_wallet::CanisterWallet, utils::get_canister_state,
};

#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct ICPCanisterWallet;

impl ICPCanisterWallet {
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
            ic_cdk::call(MAINNET_LEDGER_CANISTER_ID, "icrc2_allowance", (args,))
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

        let args = TransferFromArg {
            spender_subaccount: None,
            from: from_account,
            to: canister_account,
            amount: amount.into(),
            fee: Some(ic_ledger_types::DEFAULT_FEE.e8s().into()),
            memo: None,
            created_at_time: Some(ic_cdk::api::time()),
        };

        let (result,): (Result<u128, TransferFromError>,) =
            ic_cdk::call(MAINNET_LEDGER_CANISTER_ID, "icrc2_transfer_from", (args,))
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

impl CanisterWallet for ICPCanisterWallet {
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
            "ICP-DEPOSIT-{}-{}-{}",
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
        let default_subaccount = {
            let canister_state = get_canister_state();
            canister_state.default_subaccount
        };

        transfer_icp(amount, default_subaccount, wallet_principal_id).await?;
        Ok(())
    }

    async fn get_balance(&self, principal_id: Principal) -> Result<u128, CurrencyError> {
        let account = Account {
            owner: principal_id,
            subaccount: None,
        };
        
        let (balance,): (candid::Nat,) = ic_cdk::call(
            MAINNET_LEDGER_CANISTER_ID,
            "icrc1_balance_of", 
            (account,)
        )
        .await
        .map_err(|e| CurrencyError::LedgerError(format!("Failed to query ICP balance: {:?}", e)))?;
        
        // Convert candid::Nat to u64, ensuring it doesn't overflow
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
