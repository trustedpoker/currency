use crate::{
    currency_error::CurrencyError,
    icrc1_types::{Account, Allowance, AllowanceArgs, TransferFromArg, TransferFromError},
    state::TransactionState,
    transfer::transfer_icrc1,
    types::canister_wallet::CanisterWallet,
    utils::get_canister_state,
};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use num_traits::cast::ToPrimitive;

/// Standard record returned by ICRC-1 supported_standards method
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}

/// Structure to hold metadata about an ICRC-1 token
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct ICRC1TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub fee: u128,
    pub supported_standards: Vec<StandardRecord>,
}

/// Generic wallet for any ICRC-1 token
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct GenericICRC1TokenWallet {
    pub ledger_id: Principal,
    pub metadata: ICRC1TokenMetadata,
}

impl GenericICRC1TokenWallet {
    /// Create a new wallet by querying token metadata
    pub async fn new(ledger_id: Principal) -> Result<Self, CurrencyError> {
        // Query token metadata
        let metadata = Self::query_token_metadata(ledger_id).await?;
        
        Ok(Self {
            ledger_id,
            metadata,
        })
    }
    
    /// Query token metadata from the ledger canister
    pub async fn query_token_metadata(ledger_id: Principal) -> Result<ICRC1TokenMetadata, CurrencyError> {
        // Query name
        let (name,): (String,) = ic_cdk::call(ledger_id, "icrc1_name", ())
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("Failed to query token name: {:?}", e)))?;
        
        // Query symbol
        let (symbol,): (String,) = ic_cdk::call(ledger_id, "icrc1_symbol", ())
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("Failed to query token symbol: {:?}", e)))?;
        
        // Query decimals
        let (decimals,): (u8,) = ic_cdk::call(ledger_id, "icrc1_decimals", ())
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("Failed to query token decimals: {:?}", e)))?;
        
        // Query fee
        let (fee,): (candid::Nat,) = ic_cdk::call(ledger_id, "icrc1_fee", ())
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("Failed to query token fee: {:?}", e)))?;
        
        // Query supported standards
        let (standards,): (Vec<StandardRecord>,) = ic_cdk::call(ledger_id, "icrc1_supported_standards", ())
            .await
            .map_err(|e| CurrencyError::CanisterCallFailed(format!("Failed to query supported standards: {:?}", e)))?;
        
        Ok(ICRC1TokenMetadata {
            name,
            symbol,
            decimals,
            fee: fee.0.to_u128().unwrap_or(10000), // Default fee if conversion fails
            supported_standards: standards,
        })
    }
    
    /// Check if the token supports ICRC-2 standard (which includes approve and transfer_from)
    pub fn supports_icrc2(&self) -> bool {
        self.metadata.supported_standards.iter().any(|std| std.name == "ICRC-2")
    }
    
    /// Check the allowance granted by a user to this canister
    pub async fn check_allowance(
        &self,
        from_principal: Principal,
    ) -> Result<Allowance, CurrencyError> {
        if !self.supports_icrc2() {
            return Err(CurrencyError::OperationNotSupported(
                "Token does not support ICRC-2 (allowance) operations".to_string(),
            ));
        }
        
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
            ic_cdk::call(self.ledger_id, "icrc2_allowance", (args,))
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
        if !self.supports_icrc2() {
            return Err(CurrencyError::OperationNotSupported(
                "Token does not support ICRC-2 (transfer_from) operations".to_string(),
            ));
        }
        
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
            fee: Some(self.metadata.fee),
            memo: None,
            created_at_time: Some(ic_cdk::api::time()),
        };

        let (result,): (Result<u128, TransferFromError>,) =
            ic_cdk::call(self.ledger_id, "icrc2_transfer_from", (args,))
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

impl CanisterWallet for GenericICRC1TokenWallet {
    async fn deposit(
        &self,
        transaction_state: &mut TransactionState,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        // First check if ICRC-2 is supported
        if !self.supports_icrc2() {
            return Err(CurrencyError::OperationNotSupported(
                format!("Token {} does not support ICRC-2 (allowance) operations", self.metadata.symbol)
            ));
        }
        
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

        // Transfer the tokens using the allowance
        let block_index = self.transfer_from(from_principal, amount).await?;

        // Record the transaction
        let tx_id = format!(
            "{}-DEPOSIT-{}-{}-{}",
            self.metadata.symbol,
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
        // Check if ICRC-2 is supported
        if !self.supports_icrc2() {
            return Err(CurrencyError::OperationNotSupported(
                format!("Token {} does not support ICRC-2 (allowance) operations", self.metadata.symbol)
            ));
        }
        
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
            canister_state.default_subaccount.0.to_vec()
        };

        transfer_icrc1(
            self.ledger_id,
            amount,
            default_subaccount,
            wallet_principal_id,
            Some(self.metadata.fee),
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
            self.ledger_id,
            "icrc1_balance_of", 
            (account,)
        )
        .await
        .map_err(|e| CurrencyError::LedgerError(
            format!("Failed to query {} balance: {:?}", self.metadata.symbol, e)
        ))?;
        
        // Convert candid::Nat to u128
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
