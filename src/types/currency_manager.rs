use std::borrow::Cow;

use candid::{CandidType, Decode, Encode, Principal};
use ic_ledger_types::DEFAULT_FEE;
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};

use crate::{
    currency_error::CurrencyError,
    state::TransactionState,
    types::{
        canister_wallet::CanisterWallet,
        canister_wallets::{
            ckerc20_token_wallet::CKERC20TokenWallet, icp_canister_wallet::ICPCanisterWallet,
        },
    },
    Currency,
};

use super::canister_wallets::{btc_token_wallet::CKBTCTokenWallet, icrc1_token_wallet::GenericICRC1TokenWallet};

const MAX_VALUE_SIZE_CURRENCY_MANAGER: u32 = 100000; // Adjust based on your needs

impl Storable for CurrencyManager {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap_or_else(|e| {
            ic_cdk::println!("CurrencyManager serialization error: {:?}", e);
            vec![]
        }))
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap_or_else(|e| {
            ic_cdk::println!("CurrencyManager deserialization error: {:?}", e);
            // Return empty CurrencyManager as fallback
            CurrencyManager {
                icp: None,
                ckerc20_tokens: vec![],
                btc: None,
                generic_icrc1_tokens: vec![],
            }
        })
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_VALUE_SIZE_CURRENCY_MANAGER,
        is_fixed_size: false,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct CurrencyManager {
    pub icp: Option<ICPCanisterWallet>,
    pub ckerc20_tokens: Vec<CKERC20TokenWallet>,
    pub btc: Option<CKBTCTokenWallet>,
    pub generic_icrc1_tokens: Vec<GenericICRC1TokenWallet>,
}

impl CurrencyManager {
    pub fn new() -> Self {
        Self {
            icp: Some(ICPCanisterWallet),
            ckerc20_tokens: Vec::new(),
            btc: Some(CKBTCTokenWallet::new()),
            generic_icrc1_tokens: Vec::new(),
        }
    }

    pub async fn add_currency(&mut self, currency: Currency) -> Result<(), CurrencyError> {
        match currency {
            Currency::ICP => {
                if self.icp.is_none() {
                    self.icp = Some(ICPCanisterWallet);
                }
            }
            Currency::CKETHToken(token) => {
                // Only add if this specific token doesn't exist yet
                if !self
                    .ckerc20_tokens
                    .iter()
                    .any(|w: &CKERC20TokenWallet| w.config.token_symbol == Currency::CKETHToken(token))
                {
                    self.ckerc20_tokens.push(CKERC20TokenWallet::new(token));
                }
            }
            Currency::BTC => {
                if self.btc.is_none() {
                    self.btc = Some(CKBTCTokenWallet::new());
                }
            }
            Currency::GenericICRC1(token) => {
                // Only add if this specific token doesn't exist yet
                if !self
                    .generic_icrc1_tokens
                    .iter()
                    .any(|w: &GenericICRC1TokenWallet| w.metadata.symbol == token.symbol_to_string())
                {
                    self.generic_icrc1_tokens.push(GenericICRC1TokenWallet::new(token.ledger_id).await?);
                }
            }
        }
        Ok(())
    }

    pub fn remove_currency(&mut self, currency: &Currency) {
        match currency {
            Currency::ICP => {
                self.icp = None;
            }
            Currency::CKETHToken(token) => {
                self.ckerc20_tokens
                    .retain(|w| w.config.token_symbol != Currency::CKETHToken(*token));
            }
            Currency::BTC => {
                self.btc = None;
            }
            Currency::GenericICRC1(token) => {
                self.generic_icrc1_tokens
                    .retain(|w| w.metadata.symbol != token.symbol_to_string());
            }
        }
    }

    pub async fn deposit(
        &self,
        transaction_state: &mut TransactionState,
        currency: &Currency,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(icp) => icp.deposit(transaction_state, from_principal, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet
                    .deposit(transaction_state, from_principal, amount)
                    .await
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => {
                    wallet
                        .deposit(transaction_state, from_principal, amount)
                        .await
                }
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet
                    .deposit(transaction_state, from_principal, amount)
                    .await
            }
        }
    }

    pub async fn validate_allowance(
        &self,
        currency: &Currency,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(wallet) => wallet.validate_allowance(from_principal, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.validate_allowance(from_principal, amount).await
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => wallet.validate_allowance(from_principal, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.validate_allowance(from_principal, amount).await
            }
        }
    }

    pub async fn withdraw(
        &self,
        currency: &Currency,
        wallet_principal_id: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(wallet) => wallet.withdraw(wallet_principal_id, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.withdraw(wallet_principal_id, amount).await
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => wallet.withdraw(wallet_principal_id, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.withdraw(wallet_principal_id, amount).await
            }
        }
    }

    pub async fn withdraw_rake(
        &self,
        currency: &Currency,
        wallet_principal_id: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(wallet) => wallet.withdraw(wallet_principal_id, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.withdraw(wallet_principal_id, amount).await
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => wallet.withdraw(wallet_principal_id, amount).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.withdraw(wallet_principal_id, amount).await
            }
        }
    }

    pub async fn get_balance(&self, currency: &Currency, principal_id: Principal) -> Result<u128, CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(wallet) => wallet.get_balance(principal_id).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.get_balance(principal_id).await
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => wallet.get_balance(principal_id).await,
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                wallet.get_balance(principal_id).await
            }
        }
    }

    pub async fn get_fee(&self, currency: &Currency) -> Result<u128, CurrencyError> {
        match currency {
            Currency::ICP => match &self.icp {
                Some(_) => Ok(DEFAULT_FEE.e8s() as u128),
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::CKETHToken(token) => {
                let wallet = self
                    .ckerc20_tokens
                    .iter()
                    .find(|w| w.config.token_symbol == Currency::CKETHToken(*token))
                    .ok_or(CurrencyError::WalletNotSet)?;
                Ok(wallet.config.fee)
            }
            Currency::BTC => match &self.btc {
                Some(wallet) => Ok(wallet.config.fee),
                None => Err(CurrencyError::WalletNotSet),
            },
            Currency::GenericICRC1(token) => {
                let wallet = self
                    .generic_icrc1_tokens
                    .iter()
                    .find(|w| w.metadata.symbol == token.symbol_to_string())
                    .ok_or(CurrencyError::WalletNotSet)?;
                Ok(wallet.metadata.fee)
            }
        }
    }
}
