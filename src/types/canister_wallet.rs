use candid::Principal;

use crate::{currency_error::CurrencyError, state::TransactionState};

use super::canister_wallets::{
    ckerc20_token_wallet::CKERC20TokenWallet, icp_canister_wallet::ICPCanisterWallet,
};

pub enum Wallet {
    ICP(ICPCanisterWallet),
    ERC20(CKERC20TokenWallet),
}

pub(crate) trait CanisterWallet: Send + Sync {
    /** Deposit to the canisters wallet */
    async fn deposit(
        &self,
        transaction_state: &mut TransactionState,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError>;

    /** Validate the allowance granted by a user to this canister */
    async fn validate_allowance(
        &self,
        from_principal: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError>;

    /** Withdraw from the canisters wallet to a given address */
    async fn withdraw(
        &self,
        wallet_principal_id: Principal,
        amount: u64,
    ) -> Result<(), CurrencyError>;

    /** Get the balance */
    async fn get_balance(&self, principal_id: Principal) -> Result<u128, CurrencyError>;
}
