use candid::Principal;
use ic_ledger_types::{AccountIdentifier, Subaccount};

/** This should be handled in a separate library alltogether */
pub struct CanisterState {
    pub owner: Principal,
    pub default_subaccount: Subaccount,
    pub account_identifier: AccountIdentifier,
}

pub fn create_default_subaccount() -> Subaccount {
    let bytes = [0u8; 32];

    Subaccount(bytes)
}

// This should be handled in a separate library alltogether
pub fn get_canister_state() -> CanisterState {
    let owner_principal = ic_cdk::api::id();
    let default_subaccount = create_default_subaccount();

    let account_identifier = AccountIdentifier::new(&owner_principal, &default_subaccount);
    CanisterState {
        owner: owner_principal,
        default_subaccount,
        account_identifier,
    }
}
