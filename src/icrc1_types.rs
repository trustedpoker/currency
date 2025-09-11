use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(CandidType, Deserialize)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize)]
pub struct TransferArg {
    pub to: Account,
    pub fee: Option<u128>,
    pub memo: Option<Vec<u8>>,
    pub from_subaccount: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
    pub amount: u128,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum TransferErrorIcrc1 {
    GenericError { message: String, error_code: u128 },
    TemporarilyUnavailable,
    BadBurn { min_burn_amount: u128 },
    Duplicate { duplicate_of: u128 },
    BadFee { expected_fee: u128 },
    CreatedInFuture { ledger_time: u64 },
    TooOld,
    InsufficientFunds { balance: u128 },
}

#[derive(CandidType, Deserialize, Debug)]
pub struct Allowance {
    pub allowance: u128,
    pub expires_at: Option<u64>,
}

#[derive(CandidType, Deserialize)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(CandidType, Deserialize)]
pub struct TransferFromArg {
    pub spender_subaccount: Option<Vec<u8>>,
    pub from: Account,
    pub to: Account,
    pub amount: u128,
    pub fee: Option<u128>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum TransferFromError {
    BadFee { expected_fee: u128 },
    BadBurn { min_burn_amount: u128 },
    InsufficientFunds { balance: u128 },
    InsufficientAllowance { allowance: u128 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: u128 },
    TemporarilyUnavailable,
    GenericError { error_code: u128, message: String },
}
