use candid::Principal;
use ic_ledger_types::{AccountIdentifier, Subaccount, MAINNET_LEDGER_CANISTER_ID};

use crate::{
    currency_error::CurrencyError,
    icrc1_types::{Account, TransferArg, TransferErrorIcrc1},
};

pub async fn transfer_icp(
    amount: u64,
    default_subaccount: Subaccount,
    to: Principal,
) -> Result<(), CurrencyError> {
    let transfer_result = ic_ledger_types::transfer(
        MAINNET_LEDGER_CANISTER_ID,
    &ic_ledger_types::TransferArgs {
            memo: ic_ledger_types::Memo(0), // Use an appropriate memo
            amount: ic_ledger_types::Tokens::from_e8s(amount - ic_ledger_types::DEFAULT_FEE.e8s()),
            fee: ic_ledger_types::DEFAULT_FEE,
            from_subaccount: Some(default_subaccount),
            to: AccountIdentifier::new(&to, &ic_ledger_types::DEFAULT_SUBACCOUNT),
            created_at_time: None, // Optionally specify a time
        },
    )
    .await;

    match transfer_result {
        Ok(result) => match result {
            Ok(block_index) => ic_cdk::api::print(format!(
                "Transfer successful with block index {}",
                block_index
            )),
            Err(e) => {
                return Err(CurrencyError::LedgerError(format!(
                    "Transfer failed: {:?}",
                    e
                )))
            }
        },
        Err(e) => {
            return Err(CurrencyError::LedgerError(format!(
                "ICDK call error: {:?}",
                e
            )))
        }
    }
    Ok(())
}

// Adjusted transfer_icrc1 function
pub async fn transfer_icrc1(
    ledger_canister_id: Principal,
    amount: u64,
    default_subaccount: Vec<u8>,
    to_account: Principal,
    fee: Option<u128>
) -> Result<u128, CurrencyError> {
    ic_cdk::println!(
        "Transferring {} tokens to account {:?}",
        amount,
        &to_account,
    );

    let transfer_args = TransferArg {
        to: Account {
            owner: to_account,
            subaccount: Some(default_subaccount),
        },
        fee,
        amount: (amount as u128 - fee.unwrap_or(ic_ledger_types::DEFAULT_FEE.e8s().into())).into(),
        memo: None,
        from_subaccount: None,
        created_at_time: ic_cdk::api::time().into(),
    };

    // Call the icrc1_transfer method
    let transfer_result: Result<(Result<u128, TransferErrorIcrc1>,), _> =
        ic_cdk::call(ledger_canister_id, "icrc1_transfer", (transfer_args,)).await;

    ic_cdk::println!("Transfer result: {:?}", transfer_result);

    match transfer_result {
        Ok((Ok(block_index),)) => {
            ic_cdk::api::print(format!(
                "Transfer successful with block index {}",
                block_index
            ));
            Ok(block_index)
        }
        Ok((Err(e),)) => Err(CurrencyError::LedgerError(format!(
            "Ledger transfer error: {:?}",
            e
        ))),
        Err((rejection_code, message)) => Err(CurrencyError::LedgerError(format!(
            "Failed to call ledger: {:?} {}",
            rejection_code, message
        ))),
    }
}
