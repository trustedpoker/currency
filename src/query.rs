use candid::Principal;
use ic_ledger_types::{query_archived_blocks, query_blocks, Block, BlockIndex, GetBlocksArgs};

use crate::{
    ckusdc_canister_interface::{GetBlocksRequest, GetTransactionsResponse, Transaction},
    currency_error::CurrencyError,
};

pub async fn get_one_block(
    ledger: Principal,
    block_index: u64,
) -> Result<Option<Transaction>, CurrencyError> {
    for i in 0..3 {
        let args = GetBlocksRequest {
            start: candid::Nat::from(block_index),
            length: candid::Nat::from(1u64),
        };

        let result: Result<(GetTransactionsResponse,), _> =
            ic_cdk::call(ledger, "get_transactions", (args,)).await;

        match result {
            Ok((response,)) => return Ok(response.transactions.into_iter().next()),
            Err(e) => {
                if i == 2 {
                    // Last attempt
                    return Err(CurrencyError::QueryError(format!(
                        "Error querying transactions: {:?}",
                        e
                    )));
                }
                // On failure, continue to next iteration
                continue;
            }
        }
    }
    Ok(None)
}

pub async fn query_one_block(
    ledger: Principal,
    block_index: BlockIndex,
) -> Result<Option<Block>, CurrencyError> {
    let args = GetBlocksArgs {
        start: block_index,
        length: 1,
    };

    for i in 0..3 {
        let blocks_result = match query_blocks(ledger, &args).await {
            Ok(blocks) => blocks,
            Err(e) => {
                if i == 2 {
                    return Err(CurrencyError::QueryError(format!(
                        "Error querying blocks: {:?}",
                        e
                    )));
                }
                continue;
            }
        };

        if !blocks_result.blocks.is_empty() {
            debug_assert_eq!(blocks_result.first_block_index, block_index);
            return Ok(blocks_result.blocks.into_iter().next());
        }

        if let Some(func) = blocks_result.archived_blocks.into_iter().find_map(|b| {
            (b.start <= block_index && (block_index - b.start) < b.length).then_some(b.callback)
        }) {
            match query_archived_blocks(&func, &args).await {
                Ok(blocks) => match blocks {
                    Ok(range) => return Ok(range.blocks.into_iter().next()),
                    Err(e) => {
                        return Err(CurrencyError::QueryError(format!(
                            "Error querying archived blocks: {:?}",
                            e
                        )))
                    }
                },
                Err(e) => {
                    return Err(CurrencyError::QueryError(format!(
                        "Error querying archived blocks: {:?}",
                        e
                    )))
                }
            }
        }
    }

    Ok(None)
}

pub async fn get_balance(
    ledger: &Principal,
    owner: &Principal,
    subaccount: Option<Vec<u8>>,
) -> Result<u128, CurrencyError> {
    let (res,): (u128,) = ic_cdk::call(*ledger, "icrc1_balance_of", (owner, subaccount))
        .await
        .map_err(|e| CurrencyError::LedgerError(format!("{:?}", e)))?;
    Ok(res)
}
