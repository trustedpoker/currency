#!/bin/bash

set -x

DFX_NETWORK=local

# Example to mint ckBTC

BTCADDRESS="$(dfx canister call ckbtc_minter get_btc_address '(record {subaccount=null;})' --network "$DFX_NETWORK")"

dfx canister call ckbtc_minter update_balance '(record {subaccount=null;})' --network "$DFX_NETWORK"

WITHDRAWALADDRESS="$(dfx canister call ckbtc_minter get_withdrawal_account --network "$DFX_NETWORK")"
echo $BTCADDRESS
echo $WITHDRAWALADDRESS

cleaned_output=$(echo $WITHDRAWALADDRESS | sed -re 's/^\(|, \)$//g')

dfx canister call ckbtc_ledger icrc1_transfer "(record {from=null; to=$cleaned_output; amount=1000000; fee=null; memo=null; created_at_time=null;})" --network "$DFX_NETWORK"

# Execute the command to get the input string and save the result
# dfx canister call ckbtc_minter retrieve_btc '(record {fee = null; address="bcrt1qu9za0uzzd3kjjecgv7waqq0ynn8dl8l538q0xl"; amount=10000})' --network "$DFX_NETWORK"


dfx canister call ckbtc_ledger icrc1_transfer "(record {from=null; to= record{owner= principal \"zyrzn-feder-nafqx-wiy2s-eqc42-rnpws-u47l7-l72aj-hh3e5-a2a6q-dqe\"}; amount=100000000; fee=null; memo=null; created_at_time=null;})" 
dfx canister call ckbtc_ledger icrc1_transfer "(record {from=null; to= record{owner= principal \"uyxh5-bi3za-gxbfs-op3gj-ere73-a6jhv-5jky3-zawef-b5r2s-k26un-sae\"}; amount=100000000; fee=null; memo=null; created_at_time=null;})" 