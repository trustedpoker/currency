#!/bin/bash

set -x

DFX_NETWORK=local

DIR=target/ic

if [ ! -d "$DIR" ]; then
  mkdir "$DIR"
fi

if [ ! -f "$DIR/ic_siwb_provider.did" ]; then
    echo "Downloading did..."
    curl -sSL https://raw.githubusercontent.com/AstroxNetwork/ic-siwb/refs/heads/main/packages/ic_siwb_provider/ic_siwb_provider.did -o "$DIR/ic_siwb_provider.did"
fi

if [ ! -f "$DIR/ic_siwb_provider.wasm.gz" ]; then
    echo "Downloading wasm..."
    curl -sSL https://github.com/AstroxNetwork/ic-siwb/raw/refs/heads/main/packages/ic_siwb_provider/ic_siwb_provider.wasm.gz -o "$DIR/ic_siwb_provider.wasm.gz"
fi

if [ ! -f "$DIR/ic_siwb_provider.wasm" ]; then
    echo "Unzipping wasm..."
    gunzip -k "$DIR"/ic_siwb_provider.wasm.gz
fi

echo "Creating local ic_siwb_provider canister..."
dfx canister create ic_siwb_provider --specified-id be2us-64aaa-aaaaa-qaabq-cai --network "$DFX_NETWORK"

# uri = "http://127.0.0.1:5173";
echo "Deploying ic_siwb_provider canister..."
dfx deploy ic_siwb_provider --specified-id be2us-64aaa-aaaaa-qaabq-cai --network local --argument '(
    record {
        domain = "hffks-yiaaa-aaaah-qqana-cai.icp0.io";
        uri = "https://hffks-yiaaa-aaaah-qqana-cai.icp0.io";
        salt = "V8oaXyWK3s1E85Gsxb8GF6N29cKjBmcZ";
        statement = opt "Login to Pure Poker";
    }
)'