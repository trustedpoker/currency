#!/bin/bash

# Download ckBTC

DIR=target/ic

if [ ! -d "$DIR" ]; then
  mkdir -p "$DIR"
fi

IC_COMMIT="03dd6ee6de80c2202f66948692c69c61eb6af54d"

download_if_not_exists() {
  local url=$1
  local output=$2
  if [ ! -f "$output" ]; then
    curl -sSL "$url" -o "$output"
  else
    echo "File $output already exists, skipping download."
  fi
}

download_if_not_exists "https://download.dfinity.systems/ic/$IC_COMMIT/canisters/ic-ckbtc-minter.wasm.gz" "$DIR/ckbtc_minter.wasm.gz"
[ -f "$DIR/ckbtc_minter.wasm" ] || gunzip "$DIR/ckbtc_minter.wasm.gz"

download_if_not_exists "https://download.dfinity.systems/ic/$IC_COMMIT/canisters/ic-icrc1-ledger.wasm.gz" "$DIR/ckbtc_ledger.wasm.gz"
[ -f "$DIR/ckbtc_ledger.wasm" ] || gunzip -k "$DIR/ckbtc_ledger.wasm.gz"

download_if_not_exists "https://download.dfinity.systems/ic/$IC_COMMIT/canisters/ic-icrc1-index-ng.wasm.gz" "$DIR/ckbtc_index.wasm.gz"
[ -f "$DIR/ckbtc_index.wasm" ] || gunzip -k "$DIR/ckbtc_index.wasm.gz"

download_if_not_exists "https://download.dfinity.systems/ic/$IC_COMMIT/canisters/ic-ckbtc-kyt.wasm.gz" "$DIR/ckbtc_kyt.wasm.gz"
[ -f "$DIR/ckbtc_kyt.wasm" ] || gunzip "$DIR/ckbtc_kyt.wasm.gz"

download_if_not_exists "https://raw.githubusercontent.com/dfinity/ic/$IC_COMMIT/rs/bitcoin/ckbtc/minter/ckbtc_minter.did" "$DIR/ckbtc_minter.did"

download_if_not_exists "https://raw.githubusercontent.com/dfinity/ic/$IC_COMMIT/rs/ledger_suite/icrc1/ledger/ledger.did" "$DIR/ckbtc_ledger.did"

download_if_not_exists "https://raw.githubusercontent.com/dfinity/ic/$IC_COMMIT/rs/ledger_suite/icrc1/index-ng/index-ng.did" "$DIR/ckbtc_index.did"

download_if_not_exists "https://raw.githubusercontent.com/dfinity/ic/$IC_COMMIT/rs/bitcoin/ckbtc/kyt/kyt.did" "$DIR/ckbtc_kyt.did"