#!/bin/bash

rm -rf .dfx

./scripts/download.ckbtc.sh
./scripts/deploy.ckbtc.sh
./scripts/deploy-sign-in-providers.sh