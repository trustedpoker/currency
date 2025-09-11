import { AccountIdentifier } from "@dfinity/ledger-icp";
import { Principal } from "@dfinity/principal";
import { queryKeyFactory } from "@zk-game-dao/ui";

import { CurrencyReceiver, CurrencyType } from "./types";
import { SiwbIdentityContextType } from "ic-siwb-lasereyes-connector";
import { LaserEyesContextType } from "@omnisat/lasereyes";
import { AuthClient } from "@dfinity/auth-client";

export const Queries = {
  auth: queryKeyFactory(
    ({
      siwb,
      laserEyes,
      internetIdentityProvider,
    }: {
      siwb?: SiwbIdentityContextType;
      laserEyes?: LaserEyesContextType;
      internetIdentityProvider?: AuthClient;
    }) => [
      "auth",
      siwb?.identity?.getPrincipal() ?? "unknown",
      laserEyes?.address,
      laserEyes?.provider,
      internetIdentityProvider?.getIdentity().getPrincipal().toText() ??
        "unknown",
    ]
  ),
  _balanceModalBalance: queryKeyFactory((currency: CurrencyType) => [
    "balance-modal-balance",
    currency,
  ]),

  chain_fusion_transaction_fees: queryKeyFactory((authenticated: boolean) => [
    "chain-fusion-transaction-fees",
    authenticated.toString(),
  ]),

  walletBalance: queryKeyFactory(
    (
      currency: CurrencyType,
      authData?: { accountIdentifier?: AccountIdentifier }
    ) => [
      "wallet-balance",
      currency,
      authData?.accountIdentifier?.toHex() ?? "unknown",
    ]
  ),

  icrc_allowance: queryKeyFactory((currency: CurrencyType) => [
    "icrc-allowance",
    currency,
  ]),

  allowance: queryKeyFactory(
    (
      currency?: CurrencyType,
      receiver?: CurrencyReceiver,
      wallet?: Principal
    ) => [
      "allowance",
      currency ?? "-",
      receiver ? JSON.stringify(receiver) : "-",
      wallet?.toText() ?? "-",
    ]
  ),

  transactionFee: queryKeyFactory((currency: CurrencyType) => [
    "transaction-fee",
    currency,
  ]),
};
