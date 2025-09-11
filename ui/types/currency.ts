import { AccountIdentifier } from "@dfinity/ledger-icp";
import { Principal } from "@dfinity/principal";

export type CKTokenSymbol = { ETH: null } | { USDC: null } | { USDT: null };

export interface Token {
  decimals: number;
  ledger_id: Principal;
  symbol: Uint8Array | number[];
}

export type Currency =
  | { BTC: null }
  | { ICP: null }
  | { GenericICRC1: Token }
  | { CKETHToken: CKTokenSymbol };

export type CurrencyType = { Fake: null } | { Real: Currency };

export type CurrencyReceiver =
  | { accountIdentifier: AccountIdentifier }
  | { principal: Principal };
