import { Principal } from "@dfinity/principal";
import {
  CKTokenSymbol,
  Currency,
  CurrencyType,
  Token,
} from "../types/currency";

export const IsSamePrincipal = (a?: Principal, b?: Principal) => {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  return a.compareTo(b) === "eq";
};

export const IsSameToken = (a?: Token, b?: Token) => {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;

  return (
    a.decimals === b.decimals &&
    IsSamePrincipal(a.ledger_id, b.ledger_id) &&
    a.symbol === b.symbol
  );
};

export const IsSameCKTokenSymbol = (a?: CKTokenSymbol, b?: CKTokenSymbol) => {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;

  if ("BTC" in a) return "BTC" in b;
  if ("ETH" in a) return "ETH" in b;
  if ("USDC" in a) return "USDC" in b;
  if ("USDT" in a) return "USDT" in b;

  return false;
};

export const IsSameCurrency = (a?: Currency, b?: Currency) => {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;

  if ("ICP" in a) return "ICP" in b;
  if ("BTC" in a) return "BTC" in b;

  if ("CKETHToken" in a) {
    if (!("CKETHToken" in b)) return false;
    return IsSameCKTokenSymbol(a.CKETHToken, b.CKETHToken);
  }
  if ("GenericICRC1" in a) {
    if (!("GenericICRC1" in b)) return false;
    return IsSameToken(a.GenericICRC1, b.GenericICRC1);
  }
  return false;
};

export const IsSameCurrencyType = (a?: CurrencyType, b?: CurrencyType) => {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  if ("Fake" in a) return "Fake" in b;
  if ("Fake" in b) return false;
  return IsSameCurrency(a.Real, b.Real);
};
