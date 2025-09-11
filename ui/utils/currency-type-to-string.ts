import { matchRustEnum } from "@zk-game-dao/ui";
import { CKTokenSymbol, Currency, CurrencyType } from "../types";
import { decodeSymbolFrom8Bytes } from "./encode-symbol";

export const CKTokenToString = (ckTokenSymbol: CKTokenSymbol): string =>
  matchRustEnum(ckTokenSymbol)({
    ETH: () => "ETH",
    USDC: () => "USDC",
    USDT: () => "USDT",
  });

export const CurrencyToString = (currency: Currency): string =>
  matchRustEnum(currency)({
    GenericICRC1: (genericICRC1) => {
      const symbol = `${decodeSymbolFrom8Bytes(genericICRC1.symbol)}`;
      if (symbol.startsWith("ck")) return symbol.slice(2);
      return symbol;
    },
    CKETHToken: (ckCurrencySymbol) => CKTokenToString(ckCurrencySymbol),
    BTC: () => "BTC",
    ICP: () => "ICP",
  });

export const CurrencyTypeToString = (currencyType: CurrencyType): string =>
  matchRustEnum(currencyType)({
    Fake: () => "In game",
    Real: (real) => CurrencyToString(real),
  });
