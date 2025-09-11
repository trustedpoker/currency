import { Principal } from "@dfinity/principal";
import { matchRustEnum } from "@zk-game-dao/ui";

import {
  CKTokenSymbol,
  Currency,
  CurrencyType,
  Token,
} from "../types/currency";
import { decodeSymbolFrom8Bytes } from "./encode-symbol";

const CreateSerializer = <T>(
  serialize: (value: T) => string = JSON.stringify,
  deserialize: (value: string) => T = JSON.parse
) => ({
  serialize,
  deserialize,
  validate: (value: T) => deserialize(serialize(value)),
});

export const TokenSerializer = CreateSerializer<Token>(
  JSON.stringify,
  (value) => {
    let d = JSON.parse(value);

    if (typeof d === "string") d = JSON.parse(d);

    if (typeof d.symbol === "string")
      d.symbol = decodeSymbolFrom8Bytes(d.symbol);
    else if (typeof d.symbol === "object") {
      d.symbol = Object.values(d.symbol).map((s) => {
        if (typeof s === "string") return parseInt(s, 10);
        return s;
      });
    }

    if (typeof d.ledger_id === "string")
      d.ledger_id = Principal.fromText(d.ledger_id);
    if ("__principal__" in d.ledger_id)
      d.ledger_id = Principal.fromText(d.ledger_id.__principal__);

    return {
      decimals: d.decimals,
      ledger_id: d.ledger_id,
      symbol: d.symbol,
    };
  }
);
export const CKTokenSymbolSerializer = CreateSerializer<CKTokenSymbol>();
export const CurrencySerializer = CreateSerializer<Currency>(
  (v) =>
    JSON.stringify(
      matchRustEnum(v)({
        ICP: (): Currency => ({ ICP: null }),
        CKETHToken: (token): Currency => ({
          CKETHToken: CKTokenSymbolSerializer.validate(token),
        }),
        BTC: (): Currency => ({ BTC: null }),
        GenericICRC1: (token): Currency => ({
          GenericICRC1: TokenSerializer.validate(token),
        }),
      })
    ),
  (value) =>
    matchRustEnum(JSON.parse(value) as Currency)({
      ICP: (): Currency => ({ ICP: null }),
      CKETHToken: (token): Currency => ({
        CKETHToken: CKTokenSymbolSerializer.validate(token),
      }),
      BTC: (token): Currency => ({ BTC: null }),
      GenericICRC1: (token): Currency => ({
        GenericICRC1: TokenSerializer.validate(token),
      }),
    })
);
export const CurrencyTypeSerializer = CreateSerializer<CurrencyType>(
  (v) =>
    JSON.stringify(
      matchRustEnum(v)({
        Real: (currency): CurrencyType => ({
          Real: CurrencySerializer.validate(currency),
        }),
        Fake: (): CurrencyType => ({
          Fake: null,
        }),
      })
    ),
  (value) =>
    matchRustEnum(JSON.parse(value) as CurrencyType)({
      Real: (currency): CurrencyType => ({
        Real: CurrencySerializer.validate(currency),
      }),
      Fake: (): CurrencyType => ({
        Fake: null,
      }),
    })
);
