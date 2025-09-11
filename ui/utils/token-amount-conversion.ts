import Big from "big.js";

import { BigIntToBig, BigIntToString, BigToBigInt } from "@zk-game-dao/ui";

import { CurrencyMeta } from "../types/meta";

export const FloatToTokenAmount = <
  Param extends Big | undefined = Big | undefined,
  Return = Param extends number ? bigint : undefined,
>(
  f: Param,
  meta: CurrencyMeta
): Return => BigToBigInt<Param, Return>(f, meta.decimals);

export const TokenAmountToBig = <
  Param extends bigint | undefined = bigint | undefined,
  Return = Param extends bigint ? Big : undefined,
>(
  amount: Param,
  meta: CurrencyMeta
): Return => BigIntToBig<Param, Return>(amount, meta.decimals);

export const TokenAmountToString = (
  amount: bigint,
  meta: Pick<CurrencyMeta, "decimals" | "renderedDecimalPlaces">,
  forceAccuracy = false
) => {
  if (forceAccuracy)
    return BigIntToString(amount, meta.decimals, meta.decimals).toString();
  if ("decimals" in meta) {
    const bigDecimals = Big(10).pow(meta.decimals);
    const bigRendered = Big(amount.toString()).div(bigDecimals);
    if (bigRendered.gte(10000))
      return `${bigRendered.div(1000).round().toNumber().toLocaleString()} K`;
  }
  return BigIntToString(
    amount,
    meta.decimals,
    meta.renderedDecimalPlaces ?? 6
  ).toString();
};
