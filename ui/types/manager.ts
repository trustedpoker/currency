import { CurrencyType } from "./currency";
import { CurrencyMeta } from "./meta";

export type CurrencyManagerMap = Record<string, CurrencyManager>;

export type CurrencyManager = {
  // wallet?: {
  //   self: CurrencyReceiver;
  //   address: Principal;
  //   accountBalance(): Promise<bigint>;
  //   transferTo(to: CurrencyReceiver, amount: bigint): Promise<bigint>;
  // };
  meta: CurrencyMeta;
  currencyType: CurrencyType;
};
