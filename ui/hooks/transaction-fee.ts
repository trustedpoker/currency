import { CurrencyType } from "../types/currency";
import { useCurrencyManagerMeta } from "./currency-manager.hook";

export const useTransactionFee = (currencyType: CurrencyType) =>
  useCurrencyManagerMeta(currencyType).transactionFee;
