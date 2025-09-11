import { useMutation, UserError } from "@zk-game-dao/ui";

import { useAuth } from "../auth/types/context";
import { Queries } from "../queries";
import { Currency, CurrencyReceiver } from "../types/currency";
import { buildCurrencyManager } from "../utils/manager/manager-map";
import { CurrencyToString } from "../utils/currency-type-to-string";
import { TokenAmountToString } from "../utils/token-amount-conversion";
import { transferTo } from "../utils/transfer";
import { useRequireBalance } from "./require-balance";

export class InsufficientBalanceError extends UserError {
  constructor() {
    super("Insufficient balance");
  }
}

export const useTransfer = (currency: Currency, to?: CurrencyReceiver) => {
  const { authData } = useAuth();
  const requireBalance = useRequireBalance({ Real: currency });

  return useMutation({
    mutationFn: async (amount: bigint): Promise<bigint> => {
      if (!to) throw new UserError("Recipient not found");
      if (!authData) throw new UserError("Auth data not found");
      const { meta } = await buildCurrencyManager(authData.agent, currency);
      await requireBalance(amount + meta.transactionFee);

      try {
        return await transferTo(
          { Real: currency },
          to,
          amount + meta.transactionFee,
          authData
        );
      } catch (e) {
        console.error(e);
        throw new UserError(
          `Transfer failed. Please check your balance and try again. (Transaction fee is ${TokenAmountToString(
            meta.transactionFee,
            meta
          )} ${CurrencyToString(currency)})`
        );
      }
    },
    onSuccess: () => {
      Queries.walletBalance.invalidate({ Real: currency }, authData);
      Queries._balanceModalBalance.invalidate({ Real: currency });
    },
  });
};
