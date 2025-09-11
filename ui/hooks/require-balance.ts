import { useCallback } from "react";

import { useAuth } from "../auth";
import { CurrencyType } from "../types/currency";
import { useBalance } from "./balance";
import { fetchBalance } from "../utils/balance";

// import { useUser } from "@lib/user";

export const useRequireBalance = (currency: CurrencyType) => {
  const { authData } = useAuth();
  const balance = useBalance(currency);

  return useCallback(
    async (requiredBalance: bigint, action?: string) => {
      if (!authData) throw new Error("Auth data not found");
      const balance = await fetchBalance(currency, authData);
      if (requiredBalance <= 0) return;
      return new Promise<void>((resolve, reject) => {
        if (balance >= requiredBalance) return resolve();
        alert("Insufficient balance");
        // return showBalance({
        //   requiredBalance: {
        //     currency: currency,
        //     currencyValue: requiredBalance,
        //   },
        //   action,
        //   onBalanceUpdate: (v) => {
        //     if (v < requiredBalance) reject(new Error("Insufficient balance"));
        //     resolve();
        //   },
        // });
      });
    },
    [balance]
  );
};
