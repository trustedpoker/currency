import { useMemo } from "react";

import { useQuery } from "@zk-game-dao/ui";

import { useAuth } from "../auth/types/context";
import { Queries } from "../queries";
import { CurrencyType } from "../types/currency";
import { fetchBalance } from "../utils/balance";

export const useBalance = (currencyType: CurrencyType): bigint => {
  const { authData } = useAuth();

  const { data: wallet = 0n } = useQuery({
    queryKey: Queries.walletBalance.key(currencyType, authData),
    queryFn: async () => {
      if (!authData) return 0n;
      return fetchBalance(currencyType, authData);
    },
    refetchInterval: 5000,
  });

  return useMemo(() => wallet, [wallet]);
};
