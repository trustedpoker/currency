import { useQuery, UserError } from "@zk-game-dao/ui";
import { useContext, useMemo } from "react";

import { useBalance, useTransactionFee } from ".";
import { useAuth } from "../auth/types/context";
import { Queries } from "../queries";
import {
  AllowanceAddressData,
  AllowanceRequestData,
  CurrencyAllowanceContext,
} from "../types/allowance.context";
import { fetchAllowance, setAllowance } from "../utils/allowance";

export const useAllowanceBalance = (address?: AllowanceAddressData) => {
  const { authData } = useAuth();
  const { data } = useQuery({
    queryKey: Queries.allowance.key(
      address?.currencyType ?? { Fake: null },
      address?.receiver,
      authData?.principal
    ),
    queryFn: async () =>
      authData && address
        ? fetchAllowance(address.currencyType, address!.receiver, authData)
        : 0n,
    initialData: 0n,
    refetchInterval: 10000,
  });

  return useMemo(() => data, [data]);
};

export const useAllowance = (
  address?: AllowanceAddressData
): {
  allowance: bigint;
  require(request: AllowanceRequestData, expires_at: Date): Promise<void>;
  update(request: AllowanceRequestData, expires_at: Date): Promise<void>;
} => {
  const { authData } = useAuth();
  const ctx = useContext(CurrencyAllowanceContext);
  const balance = useBalance(address?.currencyType ?? { Real: { ICP: null } });
  const allowance = useAllowanceBalance(address);
  const fee = useTransactionFee(
    address?.currencyType ?? { Real: { ICP: null } }
  );

  return useMemo(
    () => ({
      allowance,
      require: async (request, expires_at) => {
        if (!address) throw new UserError("Address not provided");
        if (!authData) throw new UserError("Auth data not provided");
        const realAmount = request.amount + fee;

        const allowance = await fetchAllowance(
          address.currencyType,
          address.receiver,
          authData
        );

        if (allowance >= realAmount) return;
        const remaining = realAmount - allowance;

        if (remaining > balance)
          throw new UserError("Insufficient balance including fee");

        await setAllowance(
          address.currencyType,
          address.receiver,
          realAmount,
          authData,
          expires_at
        );
        await Queries.allowance.invalidate(
          address?.currencyType ?? "ICP",
          address?.receiver,
          authData?.principal
        );
        return;
      },
      update: async (request, expires_at) => {
        if (!address) throw new UserError("Address not provided");
        await ctx.setAllowance(address, request, expires_at);
        await Queries.allowance.invalidate(
          address?.currencyType ?? "ICP",
          address?.receiver,
          authData?.principal
        );
      },
    }),
    [allowance, ctx, address]
  );
};
