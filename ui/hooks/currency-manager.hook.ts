import { HttpAgent } from "@dfinity/agent";
import { IC_HOST, IsDev, matchRustEnum, useQuery } from "@zk-game-dao/ui";

import { useAuth } from "../auth/types/context";
import { CurrencyMeta } from "../types";
import { CurrencyType } from "../types/currency";
import { CurrencyManager } from "../types/manager";
import {
  buildCurrencyTypeManager,
  buildFakeCurrencyManager,
  getManagerMetadata,
  getStaticManagerMetadata,
} from "../utils/manager";
import { CurrencyTypeToString } from "../utils";
import { CurrencyTypeSerializer } from "../utils/serialize";
import { useIsBTC } from "../context";

const host = IC_HOST;

export const useCurrencyManager = (
  currencyType: CurrencyType
): CurrencyManager => {
  const { authData } = useAuth();
  const isBTC = useIsBTC();
  return useQuery({
    queryKey: [
      "currencyManager",
      CurrencyTypeSerializer.serialize(currencyType),
      authData ? authData.principal.toText() : "unauthenticaded",
    ],
    queryFn: async () => {
      const agent = authData?.agent ?? HttpAgent.createSync({ host });

      // Fetch root key only in development to bypass certificate validation
      if (IsDev) await agent.fetchRootKey();

      return await buildCurrencyTypeManager(agent, currencyType);
    },
    initialData: {
      meta: buildFakeCurrencyManager(isBTC).meta,
      currencyType,
    },
  }).data;
};

export const useRequiredCurrencyManager = (
  currencyType: CurrencyType
): CurrencyManager => {
  const manager = useCurrencyManager(currencyType);
  if (!manager)
    throw new Error(
      `Currency manager for ${CurrencyTypeToString(currencyType)} not found`
    );
  return manager;
};

export const useCurrencyManagerMeta = (
  currencyType: CurrencyType
): CurrencyMeta => {
  const isBTC = useIsBTC();
  return useQuery({
    queryKey: [
      "currencyManagerMeta",
      CurrencyTypeSerializer.serialize(currencyType),
    ],
    queryFn: async () => {
      if ("Fake" in currencyType) return buildFakeCurrencyManager(isBTC).meta;
      return await getManagerMetadata(currencyType.Real);
    },
    throwOnError: true,
    initialData: matchRustEnum(currencyType)({
      Fake: () => buildFakeCurrencyManager(isBTC).meta,
      Real: (currency) => getStaticManagerMetadata(currency),
    }),
  }).data;
};
