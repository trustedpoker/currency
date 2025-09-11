import { CkBTCMinterCanister } from "@dfinity/ckbtc";
import { Principal } from "@dfinity/principal";
import { useQuery } from "@zk-game-dao/ui";
import { useMemo } from "react";

import { useAuth } from "../auth/types/context";
import { BTC_MINTER_CANISTER_ID } from "../types";

export const useBTCMinter = () => {
  const { authData } = useAuth();
  return useMemo(
    () =>
      CkBTCMinterCanister.create({
        canisterId: Principal.from(BTC_MINTER_CANISTER_ID),
        agent: authData?.agent,
      }),
    [authData?.agent]
  );
};

export const useBTCDepositAddress = () => {
  const minter = useBTCMinter();
  const { authData } = useAuth();

  return useQuery({
    queryKey: ["btc-deposit-address", authData?.principal.toText()],
    queryFn: () => minter.getBtcAddress({}),
  });
};

export const useBTCWithdrawalAccount = () => {
  const minter = useBTCMinter();

  return useQuery({
    queryKey: ["btc-withdrawal-account"],
    queryFn: () => minter.getWithdrawalAccount(),
  });
};

export const useMinterInfo = () => {
  const minter = useBTCMinter();

  return useQuery({
    queryKey: ["btc-minter-info"],
    queryFn: () => minter.getMinterInfo({}),
    initialData: {
      retrieve_btc_min_amount: 50000n,
      min_confirmations: 6,
      kyt_fee: 100n,
    },
  });
};
