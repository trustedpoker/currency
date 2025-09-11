import { useSiwbIdentity } from "ic-siwb-lasereyes-connector";
import { useState } from "react";

import { useQuery } from "@tanstack/react-query";
import { DateToBigIntTimestamp } from "@zk-game-dao/ui";
import { addMonths } from "date-fns";

export const useSiwbLoginFlow = () => {
  const {
    prepareLogin,
    isPrepareLoginIdle,
    login,
    clear,
    connectedBtcAddress,
    getAddress,
    identity,
  } = useSiwbIdentity();

  const [manuallyTriggered, setManuallyTriggered] = useState(false);

  const address = getAddress();

  const prepareQuery = useQuery({
    queryKey: ["prepare-login", address],
    queryFn: async () => {
      if (!address) throw new Error("No address available");
      await prepareLogin();
      return true;
    },
    enabled: !!address && isPrepareLoginIdle,
    staleTime: Infinity,
    retry: false,
  });

  const loginQuery = useQuery({
    queryKey: [
      "perform-login",
      connectedBtcAddress,
      identity?.getPrincipal().toText(),
      manuallyTriggered,
    ],
    queryFn: async () => {
      if (!connectedBtcAddress || identity || !manuallyTriggered) return;
      await login();
      return true;
    },
    enabled: !!connectedBtcAddress && !identity && manuallyTriggered,
    staleTime: Infinity,
    retry: false,
  });

  useQuery({
    queryKey: ["clear-login", identity?.getPrincipal().toText()],
    queryFn: async () => {
      if (!identity) return;
      if (
        !identity
          .getDelegation()
          .delegations.every(
            (d) => d.delegation.expiration >= DateToBigIntTimestamp(new Date())
          )
      ) {
        await clear();
      }
    },
    enabled: !!identity,
    staleTime: Infinity,
    retry: false,
  });

  return {
    prepareQuery,
    loginQuery,
    manuallyTrigger: () => setManuallyTriggered(true),
  };
};
