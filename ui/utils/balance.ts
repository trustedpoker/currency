import { IcrcLedgerCanister } from "@dfinity/ledger-icrc";
import { AccountIdentifier, LedgerCanister } from "@dfinity/ledger-icp";

import { AuthData } from "../auth";
import { CurrencyType } from "../types/currency";
import { getLedgerCanisterID } from "./manager";

export const fetchBalance = async (
  currencyType: CurrencyType,
  authData: AuthData
) => {
  if ("Fake" in currencyType) return 0n;

  if ("ICP" in currencyType.Real)
    return LedgerCanister.create({
      agent: authData.agent,
      canisterId: getLedgerCanisterID(currencyType.Real),
    }).accountBalance({
      accountIdentifier: AccountIdentifier.fromPrincipal({
        principal: authData.principal,
      }),
    });

  const canisterId = getLedgerCanisterID(currencyType.Real);

  const ledgerCanister = IcrcLedgerCanister.create({
    agent: authData.agent,
    canisterId,
  });

  return ledgerCanister.balance({
    owner: authData.principal,
  });
};
