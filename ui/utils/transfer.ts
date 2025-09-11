import { IcrcLedgerCanister } from "@dfinity/ledger-icrc";
import {
  Account,
  AccountIdentifier,
  LedgerCanister,
} from "@dfinity/ledger-icp";
import { UserError } from "@zk-game-dao/ui";

import { AuthData } from "../auth";
import { CurrencyReceiver, CurrencyType } from "../types/currency";
import { getLedgerCanisterID } from "./manager";

export const transferTo = async (
  currencyType: CurrencyType,
  receiver: CurrencyReceiver,
  amount: bigint,
  authData: AuthData
) => {
  if ("Fake" in currencyType) return 0n;

  const canisterId = getLedgerCanisterID(currencyType.Real);

  if ("ICP" in currencyType.Real) {
    const canisterId = getLedgerCanisterID(currencyType.Real);

    let to: AccountIdentifier | undefined;

    if ("principal" in receiver) {
      to = AccountIdentifier.fromPrincipal({
        principal: receiver.principal,
      });
    } else if ("accountIdentifier" in receiver) {
      to = receiver.accountIdentifier;
    } else {
      throw new UserError("Invalid receiver address");
    }

    return LedgerCanister.create({
      agent: authData.agent,
      canisterId,
    }).transfer({
      to,
      amount,
    });
  }

  if (!("principal" in receiver))
    throw new UserError("Receiver must have a principal for ICRC transfers");

  const ledgerCanister = IcrcLedgerCanister.create({
    agent: authData.agent,
    canisterId,
  });

  return ledgerCanister.transfer({
    to: {
      owner: receiver.principal,
      subaccount: [],
    },
    amount,
  });
};
