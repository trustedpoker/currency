import { IcrcLedgerCanister } from '@dfinity/ledger-icrc';
import { IsDev, UserError } from '@zk-game-dao/ui';

import { AuthData } from '../auth';
import { CurrencyReceiver, CurrencyType } from '../types/currency';
import { DateToBigNanoseconds } from './time';
import { getLedgerCanisterID } from './manager';

export const fetchAllowance = async (
  currencyType: CurrencyType,
  receiver: CurrencyReceiver,
  authData: AuthData
) => {
  if (!("principal" in receiver))
    throw new UserError("Account identifier not supported");

  if ("Fake" in currencyType) return 0n;
  if (IsDev) await authData.agent.fetchRootKey();

  const canisterId = getLedgerCanisterID(currencyType.Real);

  const ledgerCanister = IcrcLedgerCanister.create({
    agent: authData.agent,
    canisterId,
  });

  const d = await ledgerCanister.allowance({
    spender: {
      owner: receiver.principal,
      subaccount: [],
    },
    account: {
      owner: authData.principal,
      subaccount: [],
    },
  });

  return d.allowance;
};

export const setAllowance = async (
  currencyType: CurrencyType,
  receiver: CurrencyReceiver,
  amount: bigint,
  authData: AuthData,
  expires_at: Date
) => {
  if (!("principal" in receiver))
    throw new UserError("Account identifier not supported");

  if ("Fake" in currencyType) return 0n;

  const canisterId = getLedgerCanisterID(currencyType.Real);

  const ledgerCanister = IcrcLedgerCanister.create({
    agent: authData.agent,
    canisterId,
  });

  return ledgerCanister.approve({
    spender: {
      owner: receiver.principal,
      subaccount: [],
    },
    amount,
    expires_at: DateToBigNanoseconds(expires_at),
  });
};
