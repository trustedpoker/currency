import { IDL } from '@dfinity/candid';
import { AccountIdentifier } from '@dfinity/ledger-icp';
import { idlFactory as icpIDLFactory } from '@dfinity/ledger-icp/dist/candid/ledger.idl';
import { idlFactory as icrcIDLFactory } from '@dfinity/ledger-icrc/dist/candid/icrc_ledger.idl';
import { Principal } from '@dfinity/principal';
import { IC_HOST, useMutation, UserError, useToast, WalletTypeNotInstalledError } from '@zk-game-dao/ui';
import { createContext, useContext } from 'react';

import { CurrencyTypeSymbolComponent } from '../components/currency-type/currency-type.component';
import { CurrencyComponent } from '../components/currency/currency.component';
import { WalletType } from '../components/wallet-type-label/wallet-type-label.component';
import { useTransactionFee } from '../hooks/transaction-fee';
import { Queries } from '../queries';
import { CurrencyTypeToString } from '../utils/currency-type-to-string';
import { Currency, CurrencyType } from './currency';
import { getLedgerCanisterID } from '../utils/manager';

// Define the structure of the transaction object
type TransferIcpTx = {
  idl: IDL.InterfaceFactory;
  canisterId: string;
  methodName: "send_dfx";
  args: {
    to: string;
    fee: { e8s: bigint };
    amount: { e8s: bigint };
    memo: bigint;
    from_subaccount: bigint[] | [];
    created_at_time: [] | { timestamp_nanos: bigint }[];
  }[];
  onSuccess: (res: bigint) => Promise<void>;
  onFail: (e: any) => Promise<void>;
};

type TransferIcrcTx = {
  idl: IDL.InterfaceFactory;
  canisterId: string;
  methodName: "icrc1_transfer";
  args: {
    to: {
      owner: Principal;
      subaccount: Principal[];
    };
    amount: bigint;
    memo: number[];
    fee: [bigint];
    from_subaccount: [];
    created_at_time: [];
  }[];
  onSuccess: (res: bigint) => Promise<void>;
  onFail: (e: any) => Promise<void>;
};
type TransferParams = TransferIcrcTx | TransferIcpTx;

type Wallet = {
  isConnected: () => Promise<boolean>;
  requestConnect: (options?: {
    host?: string;
    whitelist?: string[];
  }) => Promise<void>;
  batchTransactions: (params: TransferParams[]) => Promise<void>;
  getPrincipal: () => Promise<Principal>;
  getBalance: () => Promise<bigint>;
  createActor(options: {
    canisterId: Principal;
    interfaceFactory: typeof icpIDLFactory | typeof icrcIDLFactory;
  }): Promise<any>;
};

declare global {
  interface Window {
    ic: { [key in WalletType]: Wallet };
    phantom?: {
      solana?: {
        isPhantom: boolean;
        connect: () => Promise<void>;
      }
    }
  }
}

const host = IC_HOST;

type ManualWalletContextType = {
  walletType?: WalletType;

  setWalletType(v: WalletType): void;
};

export const ManualWalletContext = createContext<ManualWalletContextType>({
  setWalletType: () => { },
});

const getCurrencySpecificData = (currency: Currency, destination: Principal) => {
  if ('ICP' in currency)
    return {
      methodName: "send_dfx",
      idl: icpIDLFactory,
      destination: AccountIdentifier.fromPrincipal({
        principal: destination,
      }).toHex(),
    };
  return {
    methodName: "icrc1_transfer",
    idl: icrcIDLFactory,
    destination,
  };
};

export const useManualWallet = () => useContext(ManualWalletContext);
export const useManualWalletTransfer = (
  currencyType: CurrencyType,
  to?: Principal,
  action?: string,
) => {
  const { walletType } = useManualWallet();
  const transactionFee = useTransactionFee(currencyType);
  const { addToast } = useToast();

  return useMutation({
    mutationFn: async (amount: bigint) => {
      if (!walletType) throw new UserError("Wallet not found");

      if (!('ic' in window) || !(walletType in window.ic))
        throw new WalletTypeNotInstalledError(walletType);

      // Connect to the wallet
      switch (walletType) {
        case "plug":
        case "bitfinityWallet":
          console.log("Connected ing..", walletType);
          try {
            if (!(await window.ic[walletType].isConnected()))
              await window.ic[walletType].requestConnect();
          } catch (e) {
            console.error("Error connecting to wallet", e);
            throw new UserError("Failed to connect to wallet. Please try again.");
          }
          break;
        default:
          throw new UserError(`${CurrencyTypeToString(currencyType)} not supported by ${walletType}`);
      }


      if (!(await window.ic[walletType].isConnected()))
        await window.ic[walletType].requestConnect({ host });

      return await new Promise<bigint>((resolve, reject) => {
        if (!to) return reject("No destination principal found");

        if ('Fake' in currencyType) throw new UserError("Cannot transfer fake currency");

        const { methodName, idl, destination } = getCurrencySpecificData(currencyType.Real, to);
        const canisterId = getLedgerCanisterID(currencyType.Real).toText();

        let args: Record<string, unknown>[] = []
        if ('ICP' in currencyType.Real) {
          args = [{
            to: AccountIdentifier.fromPrincipal({
              principal: to,
            }).toHex(),
            fee: { e8s: transactionFee },
            amount: { e8s: amount },
            memo: BigInt(0),
            from_subaccount: [],
            created_at_time: [
              { timestamp_nanos: BigInt(Date.now()) * 1_000_000n },
            ],
          }];
        } else {
          args = [{
            to: {
              owner: to,
              subaccount: [],
            },
            fee: [transactionFee],
            amount: amount,
            memo: [],
            from_subaccount: [],
            created_at_time: [BigInt(Date.now()) * 1_000_000n],
          }];
        }

        try {
          window.ic[walletType].batchTransactions([{
            idl,
            canisterId,
            methodName: methodName as any,
            args: args as any,
            onSuccess: async (res) => {
              if (typeof res === 'object' && 'Err' in res)
                return reject((res as any).Err);
              console.log("Transfer successful", res);
              resolve(res)
            },
            onFail: async (e) => {
              console.log("Somehow failed", e);
              reject(
                new UserError(
                  "Transfer failed. Please check your balance and try again.",
                ),
              );
            },
          }]);
        }
        catch (e) {
          console.error("Error during transfer", e);
          reject(new UserError("Transfer failed. Please try again later."));
        }
      });
    },
    onSuccess: (_, amount) => {
      Queries._balanceModalBalance.invalidate(currencyType);
      addToast({
        children: (
          <>
            <span className="flex flex-row mr-1">
              <CurrencyComponent currencyType={currencyType} variant="inline" currencyValue={amount} />
            </span>
            <CurrencyTypeSymbolComponent currencyType={currencyType} />
            {` ${action ?? "has been transferred"}`}
          </>
        ),
      });
    },
  });
};
