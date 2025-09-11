import { useMutation, usePersistentState, UserError, useToast } from '@zk-game-dao/ui';
import { memo, ReactNode, useEffect, useState } from 'react';

import { useAuth } from '../auth/types/context';
import { buildChainFusionActor, ChainFusionContext, TransactionHashMap } from '../types/chain-fusion.context';
import { Currency } from '../types/currency';
import { useEIP6963 } from '../types/EIP6963.context';
import { CurrencySerializer } from '../utils/serialize';

const CHAIN_FUSION_NATIVE_WALLET_STORAGE_KEY = "chain-fusion-show-native";
const CHAIN_FUSION_NATIVE_TRANSACTION_DEPOSITS_KEY = "chain-fusion-transaction-deposits";
const CHAIN_FUSION_NATIVE_TRANSACTION_WITHDRAWALS_KEY = "chain-fusion-transaction-withdrawals";

export type ChainFusionTransferProps = { currency: Currency; amount: bigint };

export const ProvideChainFusionContext = memo<{ children: ReactNode }>(
  ({ children }) => {
    const [isNativeShown, setIsNativeShown] = useState<boolean>((localStorage.getItem(CHAIN_FUSION_NATIVE_WALLET_STORAGE_KEY) ?? 'true') === 'true');
    const [depostTransactionsHashes, setDepositTransactionHashes] = usePersistentState<TransactionHashMap>(CHAIN_FUSION_NATIVE_TRANSACTION_DEPOSITS_KEY, {});
    const [withdrawalTransactionsHashes, setWithdrawalTransactionHashes] = usePersistentState<TransactionHashMap>(CHAIN_FUSION_NATIVE_TRANSACTION_WITHDRAWALS_KEY, {});
    const eip = useEIP6963();
    const { authData } = useAuth();

    useEffect(() => {
      localStorage.setItem(CHAIN_FUSION_NATIVE_WALLET_STORAGE_KEY, isNativeShown ? 'true' : 'false');
    }, [isNativeShown]);

    const { addToast } = useToast();

    // const chainFusionActorFactory = useChainFusionActorFactory();

    const withdraw = useMutation({
      mutationFn: async ({ currency, amount }: ChainFusionTransferProps): Promise<string | null> => {
        if (!amount) throw new UserError("No amount to withdraw found");
        const c = await buildChainFusionActor(currency, eip.selectedWallet, eip.selectedAccount, authData);
        const txid = await c.withdraw(amount);
        if (typeof txid === 'string') return txid;
        return null;
      },
      onSuccess: (hash, { currency }) => {
        if (hash)
          setWithdrawalTransactionHashes({
            ...withdrawalTransactionsHashes,
            [CurrencySerializer.serialize(currency)]: [...(withdrawalTransactionsHashes[CurrencySerializer.serialize(currency)] ?? []), hash],
          });
        addToast({
          children: (
            <>
              <p>Withdrawal successful</p>
              {hash && (
                <p>
                  <a href={`https://ic.rocks/transaction/${hash}`} target="_blank" rel="noopener noreferrer">
                    View on ic.rocks
                  </a>
                </p>
              )}
            </>
          ),
        });
      },
    });

    const deposit = useMutation({
      mutationFn: async ({ currency, amount }: ChainFusionTransferProps): Promise<string | null> => {
        if (!amount) throw new UserError("No amount to deposit found");
        const c = await buildChainFusionActor(currency, eip.selectedWallet, eip.selectedAccount, authData);
        const tx = await c.deposit(amount);
        if (typeof tx === 'string') return tx;
        return null;
      },
      onSuccess: (txid, { currency }) => {
        if (txid)
          setDepositTransactionHashes({
            ...depostTransactionsHashes,
            [CurrencySerializer.serialize(currency)]: [...(depostTransactionsHashes[CurrencySerializer.serialize(currency)] ?? []), txid],
          });

        addToast({
          children: <p>Deposit successful</p>,
        });
      },
    });

    return (
      <ChainFusionContext.Provider
        value={{
          isNativeShown,
          setIsNativeShown,
          depostTransactionsHashes,
          withdrawalTransactionsHashes,
          deposit: async (currency, amount) => { await deposit.mutateAsync({ currency, amount }); },
          withdraw: async (currency, amount) => { await withdraw.mutateAsync({ currency, amount }); },
        }}
      >
        {children}
      </ChainFusionContext.Provider>
    );
  },
);
