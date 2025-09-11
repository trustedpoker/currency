import { memo, PropsWithChildren, useEffect, useMemo, useState } from 'react';

import { AccountIdentifier } from '@dfinity/ledger-icp';
import { Principal } from '@dfinity/principal';
import {
  IC_HOST, useConfirmModal, useIsMobile, useMutation, usePersistentState, UserError, useToast
} from '@zk-game-dao/ui';

import { useAuth } from '../../auth/types/context';
import { useBalance } from '../../hooks/balance';
import { useTransactionFee } from '../../hooks/transaction-fee';
import { Queries } from '../../queries';
import { useChainFusion, useShowingNativeCurrency } from '../../types/chain-fusion.context';
import { Currency, CurrencyReceiver } from '../../types/currency';
import { buildCurrencyManager } from '../../utils/manager/manager-map';
import { useManualWallet, useManualWalletTransfer } from '../../types/manual-wallet-context';
import { CurrencyToString, CurrencyTypeToString } from '../../utils/currency-type-to-string';
import { TokenAmountToString } from '../../utils/token-amount-conversion';
import { transferTo } from '../../utils/transfer';
import { CurrencyComponent } from '../currency/currency.component';
import { WalletType } from '../wallet-type-label/wallet-type-label.component';
import { ModalProps, WalletModalContentContext } from './context';
import { fetchBalance } from '../../utils/balance';

const host = IC_HOST;

export const ProvideWalletModalContext = memo<PropsWithChildren<ModalProps & { currency?: Currency; }>>(({ onBack, onSubmit, requiredBalance, children, currency }) => {
  const { authData } = useAuth();

  const { addToast } = useToast();
  const manual = useManualWallet();
  const depositToZKPFromManual = useManualWalletTransfer(
    (currency ? { Real: currency } : { Fake: null }),
    authData?.principal,
  );

  const [amount, setAmount] = useState<bigint>(0n);

  const isMobile = useIsMobile();

  const [_mode, setMode] = useState<"withdraw" | "deposit">(
    isMobile ? "withdraw" : "deposit",
  );
  const mode = useMemo(
    () => (requiredBalance ? "deposit" : _mode),
    [_mode, requiredBalance],
  );
  const transactionFee = useTransactionFee(currency ? { Real: currency } : { Fake: null });

  const [web3WalletType, setWeb3WalletType] = usePersistentState<
    WalletType | "external"
  >("web3-wallet-type", manual.walletType ?? "plug");
  const [
    web3WithdrawExternalWalletAddress,
    setWeb3WithdrawExternalWalletAddress,
  ] = usePersistentState("web3-preferredWithdrawExternalWalletAddress", "");

  const isShowingEthCurrency = useShowingNativeCurrency(currency ? currency : { ICP: null });

  useEffect(() => {
    if (!isMobile) return;
    setWeb3WalletType("external");
    setMode("withdraw");
  }, [isMobile]);

  useEffect(() => {
    if (web3WalletType === "external") return;
    manual.setWalletType(web3WalletType);
  }, [web3WalletType]);

  const walletBalance = useBalance(currency ? { Real: currency } : { Fake: null });
  const confirm = useConfirmModal();
  const chainFusion = useChainFusion();

  const withdraw = useMutation({
    mutationFn: async () => {
      if (!authData) throw new UserError("No auth data found");
      if (!amount) throw new UserError("No amount to withdraw found");
      if (!currency) throw new UserError("No currency found");

      if ('Fake' in currency)
        throw new UserError("Cannot withdraw fake currency");

      if (isShowingEthCurrency)
        return await chainFusion.withdraw(currency, amount);

      if (!web3WalletType) throw new UserError("No wallet type found");

      let receiver: CurrencyReceiver | undefined;

      let principal: Principal | undefined;
      let accountIdentifier: AccountIdentifier | undefined;

      switch (web3WalletType) {
        case "external":
          if (!web3WithdrawExternalWalletAddress)
            throw new UserError("No external wallet address value found");
          if (web3WithdrawExternalWalletAddress.indexOf('-') === -1) {
            if (!('ICP' in currency))
              throw new UserError(
                "External wallet address must be a principal for ICRC transfers",
              );
            accountIdentifier = AccountIdentifier.fromHex(web3WithdrawExternalWalletAddress);
          }
          else
            principal = Principal.fromText(web3WithdrawExternalWalletAddress);
          break;
        default:
          if (!(await window.ic[web3WalletType].isConnected()))
            await window.ic[web3WalletType].requestConnect({ host });
          principal = await window.ic[web3WalletType].getPrincipal();
          break;
      }

      if (principal) receiver = { principal };
      else if (accountIdentifier) receiver = { accountIdentifier };
      else
        throw new UserError("No principal or account identifier found");

      if (!receiver) throw new UserError("No receiver found");

      const { meta } = await buildCurrencyManager(authData.agent, currency);

      try {
        await transferTo({ Real: currency }, receiver, amount, authData);
      } catch (e) {
        if (e instanceof UserError) throw e;
        throw new UserError(
          `Transfer failed. Please check your balance and try again. (Transaction fee is ${TokenAmountToString(
            transactionFee,
            meta,
          )} ${CurrencyToString(currency)})`,
        );
      }
    },
    onSuccess: () => {
      if (!currency) throw new UserError("No currency found");
      Queries._balanceModalBalance.invalidate({ Real: currency });
      Queries.walletBalance.invalidate({ Real: currency }, authData);
      addToast({
        children: (
          <>
            <span className="flex flex-row mr-1">
              <CurrencyComponent currencyType={{ Real: currency }} variant="inline" currencyValue={amount} />
            </span>
            {` ${CurrencyToString(currency)} has been withdrawn from your ZKP wallet`}
          </>
        ),
      });
    },
  });

  const deposit = useMutation({
    mutationFn: async () => {
      if (!authData) throw new UserError("No auth data found");
      if (!amount) throw new UserError("No amount to deposit found");
      if (!currency) throw new UserError("No currency found");

      if (isShowingEthCurrency)
        return await chainFusion.deposit(currency, amount);

      if (web3WalletType === "external")
        throw new UserError(
          "If manually depositing to an external wallet, please use the external wallet deposit form",
        );
      await depositToZKPFromManual.mutateAsync(amount);
    },
    onSuccess: () => {
      if (!currency) throw new UserError("No currency found");
      Queries.walletBalance.invalidate({ Real: currency }, authData);
      Queries._balanceModalBalance.invalidate({ Real: currency });
    },
  });

  const continueMutation = useMutation({
    mutationFn: async () => {
      if (!onSubmit || !authData) return;
      let balance = walletBalance ?? 0n;
      if (!currency) throw new UserError("No currency found");
      const manager = await buildCurrencyManager(authData.agent, currency);
      if (web3WalletType !== "external") {
        await deposit.mutateAsync();
        balance = await fetchBalance({ Real: currency }, authData)
      }
      if (requiredBalance && requiredBalance.currencyValue && requiredBalance.currencyValue > balance)
        throw new UserError(
          `Insufficient balance.\nA balance of ${TokenAmountToString(
            requiredBalance.currencyValue,
            manager.meta,
          )} ${CurrencyTypeToString(requiredBalance.currencyType)} is required to continue.`,
        );
      return onSubmit(balance);
    },
    onSuccess: () => {
      if (onSubmit) onSubmit(requiredBalance?.currencyValue ?? 0n);
      else onBack();
    },
  });

  if (!authData) return <p>No principal or account found</p>;

  return (
    <WalletModalContentContext.Provider
      value={{
        deposit,
        withdraw,
        continueMutation,

        currency,
        authData,

        web3WalletType,
        setWeb3WalletType,

        web3WithdrawExternalWalletAddress,
        setWeb3WithdrawExternalWalletAddress,

        mode,
        setMode,

        amount,
        setAmount,

        requiredBalance,
      }}
    >
      {children}
    </WalletModalContentContext.Provider>
  );
});
