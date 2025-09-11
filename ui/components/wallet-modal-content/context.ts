import { type UseMutationResult } from "@tanstack/react-query/build/legacy/types";
import { createContext, ReactNode, useContext } from "react";

import { AuthData } from "../../auth/types";
import { Currency } from "../../types";
import { CryptoCoinValue } from "../currency/currency.component";
import { WalletType } from "../wallet-type-label/wallet-type-label.component";

export type ModalProps = {
  onBack(): void;
  requiredBalance?: CryptoCoinValue;
  label?: ReactNode;
  onSubmit?(newBalance: bigint): void;
};

export type WalletModalMode = "withdraw" | "deposit";

export type WalletModalContentContextType = {
  deposit: UseMutationResult<void, Error, void, unknown>;
  withdraw: UseMutationResult<void, Error, void, unknown>;
  continueMutation: UseMutationResult<void, Error, void, unknown>;

  currency?: Currency;
  authData: AuthData;

  web3WalletType: WalletType | "external";
  setWeb3WalletType(walletType: WalletType | "external"): void;

  web3WithdrawExternalWalletAddress: string;
  setWeb3WithdrawExternalWalletAddress(address: string): void;

  mode: WalletModalMode;
  setMode(mode: WalletModalMode): void;

  amount: bigint;
  setAmount(amount: bigint): void;
} & Pick<ModalProps, "requiredBalance">;

export const WalletModalContentContext =
  createContext<WalletModalContentContextType>(null as any);

export const useWalletModalContentContext = () =>
  useContext(WalletModalContentContext);
