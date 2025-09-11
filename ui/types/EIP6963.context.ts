import { createContext, useContext } from "react";


// Describes metadata related to a provider based on EIP-6963.
export interface EIP6963ProviderInfo {
  rdns: string;
  uuid: string;
  name: string;
  icon: string;
}

// Represents the structure of a provider based on EIP-1193.
export interface EIP1193Provider {
  isStatus?: boolean;
  host?: string;
  path?: string;
  sendAsync?: (
    request: { method: string; params?: Array<unknown> },
    callback: (error: Error | null, response: unknown) => void
  ) => void;
  send?: (
    request: { method: string; params?: Array<unknown> },
    callback: (error: Error | null, response: unknown) => void
  ) => void;
  request: (request: {
    method:
      | "eth_sendTransaction"
      | "eth_requestAccounts"
      | "eth_getTransactionCount"
      | "wallet_revokePermissions";
    params?: Array<unknown>;
  }) => Promise<unknown>;
}

// Combines the provider's metadata with an actual provider object, creating a complete picture of a
// wallet provider at a glance.
export interface EIP6963ProviderDetail {
  info: EIP6963ProviderInfo;
  provider: EIP1193Provider;
}

// Represents the structure of an event dispatched by a wallet to announce its presence based on EIP-6963.
export type EIP6963AnnounceProviderEvent = {
  detail: {
    info: EIP6963ProviderInfo;
    provider: Readonly<EIP1193Provider>;
  };
};

// An error object with optional properties, commonly encountered when handling eth_requestAccounts errors.
export interface WalletError {
  code?: string;
  message?: string;
}


// Context interface for the EIP-6963 provider.
export interface WalletProviderContext {
  wallets: Record<string, EIP6963ProviderDetail>; // A list of wallets.
  selectedWallet: EIP6963ProviderDetail | null; // The selected wallet.
  selectedAccount: string | null; // The selected account address.
  errorMessage: string | null; // An error message.
  connectWallet: (walletUuid: string) => Promise<void>; // Function to connect wallets.
  disconnectWallet: () => void; // Function to disconnect wallets.
  clearError: () => void;
}

declare global {
  interface WindowEventMap {
    "eip6963:announceProvider": CustomEvent;
  }
}

export const EIP6963ProviderContext = createContext<WalletProviderContext>(
  null as any
);

export const useEIP6963 = () => useContext(EIP6963ProviderContext);

export const formatBalance = (rawBalance: string) => {
  const balance = (parseInt(rawBalance) / 1000000000000000000).toFixed(2);
  return balance;
};
// '0x2386F26FC10000', // 0.01 ETH in wei (hex)
export const toWeiHex = (amount: number) => {
  const wei = amount * 1000000000000000000;
  return wei.toString(16);
};
