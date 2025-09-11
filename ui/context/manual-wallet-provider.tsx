import { memo, ReactNode, useEffect, useState } from 'react';

import { WalletType } from '../components/wallet-type-label/wallet-type-label.component';
import { ManualWalletContext } from '../types/manual-wallet-context';


const MANUAL_WALLET_TYPE_LOCAL_STORAGE_KEY = "manual-wallet-type";

export const ProvideManualWalletContext = memo<{ children: ReactNode }>(
  ({ children }) => {
    const [walletType, setIIWalletType] = useState<WalletType>(
      (localStorage.getItem(
        MANUAL_WALLET_TYPE_LOCAL_STORAGE_KEY,
      ) as WalletType) || "plug",
    );

    useEffect(() => {
      localStorage.setItem(MANUAL_WALLET_TYPE_LOCAL_STORAGE_KEY, walletType);
    }, [walletType]);

    return (
      <ManualWalletContext.Provider
        value={{
          walletType: walletType,
          setWalletType: async (v: WalletType) => setIIWalletType(v),
        }}
      >
        {children}
      </ManualWalletContext.Provider>
    );
  },
);