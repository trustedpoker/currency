import { createContext, memo, PropsWithChildren } from 'react';

import { useQuery } from '@tanstack/react-query';

import { useAuth } from '../auth';
import { useBTCMinter } from '../hooks/btc';
import { useIsBTC } from './currency-config.context';

export type BTCContextType = {
  updateBalance(): Promise<void>;
};

const BTCContext = createContext<BTCContextType>({
  updateBalance: async () => { },
});

// Seperate so that the hooks are not called when not needed
const Provide = memo<PropsWithChildren<{}>>(({ children }) => {
  const { authData } = useAuth();
  const minter = useBTCMinter();

  const updateBalanceQuery = useQuery({
    queryKey: ["btc", "updateBalance"],
    queryFn: () => minter.updateBalance({
      owner: authData?.principal,
    }),
    refetchInterval: 60000, // 1 minute
    enabled: !!authData?.principal,
  });

  return (
    <BTCContext.Provider
      value={{
        updateBalance: async () => { await updateBalanceQuery.refetch() },
      }}
    >
      {children}
    </BTCContext.Provider>
  );
})

export const ProvideBTC = memo<PropsWithChildren<{}>>(
  ({ children }) => !useIsBTC() ? children : <Provide>{children}</Provide>);