import { createContext, memo, PropsWithChildren, useCallback, useContext, useMemo } from 'react';

import { CURRENCY_NETWORKS, CurrencyConfigContextType, CurrencyNetwork } from '../types/currency-config.context';
import { usePersistentState } from '@zk-game-dao/ui';
import { Currency } from '../types';
import { CurrencySerializer } from '../utils';

const CurrencyConfigContext = createContext<CurrencyConfigContextType>({
  enabledNetworks: [],
  selectedCurrency: { ICP: null },
  setSelectedCurrency: () => { },
  isBTC: false,
});

export const ProvideCurrencyConfig = memo<PropsWithChildren<{ enabledNetworks?: CurrencyNetwork[]; disabledNetworks?: CurrencyNetwork[] }>>(
  ({ children, enabledNetworks: _enabledNetworks, disabledNetworks }) => {

    const enabledNetworks = useMemo((): CurrencyNetwork[] => {
      let networks: CurrencyNetwork[] = [...(_enabledNetworks || [...CURRENCY_NETWORKS])];
      if (!disabledNetworks) return networks;
      return networks.filter(network => disabledNetworks.findIndex(disabledNetwork => disabledNetwork === network) === -1);
    }, [_enabledNetworks, disabledNetworks]);

    const isBTC = useMemo(() => getIsBTC(enabledNetworks), [enabledNetworks]);

    const [_selectedCurrency, _setSelectedCurrency] = usePersistentState<string>(
      'selectedCurrency',
      CurrencySerializer.serialize(isBTC ? { BTC: null } : { ICP: null }),
    );

    const selectedCurrency = useMemo(() => isBTC ? { BTC: null } : CurrencySerializer.deserialize(_selectedCurrency), [_selectedCurrency, isBTC]);
    const setSelectedCurrency = useCallback((currency: Currency) => {
      if (isBTC) return;
      _setSelectedCurrency(CurrencySerializer.serialize(currency));
    }, [_setSelectedCurrency, isBTC]);

    return (
      <CurrencyConfigContext.Provider value={{ isBTC, enabledNetworks, selectedCurrency, setSelectedCurrency }}>
        {children}
      </CurrencyConfigContext.Provider>
    )
  });

export const useCurrencyConfig = () => useContext(CurrencyConfigContext);

export const useEnabledNetworks = () => {
  const ctx = useCurrencyConfig();
  return useMemo(() => ctx.enabledNetworks, [ctx.enabledNetworks]);
};

export const getIsBTC = (enabledNetworks: CurrencyNetwork[]) => enabledNetworks.length === 1 && enabledNetworks.includes('btc');

// This is a temporary solution
export const useIsBTC = () => {
  const isBTC = useCurrencyConfig().isBTC;
  return useMemo(() => isBTC, [isBTC]);
};

export const useSelectedCurrency = () => {
  const { selectedCurrency } = useCurrencyConfig();
  return useMemo(() => selectedCurrency, [CurrencySerializer.serialize(selectedCurrency)]);
};

export const useSetSelectedCurrency = () => {
  const { setSelectedCurrency } = useCurrencyConfig();
  return useCallback((currency: Currency) => setSelectedCurrency(currency), [setSelectedCurrency]);
};
