import { memo, PropsWithChildren, ReactNode } from 'react';

import { useEnabledNetworks } from '../../context';
import { CurrencyNetwork } from '../../types/currency-config.context';

export const NetworkGuardComponent = memo<PropsWithChildren<{
  /** What should be rendered if the network is not inculded in the params */
  fallback?: ReactNode;
  network: CurrencyNetwork;
}>>(({
  children,
  fallback,
  network,
}) => {
  const _enabledNetworks = useEnabledNetworks();

  if (_enabledNetworks.some(enabledNetwork => enabledNetwork === network))
    return children || null;

  return fallback || null;
});
