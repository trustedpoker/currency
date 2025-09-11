import { memo, PropsWithChildren, ReactNode } from 'react';

import { useAuth } from '../../../auth';
import { Currency } from '../../../types';
import { ProvideWalletModalContext } from '../wallet-modal.context';
import { ProvideManualWalletContext } from '../../../context/manual-wallet-provider';
import { Principal } from '@dfinity/principal';
import { encodeSymbolTo8Bytes } from '../../../utils';

export type WalletStoryProviderProps = {
  selectedWallet: 'ICP' | 'ETH' | 'BTC' | 'DCD';
  requiredBalance?: bigint;
};

export const WalletStoryProviderArgTypes = {
  selectedWallet: {
    control: {
      type: 'select',
    },
    options: ['ICP', 'ETH', 'BTC', 'DCD'],
    description: 'Selected wallet type',
    table: {
      type: { summary: 'string' },
      defaultValue: { summary: 'undefined' },
    },
  },
  requiredBalance: {
    control: {
      type: 'number',
      min: 0,
      max: 1000000,
      step: 0.01,
    },
    description: 'Required balance for the wallet',
    table: {
      type: { summary: 'number' },
      defaultValue: { summary: 'undefined' },
    },
  },
};

const BuildProps = (args: WalletStoryProviderProps): { currency: Currency } => {
  let currency: Currency = { ICP: null };

  switch (args.selectedWallet) {
    case 'ETH':
      currency = { CKETHToken: { ETH: null } }
      break;
    case 'BTC':
      currency = { BTC: null }
      break;
    case 'DCD':
      currency = { GenericICRC1: { decimals: 8, ledger_id: Principal.from('xsi2v-cyaaa-aaaaq-aabfq-cai'), symbol: encodeSymbolTo8Bytes('DCD') } }
      break;
  }

  return { currency };
}

export const WalletStoryProvider = memo<PropsWithChildren<WalletStoryProviderProps>>(({ selectedWallet, requiredBalance, children }) => {
  let { currency } = BuildProps({ selectedWallet, requiredBalance });
  const { authData } = useAuth();

  if (!authData)
    return <p>Please select a sign in provicer in storybook</p>

  return (
    <ProvideManualWalletContext>
      <ProvideWalletModalContext
        currency={currency}
        onBack={() => { }}
        onSubmit={() => { }}
        requiredBalance={requiredBalance ? {
          currencyType: { Real: currency },
          currencyValue: requiredBalance * 10n ** 8n,
        } : undefined}
      >
        {children}
      </ProvideWalletModalContext>
    </ProvideManualWalletContext>
  );
});

export const WalletStoryProviderRenderFactory = (Element: (props: { currency: Currency }) => ReactNode) => (props: WalletStoryProviderProps) => <WalletStoryProvider {...props}><Element {...BuildProps(props)} /></WalletStoryProvider>
