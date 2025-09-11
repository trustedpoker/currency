import { SiwbIdentityProvider, useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import { createContext, FC, memo, PropsWithChildren, useContext, useEffect, useState } from 'react';

import { DelegationIdentity } from '@dfinity/identity';
import { Principal } from '@dfinity/principal';
import {
  LaserEyesProvider, LeatherLogo, MagicEdenLogo, OkxLogo, OylLogo, PhantomLogo, UnisatLogo,
  useLaserEyes, WizzLogo, XverseLogo
} from '@omnisat/lasereyes';
import {
  LEATHER, MAGIC_EDEN, MAINNET, OKX, OYL, PHANTOM, ProviderType, UNISAT, WIZZ, XVERSE
} from '@omnisat/lasereyes-core';
import { UseMutationResult } from '@tanstack/react-query';
import { IsDev, useMutation, useToast } from '@zk-game-dao/ui';

import { idlFactory as siwbIdl } from '../../../../declarations/ic_siwb_provider';
import { useIsBTC } from '../../../context';

import type { _SERVICE as siwbService } from '../../../../declarations/ic_siwb_provider/ic_siwb_provider.did';
import { useSiwbLoginFlow } from './use-siwb-login-flow.hook';
export const SUPPORTED_WALLETS = [
  UNISAT,
  XVERSE,
  // PHANTOM,
  OKX,
  WIZZ,
  LEATHER,
  MAGIC_EDEN,
  OYL
] as const;
export type SupportedSIWBProvider = (typeof SUPPORTED_WALLETS)[number];

type LogoProps = React.SVGProps<SVGSVGElement> & {
  size?: number;
  variant?: 'first' | 'second';
}

export const SWIB_WALLET_MAPPING: Record<SupportedSIWBProvider, { Icon: FC<LogoProps>; label: string; }> = {
  [UNISAT]: {
    Icon: memo(UnisatLogo),
    label: "Unisat",
  },
  [WIZZ]: {
    Icon: memo(WizzLogo),
    label: "Wizz",
  },
  [XVERSE]: {
    Icon: memo(XverseLogo),
    label: "Xverse",
  },
  // [PHANTOM]: {
  //   Icon: memo(PhantomLogo),
  //   label: "Phantom",
  // },
  [OKX]: {
    Icon: memo(OkxLogo),
    label: "OKX",
  },
  [LEATHER]: {
    Icon: memo(LeatherLogo),
    label: "Leather",
  },
  [MAGIC_EDEN]: {
    Icon: memo(MagicEdenLogo),
    label: "Magic Eden",
  },
  [OYL]: {
    Icon: memo(OylLogo),
    label: "Oyl",
  },
};

type SIWBContextType = {
  identity?: DelegationIdentity;
  connectedBtcAddress?: string;
  clear(): void;
  selectedProvider?: ProviderType;
  signInMutation: UseMutationResult<void, Error, ProviderType, unknown>;
  loading: boolean;
  error?: unknown;
};

const SIWBContext = createContext<SIWBContextType>({
  loading: false,
  clear: () => { },
  signInMutation: {} as UseMutationResult<void, Error, ProviderType, unknown>,
});

const RequiredSIWBLoginsProvider = memo<PropsWithChildren<{}>>(({ children }) => {
  const { addToast } = useToast();
  const p = useLaserEyes();
  const {
    selectedProvider,
    identity,
    connectedBtcAddress,
    clear,
    setLaserEyes
  } = useSiwbIdentity();

  const { prepareQuery, loginQuery, manuallyTrigger } = useSiwbLoginFlow();

  const signInMutation = useMutation({
    mutationFn: async (providerType: ProviderType) => {
      manuallyTrigger();
      return setLaserEyes(p, providerType);
    }
  });

  useEffect(() => {
    if (loginQuery.isSuccess) {
      addToast({ children: "Connected to your wallet" });
    }
  }, [loginQuery.isSuccess]);

  return (
    <SIWBContext.Provider
      value={{
        identity,
        connectedBtcAddress,
        clear,
        selectedProvider,
        signInMutation,
        loading: prepareQuery.isLoading || loginQuery.isLoading,
        error: prepareQuery.error || loginQuery.error,
      }}
    >
      {children}
    </SIWBContext.Provider>
  );
});

export const ProvideSiwbLogins = memo<PropsWithChildren<{
  siwbProviderCanisterId: Principal;
}>>(({ children, siwbProviderCanisterId }) => {
  const isBTC = useIsBTC();
  return (
    <LaserEyesProvider config={{ network: MAINNET }}>
      <SiwbIdentityProvider<siwbService>
        canisterId={siwbProviderCanisterId.toText()}
        idlFactory={siwbIdl}
        httpAgentOptions={{ host: !IsDev ? 'https://icp0.io' : 'http://127.0.0.1:4943' }} // use only in local canister
      >
        {!isBTC ? <>{children}</> :
          (
            <RequiredSIWBLoginsProvider>
              {children}
            </RequiredSIWBLoginsProvider>
          )}
      </SiwbIdentityProvider>
    </LaserEyesProvider>
  )
},
  (prevProps, nextProps) =>
    prevProps.siwbProviderCanisterId.compareTo(nextProps.siwbProviderCanisterId) === 'eq' &&
    prevProps.children === nextProps.children
);

export const useSiwbLogins = () => useContext(SIWBContext);
