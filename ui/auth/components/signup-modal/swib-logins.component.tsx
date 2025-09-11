import { AnimatePresence } from 'framer-motion';
import { memo, useMemo } from 'react';

import { useLaserEyes } from '@omnisat/lasereyes';
import { ProviderType } from '@omnisat/lasereyes-core';
import { ErrorComponent, List, ListItem, LoadingAnimationComponent } from '@zk-game-dao/ui';

import {
  SUPPORTED_WALLETS, SupportedSIWBProvider, SWIB_WALLET_MAPPING, useSiwbLogins
} from '../provide-btc-logins/provide-btc-logins.component';
import classNames from 'classnames';

const useHasWallet = (providerType: SupportedSIWBProvider) => {

  const le = useLaserEyes();

  return useMemo(() => {
    switch (providerType) {
      case 'unisat':
        return !!le?.hasUnisat;
      case 'xverse':
        return !!le?.hasXverse;
      // case 'phantom':
      //   return !!le?.hasPhantom;
      case 'okx':
        return !!le?.hasOkx;
      case 'wizz':
        return !!le?.hasWizz;
      case 'leather':
        return !!le?.hasLeather;
      case 'magic-eden':
        return !!le?.hasMagicEden;
      case 'oyl':
        return !!le?.hasOyl;
      default:
        return false;
    }
  }, [le, providerType]);

}

const SWIBConnect = memo<{
  isPending?: boolean;
  isConnecting?: boolean;
  providerType: SupportedSIWBProvider;
  connect(type: ProviderType): void;
}>(({ isPending, providerType, isConnecting, connect }) => {
  const meta = useMemo(() => SWIB_WALLET_MAPPING[providerType], [providerType]);
  const hasWallet = useHasWallet(providerType);

  if (!meta) return null;

  return (
    <ListItem
      onClick={() => connect(providerType)}
      icon={<div className={classNames("w-6 ml-5 mr-4", { 'opacity-50': !hasWallet })}><meta.Icon size={24} /></div>}
    >
      {isPending || isConnecting ?
        <LoadingAnimationComponent variant="shimmer">
          {isConnecting ? 'Signing into ' : 'Connecting to '}{meta.label}
        </LoadingAnimationComponent> :
        <div className={classNames({ 'opacity-50': !hasWallet })}>
          {meta.label} {!hasWallet && <span className="text-red-500"> (not installed)</span>}
        </div>
      }
    </ListItem>
  )
});

export const SWIBLogins = memo(() => {
  const { identity, connectedBtcAddress, clear, selectedProvider, signInMutation, error, loading } = useSiwbLogins();
  const p = useLaserEyes();

  if (identity)
    return (
      <List>
        <ListItem rightLabel={`${identity.getPrincipal().toText().slice(0, 20)}...`}>Your principal</ListItem>
        {!!connectedBtcAddress && <ListItem rightLabel={`${connectedBtcAddress.slice(0, 20)}...`}>Your pubkey</ListItem>}
        <ListItem onClick={clear}>Disconnect {selectedProvider ?? p.provider}</ListItem>
      </List>
    )

  return (
    <AnimatePresence>
      {signInMutation.error && (
        <ErrorComponent
          error={`Failed to connect to ${signInMutation.variables}. Please check if you have the wallet installed and try again`}
        />
      )}
      <ErrorComponent error={error} />
      <List>
        {SUPPORTED_WALLETS.map((providerType, i) => (
          <SWIBConnect
            key={i}
            isPending={signInMutation.isPending && signInMutation.variables === providerType}
            isConnecting={(loading && (selectedProvider ?? p.provider ?? signInMutation.variables) === providerType)}
            providerType={providerType}
            connect={signInMutation.mutateAsync}
          />
        ))}
      </List>
    </AnimatePresence>
  )
});
