import './tailwind.css';

import { useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import React, { memo, PropsWithChildren, useMemo } from 'react';
import { MemoryRouter } from 'react-router-dom';

import { AnonymousIdentity, HttpAgent } from '@dfinity/agent';
import { AccountIdentifier } from '@dfinity/ledger-icp';
import { Principal } from '@dfinity/principal';
import {
  LayoutComponent, ProvideConfirmModal, ProvideErrorModalContext, ProvideQuery, ProvideUI
} from '@zk-game-dao/ui';

import {
  ProvideSiwbLogins
} from '../ui/auth/components/provide-btc-logins/provide-btc-logins.component';
import { AuthClientContext, AuthClientContextData, AuthData } from '../ui/auth/types/context';
import { host } from '../ui/auth/types/iiauth';
import { ProvideCurrencyConfig } from '../ui/context/currency-config.context';
import { EI6963Provider } from '../ui/context/EIP6963-provider';
import { ProvideTokenRegistry } from '../ui/context/token-registry.context';
import { CurrencyNetwork } from '../ui/types/currency-config.context';

import type { Preview } from "@storybook/react";

BigInt.prototype.toJSON = function () {
  return JSON.rawJSON(this.toString());
};

const PreviewAuth = memo<PropsWithChildren<{ authContext: AuthClientContextData }>>(({ children, authContext }) => {
  const siwb = useSiwbIdentity();

  const ctx = useMemo(() => {
    if (!authContext.authData || authContext.authData.type !== 'siwb' || !siwb.identity)
      return authContext;
    return {
      ...authContext,
      authData: {
        ...authContext.authData,
        principal: siwb.identity.getPrincipal(),
        accountIdentifier: AccountIdentifier.fromPrincipal({ principal: siwb.identity.getPrincipal() }),
        identity: siwb.identity,
        agent: HttpAgent.createSync({
          host,
          identity: siwb.identity,
        })
      }
    };
  }, [authContext, siwb]);

  return (
    <AuthClientContext.Provider value={ctx} >
      <EI6963Provider >
        {children}
      </EI6963Provider>
    </AuthClientContext.Provider >
  )

});

const buildAuthData = (method: 'unauthenticated' | 'internet_identity' | 'siwb' = 'unauthenticated'): AuthData | undefined => {
  const principal = Principal.fromText('uyxh5-bi3za-gxbfs-op3gj-ere73-a6jhv-5jky3-zawef-b5r2s-k26un-sae');
  const accountIdentifier = AccountIdentifier.fromPrincipal({ principal });
  switch (method) {
    case 'internet_identity':
      return {
        type: "internet_identity",
        provider: {
          type: 'internet_identity',
        },
        agent: HttpAgent.createSync({
          host: host,
          identity: new AnonymousIdentity(),
        }),
        identity: new AnonymousIdentity(),
        principal,
        accountIdentifier,
      };
    case 'siwb':
      return {
        type: "siwb",
        provider: {
          type: 'siwb',
          provider: 'xverse',
        },
        agent: HttpAgent.createSync({
          host: host,
          identity: new AnonymousIdentity(),
        }),
        identity: new AnonymousIdentity(),
        principal,
        accountIdentifier,
      };
    case 'unauthenticated':
      return undefined;
  }
}

const preview: Preview = {
  globalTypes: {
    authentication: {
      description: 'Login method',
      toolbar: {
        icon: 'user',
        items: [
          {
            value: 'internet_identity',
            title: 'Internet Identity',
          },
          {
            value: 'siwb',
            title: 'SIWB',
          },
          {
            value: 'unauthenticated',
            title: 'Unauthenticated',
          },
        ],
        dynamicTitle: true,
      },
    },
    network: {
      description: 'Platform',
      toolbar: {
        icon: 'platform',
        items: [
          {
            value: 'zkpoker',
            title: 'zkpoker.app',
          },
          {
            value: 'purepoker',
            title: 'purepoker.app',
          }
        ],
        dynamicTitle: true,
      },
    },
  },
  initialGlobals: {
    authentication: 'internet_identity',
    network: 'zkpoker',
  },
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  decorators: [
    (Story, context) => {
      try {

        let _window = window;
        if ('parent' in _window.parent)
          _window = { ..._window, ..._window.parent };
        // if (!_window) {
        //   _window = {} as any;
        // }

        window.XverseProviders = _window.XverseProviders;
        window.wizz = _window.wizz;
        window.sparrow = _window.sparrow;
        window.unisat = _window.unisat;
        window.leather = _window.leather;
        window.phantom = _window.phantom;
        window.okx = _window.okx;
        window.magicEden = _window.magicEden;
        window.orange = _window.orange;
        window.opNet = _window.opNet;
        window.oyl = _window.oyl;
        window.ledger = _window.ledger;
      } catch (e) {
        console.error(e);
      }

      const { network, authentication } = context.globals;

      let disabledNetworks: CurrencyNetwork[] | undefined;
      let enabledNetworks: CurrencyNetwork[] | undefined;

      switch (network) {
        case 'zkpoker':
          disabledNetworks = ['btc'];
          break;
        case 'purepoker':
          enabledNetworks = ['btc'];
          break;
      }

      const authContextValue: AuthClientContextData = {
        authData: buildAuthData(authentication),
        login: async () => { },
        loginFactory: () => async () => { },
        logout: async () => { },
        requireLogin: async () => {
          throw new Error("Require login not implemented");
        },
      };

      return (
        <MemoryRouter>
          <ProvideQuery>
            <LayoutComponent>
              <ProvideConfirmModal>
                <ProvideErrorModalContext>
                  <ProvideUI theme={network}>
                    <ProvideCurrencyConfig
                      disabledNetworks={disabledNetworks}
                      enabledNetworks={enabledNetworks}
                    >
                      <ProvideTokenRegistry>
                        <ProvideSiwbLogins siwbProviderCanisterId={Principal.fromText('j2let-saaaa-aaaam-qds2q-cai')}>
                          <PreviewAuth authContext={authContextValue} >
                            <EI6963Provider >
                              <Story />
                            </EI6963Provider>
                          </PreviewAuth>
                        </ProvideSiwbLogins>
                      </ProvideTokenRegistry>
                    </ProvideCurrencyConfig >
                  </ProvideUI>
                </ProvideErrorModalContext>
              </ProvideConfirmModal>
            </LayoutComponent>
          </ProvideQuery>
        </MemoryRouter>
      );
    },
  ],
};

export default preview;
