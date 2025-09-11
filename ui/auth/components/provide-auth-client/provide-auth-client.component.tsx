import { Buffer } from 'buffer';
import { useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import { memo, PropsWithChildren, useEffect, useMemo, useState } from 'react';

import { HttpAgent } from '@dfinity/agent';
import { AuthClient } from '@dfinity/auth-client';
import { Ed25519KeyIdentity } from '@dfinity/identity';
import { AccountIdentifier } from '@dfinity/ledger-icp';
import { useLaserEyes } from '@omnisat/lasereyes';
import { WALLET_ADAPTERS } from '@web3auth/base';
import { DateToBigIntTimestamp, IsDev, useMutation, useQuery } from '@zk-game-dao/ui';

import { Queries } from '../../../queries';
import { AuthClientContext, AuthClientContextData, AuthData, Providers } from '../../types/context';
import { host, IIHost } from '../../types/iiauth';
import { web3auth, Web3AuthLoginProvider } from '../../types/web3auth';
import { SupportedSIWBProvider } from '../provide-btc-logins/provide-btc-logins.component';
import { SignupModalComponent } from '../signup-modal/signup-modal.component';

export const ProvideAuthClient = memo<PropsWithChildren>(({ children }) => {
  const [{ web3AuthProvider, internetIdentityProvider }, setWeb3AuthProvider] =
    useState<Providers>({});

  const siwb = useSiwbIdentity();
  const laserEyes = useLaserEyes();

  const [showLoginModal, setShowLoginModal] = useState<{ onSuccess: (data: AuthData) => void; onError: (error: Error) => void }>();

  useEffect(() => {
    const init = async () => {
      const d: Providers = {};
      try {
        await web3auth.init();
        d.web3AuthProvider = web3auth.provider ?? undefined;
      } catch (error) {
        console.error(error);
      }

      try {
        d.internetIdentityProvider = await AuthClient.create({
          idleOptions: { disableIdle: IsDev, idleTimeout: 24 * 60 * 60 * 1000 },
        });
      } catch (error) {
        console.error(error);
      }

      setWeb3AuthProvider(d);
    };

    init();
  }, []);

  const { data: authData = null } = useQuery({
    queryKey: Queries.auth.key({
      siwb,
      laserEyes,
      internetIdentityProvider,
    }),
    queryFn: async (): Promise<AuthData | null> => {
      if (siwb.identity && siwb.identity.getDelegation().delegations.every(v => v.delegation.expiration > DateToBigIntTimestamp(new Date()))) {

        const agent = HttpAgent.createSync({ identity: siwb.identity, host: host });

        // Fetch root key only in development to bypass certificate validation
        if (IsDev) await agent.fetchRootKey();

        return {
          type: "siwb",
          provider: { type: 'siwb', provider: laserEyes.provider as SupportedSIWBProvider },
          agent,
          identity: siwb.identity,
          principal: siwb.identity.getPrincipal(),
          accountIdentifier: AccountIdentifier.fromPrincipal({
            principal: siwb.identity.getPrincipal(),
          }),
        };
      }
      // Try to log in with internet identity
      try {
        if (!internetIdentityProvider)
          throw new Error("Internet Identity provider not initialized");
        if (!(await internetIdentityProvider.isAuthenticated()))
          throw new Error("Not authenticated");

        const identity = await internetIdentityProvider.getIdentity();
        const agent = HttpAgent.createSync({ identity, host: host });

        // Fetch root key only in development to bypass certificate validation
        if (IsDev) await agent.fetchRootKey();

        const principal = identity.getPrincipal();
        const accountIdentifier = AccountIdentifier.fromPrincipal({
          principal,
        });

        return {
          type: "internet_identity",
          provider: { type: 'internet_identity' },
          principal,
          identity,
          accountIdentifier,
          agent,
        };
      } catch (error) {
        console.error(error);
      }

      if (!web3AuthProvider) return null;

      try {
        const userInfo = await web3auth.getUserInfo();
        const privateKey = await web3AuthProvider.request({ method: "private_key" });

        // Convert the hex private key to a Buffer
        const privateKeyBuffer = Buffer.from(privateKey as any, "hex");

        // Convert Buffer to ArrayBuffer
        const privateKeyArrayBuffer = privateKeyBuffer.buffer.slice(
          privateKeyBuffer.byteOffset,
          privateKeyBuffer.byteOffset + privateKeyBuffer.byteLength
        );

        // Create Ed25519KeyIdentity using the ArrayBuffer
        const identity = Ed25519KeyIdentity.fromSecretKey(privateKeyArrayBuffer);

        // Create an identity and ICP agent using the private key
        const agent = HttpAgent.createSync({ identity, host: host });

        // Fetch root key only in development to bypass certificate validation
        if (IsDev) await agent.fetchRootKey();

        const principal = await agent.getPrincipal();
        const accountIdentifier = AccountIdentifier.fromPrincipal({
          principal,
        });

        return {
          type: "web3auth",
          provider: userInfo as Web3AuthLoginProvider,
          userInfo,
          accountIdentifier,
          principal,
          agent,
          identity,
        };
      } catch (error) {
        console.error(error);
      }
      return null;
    },
    select: (data) => data || null,
    retry: false,
    // enabled: !!web3AuthProvider || !!internetIdentityProvider || !!siwb.identity,
  });

  const {
    mutateAsync: login,
    isPending,
    error,
  } = useMutation({
    mutationFn: async (loginProvider: Web3AuthLoginProvider) => {
      switch (loginProvider.type) {
        case "internet_identity":
          if (!internetIdentityProvider)
            throw new Error("Internet Identity provider not initialized");
          await new Promise((resolve, reject) => {
            internetIdentityProvider.login({
              identityProvider: IIHost,
              windowOpenerFeatures:
                "toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100",
              onSuccess: () => {
                resolve(null);
              },
              onError: (error) => {
                reject(error);
              },
            });
          });
          break;
        case "email_passwordless":
          await web3auth.connectTo(WALLET_ADAPTERS.AUTH, {
            loginProvider: loginProvider.type,
            options: {
              login_hint: loginProvider.email,
            },
          });
          break;
        default:
          await web3auth.connectTo(WALLET_ADAPTERS.AUTH, {
            loginProvider: loginProvider.type,
          });
          break;
      }
      Queries.auth.invalidate({
        siwb,
        laserEyes,
        internetIdentityProvider,
      });
    },
  });

  const {
    mutateAsync: logout,
    error: logoutError,
  } = useMutation({
    mutationFn: async () => {
      try {
        switch (authData?.type) {
          case "internet_identity":
            if (!internetIdentityProvider) return;
            await internetIdentityProvider.logout();
            break;
          case "web3auth":
            await web3auth.logout();
            break;
          case "siwb":
            siwb.clear();
            laserEyes.disconnect();
            break;
        }
      } catch (error) {
        console.error(error);
      }
      Queries.auth.invalidate({
        siwb,
        laserEyes,
        internetIdentityProvider,
      });
    },
  });

  const loginFactory = (loginProvider: Web3AuthLoginProvider) => () =>
    login(loginProvider);

  const requireLogin = async (): Promise<AuthData> => {
    if (authData) return authData;
    return new Promise<AuthData>((resolve, reject) => {
      setShowLoginModal({
        onSuccess: (data) => {
          setShowLoginModal(undefined);
          resolve(data);
        },
        onError: (error) => {
          setShowLoginModal(undefined);
          reject(error);
        },
      });
    });
  };

  const authContextValue = useMemo(
    (): AuthClientContextData => ({
      authData: authData || undefined,
      error: error || logoutError || undefined,
      isLoggingIn: isPending,
      login,
      loginFactory,
      logout,
      requireLogin,
    }),
    [authData, login, logout, error, logoutError, isPending],
  );

  return (
    <AuthClientContext.Provider value={authContextValue}>
      {showLoginModal && <SignupModalComponent onClose={() => showLoginModal.onError(new Error('User cancelled'))} />}
      {children}
    </AuthClientContext.Provider>
  );
});

