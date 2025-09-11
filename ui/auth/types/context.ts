import { HttpAgent, Identity } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { AccountIdentifier } from "@dfinity/ledger-icp";
import { Principal } from "@dfinity/principal";
import { IProvider } from "@web3auth/base";
import { createContext, useContext } from "react";

import { AuthDataInternetIdentity } from "./iiauth";
import { AuthDataSiwb } from "./siwb";
import { AuthDataWeb3Auth, Web3AuthLoginProvider } from "./web3auth";

export type AuthData = (
  | AuthDataInternetIdentity
  | AuthDataWeb3Auth
  | AuthDataSiwb
) & {
  agent: HttpAgent;
  identity: Identity;
  principal: Principal;
  accountIdentifier: AccountIdentifier;
};

export type AuthProvider = AuthData["provider"];

export type AuthClientContextData = {
  authData?: AuthData;
  error?: Error;
  isLoggingIn?: boolean;

  login(loginProvider: Web3AuthLoginProvider): Promise<void>;
  loginFactory(loginProvider: Web3AuthLoginProvider): () => Promise<void>;
  logout(): Promise<void>;

  requireLogin(): Promise<AuthData>;
};

export type Providers = Partial<{
  web3AuthProvider: IProvider;
  internetIdentityProvider: AuthClient;
}>;

export const AuthClientContext = createContext<AuthClientContextData>({
  login: async () => {},
  loginFactory: () => async () => {},
  logout: async () => {},

  requireLogin: async () => {
    throw new Error("Require login not implemented");
  },
});

export const useAuth = () => useContext(AuthClientContext);
