import { IC_HOST, IsDev } from "@zk-game-dao/ui";

import { AuthDataProvider } from "./auth-data";

export const host = process.env.VITE_IC_HOST ?? import.meta.env.VITE_IC_HOST ?? IC_HOST;

export const IIHost = IsDev
  ? `http://${process.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943/`
  : "https://identity.ic0.app";

export type AuthDataInternetIdentity = AuthDataProvider<
  "internet_identity",
  { type: "internet_identity" }
>;
