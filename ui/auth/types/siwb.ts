import { SupportedSIWBProvider } from "../components/provide-btc-logins/provide-btc-logins.component";
import { AuthDataProvider } from "./auth-data";

export type AuthDataSiwb = AuthDataProvider<
  "siwb",
  { type: "siwb"; provider: SupportedSIWBProvider }
>;
