import {
  AuthAdapter,
  AuthOptions,
  AuthUserInfo,
  PrivateKeyProvider,
} from "@web3auth/auth-adapter";
import {
  BaseAdapterSettings,
  CHAIN_NAMESPACES,
  WEB3AUTH_NETWORK,
} from "@web3auth/base";
import { CommonPrivateKeyProvider } from "@web3auth/base-provider";
import { Web3AuthNoModal } from "@web3auth/no-modal";
import { IC_HOST, IsDev } from "@zk-game-dao/ui";
import { AuthDataProvider } from "./auth-data";

const clientId = !IsDev
  ? "BJ5MVY5dVC1SERMgJv-0jZh7cyJBmmo_4QrSKAYILLO0YE3MOBnOHD3yQ6PysFkCeq3Di7pwrEWVJiVXj0IVJZI"
  : "BJbP2vVuQvVne9QC7GnsCnstay0grZKIWa0iAg-E7WWnMj9ua-SXnU5aEM2w7N93jsMiW4DSB4l12wlUH46EeBc";

const host = IC_HOST;

const web3AuthNetwork = IsDev
  ? WEB3AUTH_NETWORK.SAPPHIRE_DEVNET
  : WEB3AUTH_NETWORK.SAPPHIRE_MAINNET;

export const SocialLoginProviders = [
  "google",
  "line",
  "twitter",
  "internet_identity",
  "apple",
  "facebook",
  "github",
] as const;

export type SocialLoginProviderKey = (typeof SocialLoginProviders)[number];

export type Web3AuthLoginProvider =
  | { type: SocialLoginProviderKey }
  | {
    type: "email_passwordless";
    email: string;
  };

export type AuthDataWeb3Auth = AuthDataProvider<
  "web3auth",
  Web3AuthLoginProvider,
  {
    userInfo: Partial<AuthUserInfo>;
  }
>;

// Function to initialize Web3Auth with or without a private key provider
const initWeb3Auth = (
  adapterSettings?: Partial<AuthOptions & BaseAdapterSettings> & {
    privateKeyProvider?: PrivateKeyProvider | undefined;
  }
) => {
  const privateKeyProvider = new CommonPrivateKeyProvider({
    config: {
      chainConfig: {
        chainNamespace: CHAIN_NAMESPACES.OTHER, // ICP uses "other" namespace
        chainId: "InternetComputer", // ICP chain identifier
        rpcTarget: host, // ICP's public API endpoint
        displayName: "Internet Computer",
        blockExplorerUrl: "https://dashboard.internetcomputer.org",
        ticker: "ICP",
        tickerName: "Internet Computer Protocol",
      },
    },
  });

  const auth = new Web3AuthNoModal({
    clientId,
    web3AuthNetwork,
    privateKeyProvider: privateKeyProvider, // Attach privateKeyProvider here
  });

  const authAdapter = new AuthAdapter({
    clientId,
    // adapterSettings: {
    //   loginConfig: {
    //     // weibo: {
    //     //   verifier: "zkp-weibo-verifier",
    //     //   typeOfLogin: "jwt",
    //     //   clientId: "Ev39Il2sj0qi9If0txP4FyS3nk5s7aSd",
    //     // },
    //   },
    // },
  });
  if (adapterSettings) authAdapter.setAdapterSettings(adapterSettings);
  auth.configureAdapter(authAdapter);

  return auth;
};

export const web3auth = initWeb3Auth(); // Use separate settings if needed
