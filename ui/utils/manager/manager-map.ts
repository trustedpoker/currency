import { HttpAgent } from "@dfinity/agent";
import { LedgerCanister } from "@dfinity/ledger-icp";
import { IcrcTokenMetadata, mapTokenMetadata } from "@dfinity/ledger-icrc";
import { IsDev, matchRustEnum } from "@zk-game-dao/ui";

import { useIsBTC } from "../../context";
import BTCToken from "../../icons/tokens/bitcoin-symbol.svg";
import ETHToken from "../../icons/tokens/eth.svg";
import FakePP from "../../icons/tokens/fake-pp.png";
import FakeZKP from "../../icons/tokens/fake-zkp.png";
import ICPToken from "../../icons/tokens/icp.svg";
import SatoshisToken from "../../icons/tokens/satoshi.svg";
import USDTToken from "../../icons/tokens/tether.svg";
import USDCToken from "../../icons/tokens/usdc.svg";
import { CKTokenSymbol, Currency, CurrencyType } from "../../types/currency";
import { CurrencyManager } from "../../types/manager";
import { CurrencyMeta } from "../../types/meta";
import { decodeSymbolFrom8Bytes } from "../encode-symbol";
import { getManagerMetadata } from "./get-icrc-manager-metadata";
import { getLedgerCanisterID } from "./get-ledger-canister-id";
import { TOKEN_ICONS } from "./token-icons";

/** All the static metadata info that can be extracted */
export const getStaticManagerMetadata = (
  currency: Currency,
  metadata?: IcrcTokenMetadata,
  isFetched: boolean = false
): CurrencyMeta =>
  matchRustEnum(currency)({
    ICP: (): CurrencyMeta => ({
      decimals: metadata?.decimals ?? 8,
      thousands: 10 ** (metadata?.decimals ?? 8),
      transactionFee: metadata?.fee ?? 10_000n,
      metadata,
      renderedDecimalPlaces: 4,
      icon: ICPToken,
      symbol: "ICP",
      isFetched,
    }),
    GenericICRC1: (token): CurrencyMeta => {
      const symbol = metadata?.symbol ?? decodeSymbolFrom8Bytes(token.symbol);
      const icon =
        (symbol in TOKEN_ICONS
          ? TOKEN_ICONS[symbol as keyof typeof TOKEN_ICONS]
          : undefined) ?? metadata?.icon;
      return {
        metadata,
        decimals: metadata?.decimals ?? token.decimals,
        thousands: 10 ** (metadata?.decimals ?? token.decimals),
        transactionFee: metadata?.fee ?? 10_000n,
        icon,
        symbol,
        isFetched,
      };
    },
    CKETHToken: (ckTokenSymbol) =>
      matchRustEnum(ckTokenSymbol)({
        ETH: () => ({
          decimals: metadata?.decimals ?? 18,
          thousands: 10 ** (metadata?.decimals ?? 18),
          transactionFee: metadata?.fee ?? 10_000n,
          renderedDecimalPlaces: 6,
          metadata,
          icon: ETHToken,
          symbol: "ETH",
          isFetched,
        }),
        USDC: () => ({
          decimals: metadata?.decimals ?? 6,
          thousands: 10 ** (metadata?.decimals ?? 6),
          transactionFee: metadata?.fee ?? 10_000n,
          renderedDecimalPlaces: 2,
          metadata,
          icon: USDCToken,
          symbol: "USDC",
          isFetched,
        }),
        USDT: () => ({
          decimals: metadata?.decimals ?? 6,
          thousands: 10 ** (metadata?.decimals ?? 6),
          transactionFee: metadata?.fee ?? 10_000n,
          renderedDecimalPlaces: 2,
          metadata,
          icon: USDTToken,
          symbol: "USDT",
          isFetched,
        }),
      }),
    BTC: (): CurrencyMeta => ({
      decimals: metadata?.decimals ?? 8,
      thousands: 10 ** (metadata?.decimals ?? 8),
      transactionFee: metadata?.fee ?? 10_000n,
      renderedDecimalPlaces: 6,
      metadata: undefined,
      icon: BTCToken,
      symbol: "BTC",
      isFetched,
      alternatives: {
        satoshis: {
          decimals: 0,
          thousands: 1,
          transactionFee: metadata?.fee ?? 10_000n,
          metadata: undefined,
          icon: SatoshisToken,
          symbol: "sats",
          isFetched,
        },
      },
    }),
  });

export const buildICRC1CurrencyManager = async (
  agent: HttpAgent,
  currency: Currency
): Promise<CurrencyManager> => {
  return {
    currencyType: { Real: currency },
    meta: await getManagerMetadata(currency, agent),
  };
};

export const buildCKTokenManager = async (
  agent: HttpAgent,
  ckTokenSymbol: CKTokenSymbol
): Promise<CurrencyManager> =>
  buildICRC1CurrencyManager(agent, {
    CKETHToken: ckTokenSymbol,
  });

export const buildICPManager = async (
  agent: HttpAgent
): Promise<CurrencyManager> => {
  if (IsDev) await agent.fetchRootKey();

  const ledger = LedgerCanister.create({
    agent,
    canisterId: getLedgerCanisterID({ ICP: null }),
  });
  const meta = await ledger.metadata({});
  const metadata = mapTokenMetadata(meta);

  if (!metadata) throw new Error(`Metadata not found for ICP`);

  return {
    currencyType: { Real: { ICP: null } },
    meta: {
      decimals: metadata.decimals,
      thousands: 10 ** metadata.decimals,
      transactionFee: 10_000n,
      metadata,
      icon: ICPToken,
      isFetched: true,
      symbol: "ICP",
    },
  };
};

export const buildCurrencyManager = async (
  agent: HttpAgent,
  currency: Currency
): Promise<CurrencyManager> =>
  matchRustEnum(currency)({
    ICP: (): Promise<CurrencyManager> => buildICPManager(agent),
    GenericICRC1: async (token): Promise<CurrencyManager> =>
      buildICRC1CurrencyManager(agent, currency),
    CKETHToken: async (ckTokenSymbol): Promise<CurrencyManager> =>
      buildCKTokenManager(agent, ckTokenSymbol),
    BTC: async (): Promise<CurrencyManager> =>
      buildICRC1CurrencyManager(agent, { BTC: null }),
  });

export const buildFakeCurrencyManager = (isBTC: boolean): CurrencyManager => ({
  currencyType: { Fake: null },
  meta: {
    decimals: 8,
    thousands: 10 ** 8,
    transactionFee: 10_000n,
    icon: isBTC ? FakePP : FakeZKP,
    symbol: "IN-GAME",
    // We don't fetch metadata for in game currencies
    isFetched: true,
  },
});

export const buildCurrencyTypeManager = async (
  agent: HttpAgent,
  currencyType: CurrencyType
): Promise<CurrencyManager> => {
  const isBTC = useIsBTC();
  return matchRustEnum(currencyType)({
    Fake: async (): Promise<CurrencyManager> => buildFakeCurrencyManager(isBTC),
    Real: (currency) => buildCurrencyManager(agent, currency),
  });
};
