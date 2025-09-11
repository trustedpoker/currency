import { Principal } from '@dfinity/principal';
import { useQuery } from '@zk-game-dao/ui';
import axios from 'axios';
import { createContext, memo, ReactNode, useContext, useEffect, useState } from 'react';
import { useMemo } from 'react';

import { Currency, Token } from '../types';
import { encodeSymbolTo8Bytes } from '../utils';
import { CurrencySerializer } from '../utils/serialize';
import { useIsBTC } from './currency-config.context';
import { IcrcLedgerCanister, mapTokenMetadata } from '@dfinity/ledger-icrc';

type SNSApiResponse<D> = {
  data: D[];
  max_index: number;
  total_ledgers: number;
};

type ICRCLedgersResponse = SNSApiResponse<{
  ledger_canister_id: string;
  sns_root_canister_id: null | string;
  ckerc20_orchestrator_id:
  | "2s5qh-7aaaa-aaaar-qadya-cai"
  | "vxkom-oyaaa-aaaar-qafda-cai"
  | null;
  ckerc20_contract: {
    chain_id: string;
    address: string;
  } | null;
  icrc1_metadata: {
    icrc1_fee: string;
    icrc1_name: string;
    icrc1_logo: null | string;
    icrc1_symbol: string;
    icrc1_decimals: string;
    icrc1_total_supply: string;
    icrc1_max_memo_length: string;
    icrc1_minting_account: {
      owner: string;
      subaccount: null | string;
    };
  };
}>;

const ledgers_endpoint = `https://icrc-api.internetcomputer.org/api/v2/ledgers?limit=100`;

const reservedSymbols = [
  "ICP",
  "ETH",
  "USDC",
  "USDT",
  "BTC",
  "---",
  "ckUSDC",
  "ckUSDT",
  "ckETH",
  "ckBTC",
];

export type TokenRegistry = {
  highlightedCurrencies: Currency[];
  allCurrencies: Currency[];

  addCurrency: (currency: Currency) => void;
  removeCurrency: (currency: Currency) => void;
};

const TokenRegistryContext = createContext<TokenRegistry>({
  highlightedCurrencies: [],
  allCurrencies: [],
  addCurrency: () => { },
  removeCurrency: () => { },
});

const getStoredHighlightedCurrencies = (): Currency[] => {
  const stored = localStorage.getItem("highlightedCurrency");
  if (!stored) return [];
  const parsed = JSON.parse(stored) as string[];
  return parsed.map(CurrencySerializer.deserialize);
}

const storeHighlightedCurrencies = (currencies: Currency[]) => {
  localStorage.setItem("highlightedCurrency", JSON.stringify(currencies.map(CurrencySerializer.serialize)));
}

export const useSearchCurrencies = (query?: string) => useQuery({
  queryKey: ["token-registry", "icrc", query ?? 'none'],
  queryFn: async () => {
    try {
      const principal = Principal.fromText(query ?? '');

      const ledger = IcrcLedgerCanister.create({ canisterId: principal, });
      const meta = await ledger.metadata({});
      const metadata = mapTokenMetadata(meta);

      if (!metadata?.symbol) throw new Error(`Metadata not found for ${query}`);

      return [
        {
          GenericICRC1: {
            ledger_id: principal,
            symbol: encodeSymbolTo8Bytes(metadata.symbol),
            decimals: metadata.decimals,
          } as Token,
        },
      ]
    } catch (e) {
      // If the query is not a valid Principal, we assume it's a search term
    }
    const {
      data: { data: l },
    } = await axios.get<ICRCLedgersResponse>(query ? `${ledgers_endpoint}&query=${encodeURIComponent(query)}` : ledgers_endpoint);

    const ledgers: Currency[] = [];

    for (const ledger of l) {
      if (!ledger.icrc1_metadata || !ledger.icrc1_metadata.icrc1_logo)
        continue;
      if (reservedSymbols.includes(ledger.icrc1_metadata.icrc1_symbol))
        continue;

      ledgers.push({
        GenericICRC1: {
          ledger_id: Principal.fromText(ledger.ledger_canister_id),
          symbol: encodeSymbolTo8Bytes(ledger.icrc1_metadata.icrc1_symbol),
          decimals: parseInt(ledger.icrc1_metadata.icrc1_decimals),
        } as Token,
      });
    }

    return ledgers;
  },
  initialData: [],
});


export const ProvideTokenRegistry = memo<{ children: ReactNode }>(({ children }) => {
  const [_highlightedCurrencies, setHighlightedCurrencies] = useState<Currency[]>(getStoredHighlightedCurrencies());
  const isBTC = useIsBTC();

  const addCurrency = (currency: Currency) => {
    setHighlightedCurrencies((prev) => [...prev, currency].filter((c, i, a) => a.findIndex((cc) => CurrencySerializer.serialize(cc) === CurrencySerializer.serialize(c)) === i));
  };
  const removeCurrency = (currency: Currency) => {
    setHighlightedCurrencies((prev) => prev.filter((c) => CurrencySerializer.serialize(c) !== CurrencySerializer.serialize(currency)));
  };

  useEffect(() => storeHighlightedCurrencies(_highlightedCurrencies), [_highlightedCurrencies]);

  const icrc1 = useSearchCurrencies();

  const allCurrencies = useMemo(
    (): Currency[] => {
      if (isBTC) return [{ BTC: null }];
      return [
        { CKETHToken: { ETH: null } },
        { CKETHToken: { USDC: null } },
        { CKETHToken: { USDT: null } },
        { ICP: null },
        ...icrc1.data,
      ];
    },
    [icrc1.data, isBTC]
  );

  const highlightedCurrencies = useMemo(
    () => {
      if (isBTC) return [{ BTC: null }];
      return [
        { CKETHToken: { ETH: null } },
        { CKETHToken: { USDC: null } },
        { CKETHToken: { USDT: null } },
        { ICP: null },
        ..._highlightedCurrencies,
      ];
    },
    [_highlightedCurrencies.map(CurrencySerializer.serialize), isBTC]
  );

  return (
    <TokenRegistryContext.Provider
      value={{
        highlightedCurrencies,
        allCurrencies,
        addCurrency,
        removeCurrency,
      }}
    >
      {children}
    </TokenRegistryContext.Provider>
  );
});

export const useTokenRegistry = (): TokenRegistry => useContext(TokenRegistryContext);
