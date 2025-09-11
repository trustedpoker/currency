import { IcrcTokenMetadata } from "@dfinity/ledger-icrc";

export type CurrencyMeta = {
  decimals: number;
  /** the decimals to the power of 10 (8 decimals becomes 1000000000) */
  thousands: number;
  transactionFee: bigint;
  /** For expensive currencies, this forces a certain amount of decimals being rendered (BTC should show 6 for example) */
  renderedDecimalPlaces?: number;
  metadata?: IcrcTokenMetadata;

  /** Base64 encoded icon */
  icon?: string;
  
  /** The name of the currency */
  symbol: string;

  /** Marks if this data is fetched from the ledgers metadata */
  isFetched: boolean;

  /** Like satoshis for btc */
  alternatives?: Record<string, CurrencyMeta>;
};
