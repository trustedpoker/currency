import { Principal } from "@dfinity/principal";

import { encodeSymbolTo8Bytes } from "../../ui";
import { TOKEN_ICONS } from "../../ui/utils/manager/token-icons";

const MockToken = (
  ledgerId: Principal,
  symbol: string,
  decimals = 8,
  icon?: string
): {
  currencyType: {
    Real: {
      GenericICRC1: {
        ledger_id: Principal;
        symbol: Uint8Array;
        decimals: number;
      };
    };
  };
  meta: {
    icon: string;
    symbol: string;
    isFetched: true;
  };
} => ({
  currencyType: {
    Real: {
      GenericICRC1: {
        ledger_id: ledgerId,
        symbol: encodeSymbolTo8Bytes(symbol),
        decimals,
      },
    },
  },
  meta: {
    icon:
      icon ||
      `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAABl0RVh0U29mdHdhcmUAbWF0cGxvdGxpYiB2ZXJzaW9uIDIuMS4wLCBodHRwOi8vbWF0cGxvdGxpYi5vcmcvpW3flAAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxMi0wNy0yOVQxNzozMDozNiswMjowMLX7aYkAAAAASUVORK5CYII=`,
    symbol,
    isFetched: true,
  },
});

export const DCD_MOCK = MockToken(
  Principal.fromText("xsi2v-cyaaa-aaaaq-aabfq-cai"),
  "DCD",
  8,
  TOKEN_ICONS.DCD
);

export const NFID_MOCK = MockToken(
  Principal.fromText("m2blf-zqaaa-aaaaq-aaejq-cai"),
  "NFIDW",
  8,
  TOKEN_ICONS.NFIDW
);

export const YUKU_MOCK = MockToken(
  Principal.fromText("atbfz-diaaa-aaaaq-aacyq-cai"),
  "YUKU",
  8,
  TOKEN_ICONS.YUKU
);

export const MOCK_UNKNOWN = MockToken(Principal.anonymous(), "unknownToken");
