import { createContext, ReactNode } from "react";

import { CurrencyReceiver, CurrencyType } from "./currency";

export type AllowanceAddressData = {
  currencyType: CurrencyType;
  receiver: CurrencyReceiver;
  name: ReactNode;
};

export type AllowanceRequestData = {
  amount: bigint;
  reason: ReactNode;
};

export type FullAllowanceRequestData = {
  address: AllowanceAddressData;
  request: AllowanceRequestData;
};

export type AllowanceContextType = {
  setAllowance: (
    address: AllowanceAddressData,
    request: AllowanceRequestData,
    expires_at: Date
  ) => Promise<void>;
  requireAllowance: (
    address: AllowanceAddressData,
    request: AllowanceRequestData,
    /** This will be used if a new expiration has to be used */
    expires_at: Date
  ) => Promise<void>;
};

export const CurrencyAllowanceContext = createContext<AllowanceContextType>({
  setAllowance: async () => {
    throw new Error("Context not provided");
  },
  requireAllowance: async () => {
    throw new Error("Context not provided");
  },
});
