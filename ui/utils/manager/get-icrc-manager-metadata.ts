import { HttpAgent } from "@dfinity/agent";
import { IcrcLedgerCanister, mapTokenMetadata } from "@dfinity/ledger-icrc";
import { IsDev } from "@zk-game-dao/ui";

import { host } from "../../auth";
import { Currency } from "../../types/currency";
import { CurrencyMeta } from "../../types/meta";
import { CurrencyToString } from "../currency-type-to-string";
import { getLedgerCanisterID } from "./get-ledger-canister-id";
import { getStaticManagerMetadata } from "./manager-map";

export const getManagerMetadata = async (
  currency: Currency,
  agent = HttpAgent.createSync({
    host,
  })
): Promise<CurrencyMeta> => {
  if (IsDev) await agent.fetchRootKey();

  const ledger = IcrcLedgerCanister.create({
    agent,
    canisterId: getLedgerCanisterID(currency),
  });

  const meta = await ledger.metadata({});
  const metadata = mapTokenMetadata(meta);

  if (!metadata)
    throw new Error(`Metadata not found for ${CurrencyToString(currency)}`);

  return getStaticManagerMetadata(
    currency,
    {
      ...metadata,
      fee: (await ledger.transactionFee({})) ?? metadata.fee,
    },
    true
  );
};
