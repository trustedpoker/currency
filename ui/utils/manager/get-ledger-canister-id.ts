import { Principal } from "@dfinity/principal";
import { matchRustEnum } from "@zk-game-dao/ui";

import { BTC_LEDGER_CANISTER_ID, CKTokenSymbol, Currency } from "../../types";

export const getCKTokenLedgerCanisterID = (
  ckTokenSymbol: CKTokenSymbol
): Principal =>
  Principal.fromText(
    matchRustEnum(ckTokenSymbol)({
      ETH: () => "ss2fx-dyaaa-aaaar-qacoq-cai",
      USDC: () => "xevnm-gaaaa-aaaar-qafnq-cai",
      USDT: () => "cngnf-vqaaa-aaaar-qag4q-cai",
    })
  );

export const getLedgerCanisterID = (currency: Currency): Principal =>
  matchRustEnum(currency)({
    ICP: () => Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai"),
    GenericICRC1: (token) => token.ledger_id,
    CKETHToken: (ckTokenSymbol) => getCKTokenLedgerCanisterID(ckTokenSymbol),
    BTC: () => Principal.fromText(BTC_LEDGER_CANISTER_ID),
  });
