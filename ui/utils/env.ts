import { Principal } from "@dfinity/principal";
import { IsDev } from "@zk-game-dao/ui";

export const IC_SIWB_ID = Principal.fromText(
  IsDev ? "be2us-64aaa-aaaaa-qaabq-cai" : "j2let-saaaa-aaaam-qds2q-cai"
);
