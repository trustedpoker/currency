import { CkETHMinterCanister } from "@dfinity/cketh";
import { Account, SubAccount } from "@dfinity/ledger-icp";
import { IcrcLedgerCanister } from "@dfinity/ledger-icrc";
import { Allowance } from "@dfinity/ledger-icrc/dist/candid/icrc_ledger";
import { Principal } from "@dfinity/principal";
import { IsDev, matchRustEnum, useQuery, UserError } from "@zk-game-dao/ui";
import { ethers } from "ethers";
import { createContext, useContext, useMemo } from "react";

import { AuthData, useAuth } from "../auth/types/context";
import { Queries } from "../queries";
import { CurrencyToString } from "../utils/currency-type-to-string";
import { CKTokenSymbol, Currency } from "./currency";
import { EIP6963ProviderDetail, useEIP6963 } from "./EIP6963.context";
import { buildCKTokenManager } from "../utils/manager/manager-map";

export const USDC_MINTER_CANISTER_ID = "sv3dd-oaaaa-aaaar-qacoa-cai";
export const USDC_LEDGER_CANISTER_ID = "xevnm-gaaaa-aaaar-qafnq-cai";
export const USDC_DECIMALS = 6;

export const USDT_MINTER_CANISTER_ID = "sv3dd-oaaaa-aaaar-qacoa-cai";
export const USDT_LEDGER_CANISTER_ID = "cngnf-vqaaa-aaaar-qag4q-cai";
export const USDT_DECIMALS = 6;

export const ETH_MINTER_CANISTER_ID = "sv3dd-oaaaa-aaaar-qacoa-cai";
export const ETH_LEDGER_CANISTER_ID = "ss2fx-dyaaa-aaaar-qacoq-cai";
export const ETH_DECIMALS = 18;

export const BTC_MINTER_CANISTER_ID = "mqygn-kiaaa-aaaar-qaadq-cai";
export const BTC_LEDGER_CANISTER_ID = "mxzaz-hqaaa-aaaar-qaada-cai";
export const BTC_DECIMALS = 8;

export const getERC20CanisterData = (
  ckTokenSymbol: CKTokenSymbol
): {
  minter: Principal;
  ledger: Principal;
  tokenContractAddress: string;
  decimals: number;
} =>
  matchRustEnum(ckTokenSymbol)({
    ETH: () => ({
      minter: Principal.fromText(ETH_MINTER_CANISTER_ID),
      ledger: Principal.fromText(ETH_LEDGER_CANISTER_ID),
      tokenContractAddress: "0x2170Ed0880ac9A755fd29B2688956BD959F933F8",
      decimals: ETH_DECIMALS,
    }),
    USDC: () => ({
      minter: Principal.fromText(USDC_MINTER_CANISTER_ID),
      ledger: Principal.fromText(USDC_LEDGER_CANISTER_ID),
      tokenContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      decimals: USDC_DECIMALS,
    }),
    USDT: () => ({
      minter: Principal.fromText(USDT_MINTER_CANISTER_ID),
      ledger: Principal.fromText(USDT_LEDGER_CANISTER_ID),
      tokenContractAddress: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
      decimals: USDT_DECIMALS,
    }),
  });

const erc20Abi = [
  {
    constant: true,
    inputs: [],
    name: "name",
    outputs: [{ name: "", type: "string" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      { name: "_spender", type: "address" },
      { name: "_value", type: "uint256" },
    ],
    name: "approve",
    outputs: [{ name: "", type: "bool" }],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "totalSupply",
    outputs: [{ name: "", type: "uint256" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      { name: "_from", type: "address" },
      { name: "_to", type: "address" },
      { name: "_value", type: "uint256" },
    ],
    name: "transferFrom",
    outputs: [{ name: "", type: "bool" }],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "decimals",
    outputs: [{ name: "", type: "uint8" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [{ name: "_owner", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "balance", type: "uint256" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "symbol",
    outputs: [{ name: "", type: "string" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      { name: "_to", type: "address" },
      { name: "_value", type: "uint256" },
    ],
    name: "transfer",
    outputs: [{ name: "", type: "bool" }],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      { name: "_owner", type: "address" },
      { name: "_spender", type: "address" },
    ],
    name: "allowance",
    outputs: [{ name: "", type: "uint256" }],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  { payable: true, stateMutability: "payable", type: "fallback" },
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: "owner", type: "address" },
      { indexed: true, name: "spender", type: "address" },
      { indexed: false, name: "value", type: "uint256" },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: "from", type: "address" },
      { indexed: true, name: "to", type: "address" },
      { indexed: false, name: "value", type: "uint256" },
    ],
    name: "Transfer",
    type: "event",
  },
];

const helperAbi = [
  {
    inputs: [
      { internalType: "address", name: "_minterAddress", type: "address" },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [{ internalType: "address", name: "target", type: "address" }],
    name: "AddressEmptyCode",
    type: "error",
  },
  {
    inputs: [{ internalType: "address", name: "account", type: "address" }],
    name: "AddressInsufficientBalance",
    type: "error",
  },
  { inputs: [], name: "FailedInnerCall", type: "error" },
  {
    inputs: [{ internalType: "address", name: "token", type: "address" }],
    name: "SafeERC20FailedOperation",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "erc20ContractAddress",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
      {
        indexed: true,
        internalType: "bytes32",
        name: "principal",
        type: "bytes32",
      },
      {
        indexed: false,
        internalType: "bytes32",
        name: "subaccount",
        type: "bytes32",
      },
    ],
    name: "ReceivedEthOrErc20",
    type: "event",
  },
  {
    inputs: [
      { internalType: "address", name: "erc20Address", type: "address" },
      { internalType: "uint256", name: "amount", type: "uint256" },
      { internalType: "bytes32", name: "principal", type: "bytes32" },
      { internalType: "bytes32", name: "subaccount", type: "bytes32" },
    ],
    name: "depositErc20",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { internalType: "bytes32", name: "principal", type: "bytes32" },
      { internalType: "bytes32", name: "subaccount", type: "bytes32" },
    ],
    name: "depositEth",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [],
    name: "getMinterAddress",
    outputs: [{ internalType: "address", name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
];

const HELPER_CONTRACT_ADDRESS = "0x18901044688D3756C35Ed2b36D93e6a5B8e00E68";

function encodePrincipal(_principal: Principal) {
  const principalString = _principal.toText();
  const principal = Principal.fromText(principalString);
  const subAccount = SubAccount.fromPrincipal(principal);
  const bytes32 = subAccount.toUint8Array();
  const hexString = "0x" + Buffer.from(bytes32).toString("hex");
  return hexString;
}

export type TransactionHashMap = Partial<Record<string, string[]>>;

type ChainFusionContextValue = {
  /** Whether the ui should show the native currencies or not */
  isNativeShown: boolean;
  setIsNativeShown(show: boolean): void;

  depostTransactionsHashes: TransactionHashMap;
  withdrawalTransactionsHashes: TransactionHashMap;

  deposit(currency: Currency, amount: bigint): Promise<void>;
  withdraw(currency: Currency, amount: bigint): Promise<void>;
};

export const ChainFusionContext = createContext<ChainFusionContextValue>({
  isNativeShown: true,
  setIsNativeShown: () => {},
  depostTransactionsHashes: {},
  withdrawalTransactionsHashes: {},
  deposit: async () => {},
  withdraw: async () => {},
});

export const useChainFusion = () => useContext(ChainFusionContext);
export const useIsChainFusionCurrency = (currency: Currency) =>
  useMemo(
    () =>
      matchRustEnum(currency)({
        ICP: () => false,
        GenericICRC1: () => false,
        CKETHToken: () => true,
        BTC: () => true,
      }),
    [currency]
  );

export const useShowingNativeCurrency = (currency: Currency) => {
  const isNativeCurrency = useIsChainFusionCurrency(currency);
  const { isNativeShown } = useChainFusion();

  return useMemo(
    () => isNativeCurrency && isNativeShown,
    [isNativeCurrency, isNativeShown]
  );
};

const minimum_eth_withdrawal = 0.03;

export const buildChainFusionActor = (
  currency: Currency,
  selectedWallet: EIP6963ProviderDetail | null,
  selectedAccount: string | null,
  authData?: AuthData
): {
  withdraw(amount: bigint): Promise<unknown>;
  deposit(amount: bigint): Promise<unknown>;
  setAllowanceTo(allowance: bigint): Promise<bigint>;
  fetchAllowance(): Promise<Allowance>;
} => {
  try {
    if (!selectedWallet) throw new UserError("No Wallet selected");
    if (!selectedAccount) throw new UserError("No Account selected");
    if (!authData) throw new UserError("You need to be logged in");
    // if (!managerMap) throw new UserError("No currency manager map found");

    // const manager = managerMap[currency];
    // if (!manager) throw new UserError("No currency manager found");

    if (!("CKETHToken" in currency))
      throw new UserError(`${CurrencyToString(currency)} is not supported yet`);

    const data = getERC20CanisterData(currency.CKETHToken);
    if (!data) throw new UserError(`${currency} is not supported yet`);

    const minterCanister = CkETHMinterCanister.create({
      agent: authData.agent,
      canisterId: data.minter,
    });

    const ledgerCanister = IcrcLedgerCanister.create({
      agent: authData.agent,
      canisterId: data.ledger,
    });

    const spender: Account = {
      owner: minterCanister.canisterId,
      subaccount: [],
    };

    const account: Account = {
      owner: minterCanister.canisterId,
      subaccount: [],
    };

    const provider = new ethers.BrowserProvider(selectedWallet.provider);

    const fetchAllowance = () =>
      ledgerCanister.allowance({
        spender,
        account,
      });

    const setAllowanceTo = async (allowance: bigint) => {
      if (allowance < 0n) throw new UserError("Allowance cannot be negative");

      console.log(`Setting allowance to ${allowance}`);
      const block = await ledgerCanister.approve({
        spender,
        amount: allowance,
      });
      console.log(`Successfully set allowance to ${allowance}`);
      Queries.icrc_allowance.invalidate({ Real: currency });
      return block;
    };

    const requireAllowance = async (allowance: bigint) => {
      if (allowance === 0n) return;
      const currentAllowance = (await fetchAllowance()).allowance;
      const requiredAllowance = allowance - currentAllowance;
      console.log({
        currentAllowance,
        allowance,
        requiredAllowance,
      });
      if (requiredAllowance > 0n) return setAllowanceTo(allowance);
    };

    if ("BTC" in currency.CKETHToken)
      throw new UserError("BTC is not supported yet");

    if ("ETH" in currency.CKETHToken)
      return {
        setAllowanceTo,
        fetchAllowance,
        withdraw: async (amount) => {
          const manager = await buildCKTokenManager(
            authData.agent,
            currency.CKETHToken
          );
          const fees = await getChainFusionTransactionFee(authData);
          if (
            amount <
            BigInt(minimum_eth_withdrawal * 10 ** manager.meta.decimals)
          )
            throw new UserError(
              `Minimum withdrawal amount is ${minimum_eth_withdrawal} ETH`
            );
          await requireAllowance(amount + fees.ckETHToETH);
          // await ledgerCanister.approve({
          //   spender: { owner: minterCanister.canisterId, subaccount: [] },
          //   amount: amount + fees.ckETHToETH,
          // });
          return minterCanister.withdrawEth({
            address: selectedAccount,
            amount,
          });
        },
        deposit: async (amount) => {
          const manager = await buildCKTokenManager(
            authData.agent,
            currency.CKETHToken
          );
          const addedDecimals = data.decimals - manager.meta.decimals;
          const amountAdjustedForNative = amount * BigInt(10 ** addedDecimals);

          const signer = await provider.getSigner();

          // Create the helper contract interface
          const helperContract = new ethers.Contract(
            HELPER_CONTRACT_ADDRESS,
            helperAbi,
            signer
          );

          const depositTx = await signer.sendTransaction({
            to: HELPER_CONTRACT_ADDRESS,
            data: await helperContract.interface.encodeFunctionData(
              "depositEth",
              [
                ethers.hexlify(encodePrincipal(authData.principal)),
                ethers.hexlify(
                  "0x0000000000000000000000000000000000000000000000000000000000000000"
                ),
              ]
            ),
            value: amountAdjustedForNative,
          });

          await depositTx.wait();
          console.log(`ETH Deposit transaction hash: ${depositTx.hash}`);
          return depositTx.hash;
        },
      };

    return {
      setAllowanceTo,
      fetchAllowance,
      withdraw: async (amount) => {
        const fees = await getChainFusionTransactionFee(authData);
        const ckETHCanister = IcrcLedgerCanister.create({
          agent: authData.agent,
          canisterId: Principal.fromText(ETH_LEDGER_CANISTER_ID),
        });

        const gasInCKETH = fees.ckERC20ToERC20;
        if (!gasInCKETH) throw new UserError("No gas price found for CKETH");

        const allowance = await ckETHCanister.allowance({
          spender,
          account,
        });

        const requiredAllowance = gasInCKETH - allowance.allowance;

        if (requiredAllowance > 0n)
          await ckETHCanister.approve({
            spender,
            amount: gasInCKETH - allowance.allowance,
          });

        await requireAllowance(amount);

        return minterCanister.withdrawErc20({
          address: selectedAccount,
          amount,
          ledgerCanisterId: ledgerCanister.canisterId,
        });
      },
      deposit: async (amount) => {
        const manager = await buildCKTokenManager(
          authData.agent,
          currency.CKETHToken
        );
        const addedDecimals = data.decimals - manager.meta.decimals;
        const amountAdjustedForNative = amount * BigInt(10 ** addedDecimals);

        if (!selectedWallet) throw new UserError("No connected wallet found");
        if (!selectedAccount) throw new UserError("No connected account found");

        // const gasLimit = await provider.estimateGas({});
        const signer = await provider.getSigner();

        // Create the helper contract interface
        const helperContract = new ethers.Contract(
          HELPER_CONTRACT_ADDRESS,
          helperAbi,
          signer
        );

        // ERC-20 Deposit
        console.log("Processing ERC-20 deposit...");

        // Create the ERC-20 token interface
        const tokenContract = new ethers.Contract(
          data.tokenContractAddress,
          erc20Abi,
          signer
        );

        // Step 1: Approve the helper contract to spend the token
        const approveTx = await tokenContract.approve(
          HELPER_CONTRACT_ADDRESS,
          amountAdjustedForNative
        ); // Adjust decimals for the token
        await approveTx.wait();
        console.log(`Approval transaction hash: ${approveTx.hash}`);

        const depositTx = await helperContract.depositErc20(
          data.tokenContractAddress,
          amountAdjustedForNative,
          ethers.hexlify(encodePrincipal(authData.principal)),
          ethers.hexlify(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
          )
        );

        await depositTx.wait();
        console.log(`ERC-20 Deposit transaction hash: ${depositTx.hash}`);
        return depositTx.hash;
      },
    };
  } catch (error) {
    console.error(`Cannot withdraw ${currency} using Chain Fusion`);
    return {
      withdraw: async () => {
        throw error;
      },
      deposit: async () => {
        throw error;
      },
      setAllowanceTo: async () => 0n,
      fetchAllowance: async () => ({ allowance: 0n, expires_at: [] }),
    };
  }
};

export const useChainFusionActor = (currency: Currency) => {
  const { authData } = useAuth();
  const { selectedWallet, selectedAccount } = useEIP6963();
  return useMemo(
    () =>
      buildChainFusionActor(
        currency,
        selectedWallet,
        selectedAccount,
        authData
      ),
    [currency, selectedWallet, selectedAccount, authData]
  );
};

export const useChainFusionAllowance = (currency: Currency) => {
  const { fetchAllowance } = useChainFusionActor(currency);
  return useQuery({
    queryKey: Queries.icrc_allowance.key({ Real: currency }),
    queryFn: fetchAllowance,
    refetchInterval: 10_000,
  }).data;
};

export const useSetAllowance = (currency: Currency) =>
  useChainFusionActor(currency).setAllowanceTo;

// https://github.com/dfinity/oisy-wallet/blob/main/src/frontend/src/eth/constants/eth.constants.ts
const baseETHFee = 21_000n;

// Discussed with crosschain team. At the moment we set 0.01 Ethererum as additional transaction fee for a conversion from ckErc20 to Erc20.
// Those are the fees of the icrc2_approve(minter, tx_fee) describe in the first step of the withdrawal scheme.
// See https://github.com/dfinity/ic/blob/master/rs/ethereum/cketh/docs/ckerc20.adoc#withdrawal-ckerc20-to-erc20
// TODO: in the future we might either want to user to overwrite this value or implement some clever way to estimate those fees.
export const CKERC20_TO_ERC20_MAX_TRANSACTION_FEE = 10_000_000_000_000_000n; // i.e. 0.01 Ethereum

export const getChainFusionTransactionFee = async (authData: AuthData) => {
  const ckethManager = await buildCKTokenManager(authData.agent, { ETH: null });
  const ckETHDecimals = ckethManager.meta.decimals ?? 18;

  const ethDecimalDIFF = ETH_DECIMALS - ckETHDecimals;
  const ethDecimalDIFFThousands = 10n ** BigInt(ethDecimalDIFF);

  return {
    ckERC20ToERC20:
      CKERC20_TO_ERC20_MAX_TRANSACTION_FEE / ethDecimalDIFFThousands,
    ckETHToETH: baseETHFee / ethDecimalDIFFThousands,
  };
};

export const useChainFusionTransactionFees = () => {
  const { authData } = useAuth();

  return useQuery({
    queryKey: Queries.chain_fusion_transaction_fees.key(!!authData),
    queryFn: () => {
      if (!authData) return;
      return getChainFusionTransactionFee(authData);
    },
  }).data;
};
