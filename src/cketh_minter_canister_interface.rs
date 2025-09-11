// This is an experimental feature to generate Rust binding from Candid.
// You may want to manually adjust some of the types.
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub enum BlockTag {
    Safe,
    Finalized,
    Latest,
}

#[derive(CandidType, Deserialize)]
pub struct UpgradeArg {
    pub deposit_with_subaccount_helper_contract_address: Option<String>,
    pub next_transaction_nonce: Option<candid::Nat>,
    pub evm_rpc_id: Option<Principal>,
    pub ledger_suite_orchestrator_id: Option<Principal>,
    pub erc20_helper_contract_address: Option<String>,
    pub last_erc20_scraped_block_number: Option<candid::Nat>,
    pub ethereum_contract_address: Option<String>,
    pub minimum_withdrawal_amount: Option<candid::Nat>,
    pub last_deposit_with_subaccount_scraped_block_number: Option<candid::Nat>,
    pub ethereum_block_height: Option<BlockTag>,
}

#[derive(CandidType, Deserialize)]
pub enum EthereumNetwork {
    Mainnet,
    Sepolia,
}

#[derive(CandidType, Deserialize)]
pub struct InitArg {
    pub ethereum_network: EthereumNetwork,
    pub last_scraped_block_number: candid::Nat,
    pub ecdsa_key_name: String,
    pub next_transaction_nonce: candid::Nat,
    pub ledger_id: Principal,
    pub ethereum_contract_address: Option<String>,
    pub minimum_withdrawal_amount: candid::Nat,
    pub ethereum_block_height: BlockTag,
}

#[derive(CandidType, Deserialize)]
pub enum MinterArg {
    UpgradeArg(UpgradeArg),
    InitArg(InitArg),
}

#[derive(CandidType, Deserialize)]
pub struct AddCkErc20Token {
    pub ckerc20_ledger_id: Principal,
    pub chain_id: candid::Nat,
    pub address: String,
    pub ckerc20_token_symbol: String,
}

#[derive(CandidType, Deserialize)]
pub struct Eip1559TransactionPriceArg {
    pub ckerc20_ledger_id: Principal,
}

#[derive(CandidType, Deserialize)]
pub struct Eip1559TransactionPrice {
    pub max_priority_fee_per_gas: candid::Nat,
    pub max_fee_per_gas: candid::Nat,
    pub max_transaction_fee: candid::Nat,
    pub timestamp: Option<u64>,
    pub gas_limit: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum CanisterStatusType {
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "running")]
    Running,
}

#[derive(CandidType, Deserialize)]
pub enum LogVisibility {
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
}

#[derive(CandidType, Deserialize)]
pub struct DefiniteCanisterSettings {
    pub freezing_threshold: candid::Nat,
    pub controllers: Vec<Principal>,
    pub reserved_cycles_limit: candid::Nat,
    pub log_visibility: LogVisibility,
    pub wasm_memory_limit: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub compute_allocation: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct QueryStats {
    pub response_payload_bytes_total: candid::Nat,
    pub num_instructions_total: candid::Nat,
    pub num_calls_total: candid::Nat,
    pub request_payload_bytes_total: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct CanisterStatusResponse {
    pub status: CanisterStatusType,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
    pub settings: DefiniteCanisterSettings,
    pub query_stats: QueryStats,
    pub idle_cycles_burned_per_day: candid::Nat,
    pub module_hash: Option<serde_bytes::ByteBuf>,
    pub reserved_cycles: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct GetEventsArg {
    pub start: u64,
    pub length: u64,
}

pub type Subaccount = serde_bytes::ByteBuf;
#[derive(CandidType, Deserialize)]
pub struct EventSource {
    pub transaction_hash: String,
    pub log_index: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct UnsignedTransactionAccessListItem {
    pub storage_keys: Vec<serde_bytes::ByteBuf>,
    pub address: String,
}

#[derive(CandidType, Deserialize)]
pub struct UnsignedTransaction {
    pub destination: String,
    pub value: candid::Nat,
    pub max_priority_fee_per_gas: candid::Nat,
    pub data: serde_bytes::ByteBuf,
    pub max_fee_per_gas: candid::Nat,
    pub chain_id: candid::Nat,
    pub nonce: candid::Nat,
    pub gas_limit: candid::Nat,
    pub access_list: Vec<UnsignedTransactionAccessListItem>,
}

#[derive(CandidType, Deserialize)]
pub enum ReimbursementIndex {
    CkErc20 {
        cketh_ledger_burn_index: candid::Nat,
        ledger_id: Principal,
        ckerc20_ledger_burn_index: candid::Nat,
    },
    CkEth {
        ledger_burn_index: candid::Nat,
    },
}

#[derive(CandidType, Deserialize)]
pub enum TransactionReceiptStatus {
    Success,
    Failure,
}

#[derive(CandidType, Deserialize)]
pub struct TransactionReceipt {
    pub effective_gas_price: candid::Nat,
    pub status: TransactionReceiptStatus,
    pub transaction_hash: String,
    pub block_hash: String,
    pub block_number: candid::Nat,
    pub gas_used: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum EventPayload {
    SkippedBlock {
        block_number: candid::Nat,
        contract_address: Option<String>,
    },
    AcceptedErc20Deposit {
        principal: Principal,
        transaction_hash: String,
        value: candid::Nat,
        log_index: candid::Nat,
        subaccount: Option<Subaccount>,
        block_number: candid::Nat,
        erc20_contract_address: String,
        from_address: String,
    },
    SignedTransaction {
        raw_transaction: String,
        withdrawal_id: candid::Nat,
    },
    Upgrade(UpgradeArg),
    Init(InitArg),
    AddedCkErc20Token {
        ckerc20_ledger_id: Principal,
        chain_id: candid::Nat,
        address: String,
        ckerc20_token_symbol: String,
    },
    SyncedDepositWithSubaccountToBlock {
        block_number: candid::Nat,
    },
    QuarantinedDeposit {
        event_source: EventSource,
    },
    SyncedToBlock {
        block_number: candid::Nat,
    },
    AcceptedDeposit {
        principal: Principal,
        transaction_hash: String,
        value: candid::Nat,
        log_index: candid::Nat,
        subaccount: Option<Subaccount>,
        block_number: candid::Nat,
        from_address: String,
    },
    ReplacedTransaction {
        withdrawal_id: candid::Nat,
        transaction: UnsignedTransaction,
    },
    QuarantinedReimbursement {
        index: ReimbursementIndex,
    },
    MintedCkEth {
        event_source: EventSource,
        mint_block_index: candid::Nat,
    },
    ReimbursedEthWithdrawal {
        transaction_hash: Option<String>,
        withdrawal_id: candid::Nat,
        reimbursed_amount: candid::Nat,
        reimbursed_in_block: candid::Nat,
    },
    FailedErc20WithdrawalRequest {
        to: Principal,
        withdrawal_id: candid::Nat,
        reimbursed_amount: candid::Nat,
        to_subaccount: Option<serde_bytes::ByteBuf>,
    },
    ReimbursedErc20Withdrawal {
        burn_in_block: candid::Nat,
        transaction_hash: Option<String>,
        withdrawal_id: candid::Nat,
        reimbursed_amount: candid::Nat,
        ledger_id: Principal,
        reimbursed_in_block: candid::Nat,
    },
    MintedCkErc20 {
        event_source: EventSource,
        erc20_contract_address: String,
        mint_block_index: candid::Nat,
        ckerc20_token_symbol: String,
    },
    CreatedTransaction {
        withdrawal_id: candid::Nat,
        transaction: UnsignedTransaction,
    },
    InvalidDeposit {
        event_source: EventSource,
        reason: String,
    },
    SyncedErc20ToBlock {
        block_number: candid::Nat,
    },
    AcceptedErc20WithdrawalRequest {
        cketh_ledger_burn_index: candid::Nat,
        destination: String,
        ckerc20_ledger_id: Principal,
        withdrawal_amount: candid::Nat,
        from: Principal,
        created_at: u64,
        from_subaccount: Option<serde_bytes::ByteBuf>,
        erc20_contract_address: String,
        ckerc20_ledger_burn_index: candid::Nat,
        max_transaction_fee: candid::Nat,
    },
    AcceptedEthWithdrawalRequest {
        ledger_burn_index: candid::Nat,
        destination: String,
        withdrawal_amount: candid::Nat,
        from: Principal,
        created_at: Option<u64>,
        from_subaccount: Option<serde_bytes::ByteBuf>,
    },
    FinalizedTransaction {
        withdrawal_id: candid::Nat,
        transaction_receipt: TransactionReceipt,
    },
}

#[derive(CandidType, Deserialize)]
pub struct Event {
    pub timestamp: u64,
    pub payload: EventPayload,
}

#[derive(CandidType, Deserialize)]
pub struct GetEventsRet {
    pub total_event_count: u64,
    pub events: Vec<Event>,
}

#[derive(CandidType, Deserialize)]
pub struct CkErc20Token {
    pub erc20_contract_address: String,
    pub ledger_canister_id: Principal,
    pub ckerc20_token_symbol: String,
}

#[derive(CandidType, Deserialize)]
pub struct GasFeeEstimate {
    pub max_priority_fee_per_gas: candid::Nat,
    pub max_fee_per_gas: candid::Nat,
    pub timestamp: u64,
}

#[derive(CandidType, Deserialize)]
pub struct MinterInfoErc20BalancesInnerItem {
    pub balance: candid::Nat,
    pub erc20_contract_address: String,
}

#[derive(CandidType, Deserialize)]
pub struct MinterInfo {
    pub deposit_with_subaccount_helper_contract_address: Option<String>,
    pub eth_balance: Option<candid::Nat>,
    pub eth_helper_contract_address: Option<String>,
    pub last_observed_block_number: Option<candid::Nat>,
    pub evm_rpc_id: Option<Principal>,
    pub erc20_helper_contract_address: Option<String>,
    pub last_erc20_scraped_block_number: Option<candid::Nat>,
    pub supported_ckerc20_tokens: Option<Vec<CkErc20Token>>,
    pub last_gas_fee_estimate: Option<GasFeeEstimate>,
    pub cketh_ledger_id: Option<Principal>,
    pub smart_contract_address: Option<String>,
    pub last_eth_scraped_block_number: Option<candid::Nat>,
    pub minimum_withdrawal_amount: Option<candid::Nat>,
    pub erc20_balances: Option<Vec<MinterInfoErc20BalancesInnerItem>>,
    pub minter_address: Option<String>,
    pub last_deposit_with_subaccount_scraped_block_number: Option<candid::Nat>,
    pub ethereum_block_height: Option<BlockTag>,
}

#[derive(CandidType, Deserialize)]
pub struct EthTransaction {
    pub transaction_hash: String,
}

#[derive(CandidType, Deserialize)]
pub enum TxFinalizedStatus {
    Success {
        transaction_hash: String,
        effective_transaction_fee: Option<candid::Nat>,
    },
    Reimbursed {
        transaction_hash: String,
        reimbursed_amount: candid::Nat,
        reimbursed_in_block: candid::Nat,
    },
    PendingReimbursement(EthTransaction),
}

#[derive(CandidType, Deserialize)]
pub enum RetrieveEthStatus {
    NotFound,
    TxFinalized(TxFinalizedStatus),
    TxSent(EthTransaction),
    TxCreated,
    Pending,
}

#[derive(CandidType, Deserialize)]
pub struct WithdrawErc20Arg {
    pub ckerc20_ledger_id: Principal,
    pub recipient: String,
    pub from_cketh_subaccount: Option<Subaccount>,
    pub from_ckerc20_subaccount: Option<Subaccount>,
    pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct RetrieveErc20Request {
    pub ckerc20_block_index: candid::Nat,
    pub cketh_block_index: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum LedgerError {
    TemporarilyUnavailable(String),
    InsufficientAllowance {
        token_symbol: String,
        ledger_id: Principal,
        allowance: candid::Nat,
        failed_burn_amount: candid::Nat,
    },
    AmountTooLow {
        minimum_burn_amount: candid::Nat,
        token_symbol: String,
        ledger_id: Principal,
        failed_burn_amount: candid::Nat,
    },
    InsufficientFunds {
        balance: candid::Nat,
        token_symbol: String,
        ledger_id: Principal,
        failed_burn_amount: candid::Nat,
    },
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawErc20Error {
    TokenNotSupported {
        supported_tokens: Vec<CkErc20Token>,
    },
    TemporarilyUnavailable(String),
    CkErc20LedgerError {
        error: LedgerError,
        cketh_block_index: candid::Nat,
    },
    CkEthLedgerError {
        error: LedgerError,
    },
    RecipientAddressBlocked {
        address: String,
    },
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawErc20Ret {
    Ok(RetrieveErc20Request),
    Err(WithdrawErc20Error),
}

#[derive(CandidType, Deserialize)]
pub struct WithdrawalArg {
    pub recipient: String,
    pub from_subaccount: Option<Subaccount>,
    pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct RetrieveEthRequest {
    pub block_index: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawalError {
    TemporarilyUnavailable(String),
    InsufficientAllowance { allowance: candid::Nat },
    AmountTooLow { min_withdrawal_amount: candid::Nat },
    RecipientAddressBlocked { address: String },
    InsufficientFunds { balance: candid::Nat },
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawEthRet {
    Ok(RetrieveEthRequest),
    Err(WithdrawalError),
}

#[derive(CandidType, Deserialize)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<serde_bytes::ByteBuf>,
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawalSearchParameter {
    ByRecipient(String),
    BySenderAccount(Account),
    ByWithdrawalId(u64),
}

#[derive(CandidType, Deserialize)]
pub enum WithdrawalStatus {
    TxFinalized(TxFinalizedStatus),
    TxSent(EthTransaction),
    TxCreated,
    Pending,
}

#[derive(CandidType, Deserialize)]
pub struct WithdrawalDetail {
    pub status: WithdrawalStatus,
    pub token_symbol: String,
    pub withdrawal_amount: candid::Nat,
    pub withdrawal_id: u64,
    pub from: Principal,
    pub from_subaccount: Option<serde_bytes::ByteBuf>,
    pub max_transaction_fee: Option<candid::Nat>,
    pub recipient_address: String,
}

pub struct Service(pub Principal);
impl Service {
    pub async fn add_ckerc_20_token(&self, arg0: AddCkErc20Token) -> Result<()> {
        ic_cdk::call(self.0, "add_ckerc20_token", (arg0,)).await
    }
    pub async fn eip_1559_transaction_price(
        &self,
        arg0: Option<Eip1559TransactionPriceArg>,
    ) -> Result<(Eip1559TransactionPrice,)> {
        ic_cdk::call(self.0, "eip_1559_transaction_price", (arg0,)).await
    }
    pub async fn get_canister_status(&self) -> Result<(CanisterStatusResponse,)> {
        ic_cdk::call(self.0, "get_canister_status", ()).await
    }
    pub async fn get_events(&self, arg0: GetEventsArg) -> Result<(GetEventsRet,)> {
        ic_cdk::call(self.0, "get_events", (arg0,)).await
    }
    pub async fn get_minter_info(&self) -> Result<(MinterInfo,)> {
        ic_cdk::call(self.0, "get_minter_info", ()).await
    }
    pub async fn is_address_blocked(&self, arg0: String) -> Result<(bool,)> {
        ic_cdk::call(self.0, "is_address_blocked", (arg0,)).await
    }
    pub async fn minter_address(&self) -> Result<(String,)> {
        ic_cdk::call(self.0, "minter_address", ()).await
    }
    pub async fn retrieve_eth_status(&self, arg0: u64) -> Result<(RetrieveEthStatus,)> {
        ic_cdk::call(self.0, "retrieve_eth_status", (arg0,)).await
    }
    pub async fn smart_contract_address(&self) -> Result<(String,)> {
        ic_cdk::call(self.0, "smart_contract_address", ()).await
    }
    pub async fn withdraw_erc_20(&self, arg0: WithdrawErc20Arg) -> Result<(WithdrawErc20Ret,)> {
        ic_cdk::call(self.0, "withdraw_erc20", (arg0,)).await
    }
    pub async fn withdraw_eth(&self, arg0: WithdrawalArg) -> Result<(WithdrawEthRet,)> {
        ic_cdk::call(self.0, "withdraw_eth", (arg0,)).await
    }
    pub async fn withdrawal_status(
        &self,
        arg0: WithdrawalSearchParameter,
    ) -> Result<(Vec<WithdrawalDetail>,)> {
        ic_cdk::call(self.0, "withdrawal_status", (arg0,)).await
    }
}
