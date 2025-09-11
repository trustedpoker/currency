use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, CandidType, Deserialize, PartialEq, Eq, Copy)]
pub struct CKTokenConfig {
    pub minter_id: Principal,
    pub ledger_id: Principal,
    pub token_symbol: Currency,
    pub decimals: u8,
    pub fee: u128,
}

#[derive(Debug, Clone, Serialize, CandidType, Deserialize, PartialEq, Eq, Hash, Copy)]
pub struct Token {
    pub ledger_id: Principal,
    pub symbol: [u8; 8],
    pub decimals: u8,
}

impl Token {
    // Convert a String to Token (with the [u8; 8] symbol)
    pub fn from_string(ledger_id: Principal, symbol: &str, decimals: u8) -> Self {
        let mut symbol_bytes = [0u8; 8];
        // Copy bytes from the string to the array, up to the length of the array
        for (i, byte) in symbol.as_bytes().iter().enumerate() {
            if i >= 8 {
                break; // Prevent out-of-bounds access
            }
            symbol_bytes[i] = *byte;
        }

        Token {
            ledger_id,
            symbol: symbol_bytes,
            decimals,
        }
    }

    // Convert Token's [u8; 8] symbol to a String
    pub fn symbol_to_string(&self) -> String {
        // Find the first zero byte (end of the string)
        let end = self.symbol.iter()
            .position(|&b| b == 0)
            .unwrap_or(self.symbol.len());
        
        // Convert only the valid bytes to a String
        String::from_utf8_lossy(&self.symbol[0..end]).to_string()
    }
}

#[derive(Debug, Clone, Serialize, CandidType, Deserialize, PartialEq, Eq, Copy, Hash)]
pub enum CKTokenSymbol {
    USDC,
    USDT,
    ETH,
}

#[derive(Debug, Clone, Serialize, CandidType, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum Currency {
    ICP,
    CKETHToken(CKTokenSymbol),
    BTC,
    GenericICRC1(Token)
}

impl Currency {
    pub fn decimals(&self) -> u8 {
        match self {
            Currency::ICP => 8,
            Currency::CKETHToken(token) => match token {
                CKTokenSymbol::ETH => 18,
                _ => 6,
            },
            Currency::BTC => 8,
            Currency::GenericICRC1(token) => token.decimals,
        }
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Currency::ICP => write!(f, "ICP"),
            Currency::CKETHToken(ck_token) => write!(f, "{:?}", ck_token),
            Currency::BTC => write!(f, "BTC"),
            Currency::GenericICRC1(token) => write!(f, "{}", token.symbol_to_string()),
        }
    }
}

// implement from and to u8 for Currency
impl From<u8> for Currency {
    fn from(value: u8) -> Self {
        match value {
            0 => Currency::ICP,
            1 => Currency::CKETHToken(CKTokenSymbol::USDC),
            2 => Currency::CKETHToken(CKTokenSymbol::USDT),
            3 => Currency::CKETHToken(CKTokenSymbol::ETH),
            4 => Currency::BTC,
            _ => panic!("Invalid currency value"),
        }
    }
}

impl From<Currency> for u8 {
    fn from(value: Currency) -> Self {
        match value {
            Currency::ICP => 0,
            Currency::CKETHToken(token) => match token {
                CKTokenSymbol::USDC => 1,
                CKTokenSymbol::USDT => 2,
                CKTokenSymbol::ETH => 3,
            },
            Currency::BTC => 4,
            Currency::GenericICRC1(_) => 5,
        }
    }
}
