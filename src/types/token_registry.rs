use std::collections::HashMap;
use candid::{CandidType, Decode, Encode, Principal};
use serde::{Deserialize, Serialize};
use ic_stable_structures::{Storable, storable::Bound};
use std::borrow::Cow;

use crate::{
    currency_error::CurrencyError, 
    types::currency::{Currency, CKTokenSymbol},
};

use super::{canister_wallets::icrc1_token_wallet::{GenericICRC1TokenWallet, ICRC1TokenMetadata}, currency::Token};

// Maximum size for storing the registry
const MAX_VALUE_SIZE_TOKEN_REGISTRY: u32 = 10_000_000;

/// Registry for tracking ICRC-1 tokens
#[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
pub struct ICRC1TokenRegistry {
    // Map of ledger canister ID to token metadata
    tokens: HashMap<String, ICRC1TokenMetadata>,
    // Map of token symbol to ledger canister ID
    symbol_to_canister: HashMap<String, String>,
}

impl Default for ICRC1TokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ICRC1TokenRegistry {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            symbol_to_canister: HashMap::new(),
        }
    }
    
    /// Register a new token by its ledger canister ID
    pub async fn register_token(&mut self, ledger_id: Principal) -> Result<ICRC1TokenMetadata, CurrencyError> {
        let ledger_id_str = ledger_id.to_string();
        
        // Skip if already registered
        if self.tokens.contains_key(&ledger_id_str) {
            return Ok(self.tokens.get(&ledger_id_str).unwrap().clone());
        }
        
        // Query token metadata
        let metadata = GenericICRC1TokenWallet::query_token_metadata(ledger_id).await?;
        
        // Store in maps
        self.symbol_to_canister.insert(metadata.symbol.clone(), ledger_id_str.clone());
        self.tokens.insert(ledger_id_str, metadata.clone());
        
        Ok(metadata)
    }
    
    /// Check if a token is already registered by ledger ID
    pub fn is_token_registered(&self, ledger_id: &Principal) -> bool {
        self.tokens.contains_key(&ledger_id.to_string())
    }
    
    /// Check if a token is already registered by symbol
    pub fn is_symbol_registered(&self, symbol: &str) -> bool {
        self.symbol_to_canister.contains_key(symbol)
    }
    
    /// Get token metadata by ledger ID
    pub fn get_token_metadata(&self, ledger_id: &Principal) -> Option<ICRC1TokenMetadata> {
        self.tokens.get(&ledger_id.to_string()).cloned()
    }
    
    /// Get ledger ID by symbol
    pub fn get_ledger_by_symbol(&self, symbol: &str) -> Option<Principal> {
        self.symbol_to_canister.get(symbol)
            .and_then(|id_str| Principal::from_text(id_str).ok())
    }
    
    /// Get all registered tokens
    pub fn get_all_tokens(&self) -> Vec<(Principal, ICRC1TokenMetadata)> {
        self.tokens.iter()
            .filter_map(|(id_str, metadata)| {
                Principal::from_text(id_str).ok().map(|id| (id, metadata.clone()))
            })
            .collect()
    }
    
    /// Convert a token into a Currency enum
    pub fn to_currency(&self, ledger_id: &Principal) -> Option<Currency> {
        // First check if it's one of our predefined tokens
        let metadata = self.get_token_metadata(ledger_id)?;
        
        // Check if it's one of our predefined tokens
        match metadata.symbol.as_str() {
            "ICP" => Some(Currency::ICP),
            "ckBTC" => Some(Currency::BTC),
            "ckETH" => Some(Currency::CKETHToken(CKTokenSymbol::ETH)),
            "ckUSDC" => Some(Currency::CKETHToken(CKTokenSymbol::USDC)),
            "ckUSDT" => Some(Currency::CKETHToken(CKTokenSymbol::USDT)),
            // For any other token, we can create a new Currency variant
            // This would require extending your Currency enum
            symbol => Some(Currency::GenericICRC1(Token::from_string(*ledger_id, symbol, metadata.decimals))),
        }
    }
}

impl Storable for ICRC1TokenRegistry {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap_or_else(|e| {
            ic_cdk::println!("TokenRegistry serialization error: {:?}", e);
            vec![]
        }))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap_or_else(|e| {
            ic_cdk::println!("TokenRegistry deserialization error: {:?}", e);
            Self::new()
        })
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_VALUE_SIZE_TOKEN_REGISTRY,
        is_fixed_size: false,
    };
}
