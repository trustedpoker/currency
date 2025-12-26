use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};

// Note: Using deprecated API for compatibility. Will update to management_canister root module in future.
use serde_json;

use crate::currency_error::CurrencyError;
use super::types::*;

/// TronGrid API client using IC HTTP outcalls
pub struct TronHttpClient {
    pub api_url: String,
    pub api_key: Option<String>,
}

impl TronHttpClient {
    /// Create a new TronHttpClient for mainnet
    pub fn mainnet(api_key: Option<String>) -> Self {
        Self {
            api_url: "https://api.trongrid.io".to_string(),
            api_key,
        }
    }

    /// Create a new TronHttpClient for testnet (Shasta)
    pub fn testnet(api_key: Option<String>) -> Self {
        Self {
            api_url: "https://api.shasta.trongrid.io".to_string(),
            api_key,
        }
    }

    /// Get new deposits for a specific address
    ///
    /// This method queries TronGrid API for TRC-20 USDT transactions
    /// received by the specified address since the last check.
    ///
    /// # Parameters
    /// * `address` - The Tron address to check
    /// * `last_checked_timestamp` - Unix timestamp (ms) of last check
    ///
    /// # Returns
    /// * Vector of new deposit transactions
    pub async fn get_address_deposits(
        &self,
        address: &str,
        last_checked_timestamp: u64,
    ) -> Result<Vec<TronTxInfo>, CurrencyError> {
        // Use TronGrid API to get TRC-20 transactions for this address
        let url = format!(
            "{}/v1/accounts/{}/transactions/trc20?only_confirmed=true&only_to=true&limit=20",
            self.api_url, address
        );

        let response = self.get_request(&url).await?;

        // Parse response
        let tx_response: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to parse transactions: {}", e)))?;

        let mut deposits = Vec::new();

        // Extract transactions
        if let Some(data) = tx_response.get("data").and_then(|d| d.as_array()) {
            for tx in data {
                // Filter by timestamp
                if let Some(timestamp) = tx.get("block_timestamp").and_then(|t| t.as_u64()) {
                    if timestamp <= last_checked_timestamp {
                        continue; // Skip old transactions
                    }
                }

                // Extract transaction details
                if let (Some(tx_id), Some(value_str), Some(from), Some(to)) = (
                    tx.get("transaction_id").and_then(|t| t.as_str()),
                    tx.get("value").and_then(|v| v.as_str()),
                    tx.get("from").and_then(|f| f.as_str()),
                    tx.get("to").and_then(|t| t.as_str()),
                ) {
                    deposits.push(TronTxInfo {
                        tx_id: tx_id.to_string(),
                        block_number: tx.get("block_number").and_then(|b| b.as_u64()).unwrap_or(0),
                        block_timestamp: tx.get("block_timestamp").and_then(|t| t.as_u64()).unwrap_or(0),
                        from: from.to_string(),
                        to: to.to_string(),
                        value: value_str.to_string(),
                        confirmed: true, // only_confirmed=true in query
                    });
                }
            }
        }

        Ok(deposits)
    }

    /// Get transaction information by hash
    pub async fn get_transaction_info(&self, tx_hash: &str) -> Result<TronTxInfo, CurrencyError> {
        let url = format!("{}/wallet/gettransactionbyid", self.api_url);
        
        let body = serde_json::json!({
            "value": tx_hash
        });

        let response = self.post_request(&url, &body).await?;
        
        // Parse response
        let tx_response: TronGridTransactionResponse = serde_json::from_slice(&response.body)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to parse transaction: {}", e)))?;

        // Extract TRC-20 transfer info from contract data
        self.parse_trc20_transfer(tx_response)
    }

    /// Broadcast a signed transaction
    pub async fn broadcast_transaction(&self, signed_tx: &SignedTransaction) -> Result<String, CurrencyError> {
        let url = format!("{}/wallet/broadcasttransaction", self.api_url);
        
        let body = serde_json::to_value(signed_tx)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to serialize transaction: {}", e)))?;

        let response = self.post_request(&url, &body).await?;
        
        let broadcast_response: BroadcastResponse = serde_json::from_slice(&response.body)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to parse broadcast response: {}", e)))?;

        if broadcast_response.result {
            broadcast_response.tx_id
                .ok_or_else(|| CurrencyError::InvalidResponse("No tx_id in response".to_string()))
        } else {
            Err(CurrencyError::InvalidResponse(format!(
                "Broadcast failed: {:?} - {:?}",
                broadcast_response.code,
                broadcast_response.message
            )))
        }
    }

    /// Get account balance (for hot wallet monitoring)
    pub async fn get_account_balance(&self, address: &str) -> Result<u64, CurrencyError> {
        let url = format!("{}/wallet/getaccount", self.api_url);
        
        let body = serde_json::json!({
            "address": address,
            "visible": true
        });

        let response = self.post_request(&url, &body).await?;
        
        let account_info: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to parse account: {}", e)))?;

        // For TRC-20, we need to call a different endpoint
        self.get_trc20_balance(address).await
    }

    /// Get TRC-20 USDT balance
    pub async fn get_trc20_balance(&self, address: &str) -> Result<u64, CurrencyError> {
        let url = format!("{}/v1/accounts/{}/transactions/trc20", self.api_url, address);
        
        // Note: This is a simplified version. In production, you'd use the contract call
        // to get the exact balance via the balanceOf function
        
        let response = self.get_request(&url).await?;
        
        // Parse and return balance
        // This is a placeholder - actual implementation would call the contract's balanceOf function
        Ok(0)
    }

    /// Make a POST request to TronGrid API
    async fn post_request(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse, CurrencyError> {
        let mut headers = vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ];

        // Add API key if provided
        if let Some(api_key) = &self.api_key {
            headers.push(HttpHeader {
                name: "TRON-PRO-API-KEY".to_string(),
                value: api_key.clone(),
            });
        }

        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| CurrencyError::InvalidResponse(format!("Failed to serialize body: {}", e)))?;

        let request = CanisterHttpRequestArgument {
            url: url.to_string(),
            method: HttpMethod::POST,
            body: Some(body_bytes),
            max_response_bytes: Some(10_000), // 10KB max response
            transform: Some(TransformContext::from_name(
                "transform_http_response".to_string(),
                vec![],
            )),
            headers,
        };

        // 2B cycles per request (user pays this)
        let cycles = 2_000_000_000u128;

        match http_request(request, cycles).await {
            Ok((response,)) => {
                if response.status >= 200u64 && response.status < 300u64 {
                    Ok(response)
                } else {
                    Err(CurrencyError::InvalidResponse(format!(
                        "HTTP error: {}",
                        response.status
                    )))
                }
            }
            Err((r, m)) => Err(CurrencyError::InvalidResponse(format!(
                "HTTP request failed: {:?} - {}",
                r, m
            ))),
        }
    }

    /// Make a GET request to TronGrid API
    async fn get_request(&self, url: &str) -> Result<HttpResponse, CurrencyError> {
        let mut headers = vec![];

        if let Some(api_key) = &self.api_key {
            headers.push(HttpHeader {
                name: "TRON-PRO-API-KEY".to_string(),
                value: api_key.clone(),
            });
        }

        let request = CanisterHttpRequestArgument {
            url: url.to_string(),
            method: HttpMethod::GET,
            body: None,
            max_response_bytes: Some(10_000),
            transform: Some(TransformContext::from_name(
                "transform_http_response".to_string(),
                vec![],
            )),
            headers,
        };

        let cycles = 2_000_000_000u128;

        match http_request(request, cycles).await {
            Ok((response,)) => {
                if response.status >= 200u64 && response.status < 300u64 {
                    Ok(response)
                } else {
                    Err(CurrencyError::InvalidResponse(format!(
                        "HTTP error: {}",
                        response.status
                    )))
                }
            }
            Err((r, m)) => Err(CurrencyError::InvalidResponse(format!(
                "HTTP request failed: {:?} - {}",
                r, m
            ))),
        }
    }

    /// Parse TRC-20 transfer from transaction response
    fn parse_trc20_transfer(&self, tx_response: TronGridTransactionResponse) -> Result<TronTxInfo, CurrencyError> {
        // Check if transaction succeeded
        if tx_response.ret.is_empty() {
            return Err(CurrencyError::InvalidResponse("No return value in transaction".to_string()));
        }

        if tx_response.ret[0].contract_ret != "SUCCESS" {
            return Err(CurrencyError::InvalidResponse(format!(
                "Transaction failed: {}",
                tx_response.ret[0].contract_ret
            )));
        }

        // Extract contract data
        if tx_response.raw_data.contract.is_empty() {
            return Err(CurrencyError::InvalidResponse("No contract in transaction".to_string()));
        }

        let contract = &tx_response.raw_data.contract[0];
        
        // For TRC-20 transfers, we need to decode the contract parameter
        // This is a simplified version - actual implementation would decode the data field
        
        let _value = &contract.parameter.value;
        
        // Extract from, to, and amount from the contract data
        // Note: This is a placeholder. Actual implementation needs to:
        // 1. Verify the contract address is the USDT contract
        // 2. Decode the 'data' field which contains the transfer(address,uint256) call
        // 3. Extract the recipient address and amount from the decoded data
        
        Ok(TronTxInfo {
            tx_id: tx_response.tx_id,
            block_number: tx_response.blockNumber.unwrap_or(0),
            block_timestamp: tx_response.block_timestamp.unwrap_or(0),
            from: "".to_string(), // TODO: Extract from contract data
            to: "".to_string(),   // TODO: Extract from contract data
            value: "0".to_string(), // TODO: Extract from contract data
            confirmed: tx_response.blockNumber.is_some(),
        })
    }

    /// Get recent TRC-20 USDT transactions for an address
    /// 
    /// Fetches incoming TRC-20 transactions to the specified address.
    /// This is used to auto-detect deposits without requiring tx hash input.
    /// 
    /// # Parameters
    /// * `address` - The Tron address to check
    /// * `limit` - Maximum number of transactions to fetch
    /// 
    /// # Returns
    /// * Vector of TronTxInfo for incoming transactions
    /// 
    /// # Note
    /// For MVP, this returns a placeholder. Full implementation requires:
    /// - TronGrid API endpoint: /v1/accounts/{address}/transactions/trc20
    /// - Filtering for USDT contract: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t (mainnet)
    /// - Parsing transaction data to extract sender, amount, etc.
    pub async fn get_trc20_transactions(
        &self,
        _address: &str,
        _limit: u32,
    ) -> Result<Vec<TronTxInfo>, CurrencyError> {
        // For MVP, return empty list
        // Full implementation would:
        // 1. Call TronGrid API: GET /v1/accounts/{address}/transactions/trc20
        // 2. Filter for USDT contract address
        // 3. Parse each transaction to extract from, to, amount
        // 4. Return only confirmed transactions
        
        // Example URL: https://api.trongrid.io/v1/accounts/{address}/transactions/trc20?limit={limit}&contract_address=TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
        
        Ok(vec![])
    }
}

/// Transform function for HTTP responses (required by IC HTTP outcalls)
#[ic_cdk::query]
fn transform_http_response(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tron_http_client_creation() {
        // Test mainnet client creation
        let mainnet_client = TronHttpClient::mainnet(None);
        assert_eq!(mainnet_client.api_url, "https://api.trongrid.io");
        assert!(mainnet_client.api_key.is_none());

        let mainnet_with_key = TronHttpClient::mainnet(Some("test-key".to_string()));
        assert_eq!(mainnet_with_key.api_url, "https://api.trongrid.io");
        assert_eq!(mainnet_with_key.api_key, Some("test-key".to_string()));

        // Test testnet client creation
        let testnet_client = TronHttpClient::testnet(None);
        assert_eq!(testnet_client.api_url, "https://api.shasta.trongrid.io");
        assert!(testnet_client.api_key.is_none());

        let testnet_with_key = TronHttpClient::testnet(Some("test-key".to_string()));
        assert_eq!(testnet_with_key.api_url, "https://api.shasta.trongrid.io");
        assert_eq!(testnet_with_key.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_parse_trc20_transfer_error_cases() {
        let client = TronHttpClient::mainnet(None);
        
        // Test empty ret array
        let empty_ret = TronGridTransactionResponse {
            ret: vec![],
            tx_id: "test".to_string(),
            raw_data: TronGridRawData {
                contract: vec![],
                timestamp: 0,
            },
            blockNumber: None,
            block_timestamp: None,
        };
        assert!(client.parse_trc20_transfer(empty_ret).is_err());

        // Test failed transaction
        let failed_tx = TronGridTransactionResponse {
            ret: vec![TronGridRet {
                contract_ret: "FAILED".to_string(),
            }],
            tx_id: "test".to_string(),
            raw_data: TronGridRawData {
                contract: vec![],
                timestamp: 0,
            },
            blockNumber: None,
            block_timestamp: None,
        };
        assert!(client.parse_trc20_transfer(failed_tx).is_err());

        // Test empty contract array
        let no_contract = TronGridTransactionResponse {
            ret: vec![TronGridRet {
                contract_ret: "SUCCESS".to_string(),
            }],
            tx_id: "test".to_string(),
            raw_data: TronGridRawData {
                contract: vec![],
                timestamp: 0,
            },
            blockNumber: None,
            block_timestamp: None,
        };
        assert!(client.parse_trc20_transfer(no_contract).is_err());
    }

    // Note: Actual HTTP request tests would require:
    // 1. Mocking the IC HTTP outcall system (complex)
    // 2. Integration tests with actual TronGrid API (requires network)
    // 3. Testnet environment setup
    // These are deferred to Day 3+ when we do integration testing
}

