use bs58;
use sha2::{Sha256, Digest};
use hex;

use crate::currency_error::CurrencyError;

/// Validate a Tron address (Base58Check format, starts with 'T')
pub fn validate_tron_address(address: &str) -> Result<(), CurrencyError> {
    // Check if address starts with 'T'
    if !address.starts_with('T') {
        return Err(CurrencyError::InvalidAddress(
            "Tron address must start with 'T'".to_string()
        ));
    }

    // Check length (Tron addresses are typically 34 characters)
    if address.len() != 34 {
        return Err(CurrencyError::InvalidAddress(
            format!("Invalid Tron address length: {} (expected 34)", address.len())
        ));
    }

    // Try to decode Base58
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|_| CurrencyError::InvalidAddress("Invalid Base58 encoding".to_string()))?;

    // Tron address is 25 bytes: 1 byte prefix (0x41) + 20 bytes address + 4 bytes checksum
    if decoded.len() != 25 {
        return Err(CurrencyError::InvalidAddress(
            format!("Invalid decoded length: {} (expected 25)", decoded.len())
        ));
    }

    // Verify checksum
    let address_bytes = &decoded[..21];
    let checksum = &decoded[21..25];
    
    let mut hasher = Sha256::new();
    hasher.update(address_bytes);
    let hash1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let hash2 = hasher.finalize();
    
    let calculated_checksum = &hash2[..4];
    
    if checksum != calculated_checksum {
        return Err(CurrencyError::InvalidAddress("Invalid checksum".to_string()));
    }

    Ok(())
}

/// Convert Tron Base58 address to hex format
pub fn base58_to_hex(address: &str) -> Result<String, CurrencyError> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|_| CurrencyError::InvalidAddress("Invalid Base58 encoding".to_string()))?;
    
    // Skip the checksum (last 4 bytes)
    let address_bytes = &decoded[..21];
    
    Ok(hex::encode(address_bytes))
}

/// Convert hex address to Tron Base58 format
pub fn hex_to_base58(hex_str: &str) -> Result<String, CurrencyError> {
    let hex_str = hex_str.trim_start_matches("0x");
    let address_bytes = hex::decode(hex_str)
        .map_err(|_| CurrencyError::InvalidAddress("Invalid hex encoding".to_string()))?;
    
    if address_bytes.len() != 21 {
        return Err(CurrencyError::InvalidAddress(
            format!("Invalid hex address length: {} (expected 21)", address_bytes.len())
        ));
    }
    
    // Calculate checksum
    let mut hasher = Sha256::new();
    hasher.update(&address_bytes);
    let hash1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let hash2 = hasher.finalize();
    
    let checksum = &hash2[..4];
    
    // Combine address + checksum
    let mut full_address = address_bytes.to_vec();
    full_address.extend_from_slice(checksum);
    
    // Encode to Base58
    Ok(bs58::encode(&full_address).into_string())
}

/// Format amount from smallest unit to human-readable format
pub fn format_usdt_amount(amount: u64) -> String {
    let whole = amount / 1_000_000;
    let fraction = amount % 1_000_000;
    format!("{}.{:06}", whole, fraction)
}

/// Parse amount from human-readable format to smallest unit
pub fn parse_usdt_amount(amount_str: &str) -> Result<u64, CurrencyError> {
    let parts: Vec<&str> = amount_str.split('.').collect();
    
    match parts.len() {
        1 => {
            // No decimal point, treat as whole USDT
            let whole: u64 = parts[0]
                .parse()
                .map_err(|_| CurrencyError::InvalidAmount("Invalid amount format".to_string()))?;
            Ok(whole * 1_000_000)
        }
        2 => {
            // Has decimal point
            let whole: u64 = parts[0]
                .parse()
                .map_err(|_| CurrencyError::InvalidAmount("Invalid amount format".to_string()))?;
            
            // Pad or truncate to 6 decimal places
            let fraction_str = format!("{:0<6}", parts[1]);
            let fraction: u64 = fraction_str[..6]
                .parse()
                .map_err(|_| CurrencyError::InvalidAmount("Invalid amount format".to_string()))?;
            
            Ok(whole * 1_000_000 + fraction)
        }
        _ => Err(CurrencyError::InvalidAmount("Invalid amount format".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_usdt_amount() {
        assert_eq!(format_usdt_amount(1_000_000), "1.000000");
        assert_eq!(format_usdt_amount(1_500_000), "1.500000");
        assert_eq!(format_usdt_amount(100), "0.000100");
    }

    #[test]
    fn test_parse_usdt_amount() {
        assert_eq!(parse_usdt_amount("1").unwrap(), 1_000_000);
        assert_eq!(parse_usdt_amount("1.5").unwrap(), 1_500_000);
        assert_eq!(parse_usdt_amount("0.000100").unwrap(), 100);
    }

    #[test]
    fn test_validate_tron_address() {
        // Valid mainnet address (known good address)
        // TQn9Y2khEsLMWDmPxKvFJN1dFMjv1kZ5E is a valid Tron address
        // Note: We'll test with a known valid address or test the validation logic
        
        // Invalid: doesn't start with T
        assert!(validate_tron_address("AG3XXyExBkPp9nzdajDZsozEu4BkaSJozs").is_err());
        
        // Invalid: wrong length
        assert!(validate_tron_address("TG3XXy").is_err());
        assert!(validate_tron_address("T").is_err());
        assert!(validate_tron_address("TG3XXyExBkPp9nzdajDZsozEu4BkaSJozsExtra").is_err());
        
        // Invalid: empty string
        assert!(validate_tron_address("").is_err());
        
        // Invalid: wrong prefix (should be T for Tron)
        assert!(validate_tron_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err()); // Bitcoin address
    }

    #[test]
    fn test_base58_to_hex() {
        // Test with a valid Tron address
        // This will decode the Base58, but we can't verify exact hex without knowing the address
        let result = base58_to_hex("TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs");
        // Should succeed if address is valid Base58
        assert!(result.is_ok());
        
        // Invalid Base58
        assert!(base58_to_hex("Invalid!@#").is_err());
    }

    #[test]
    fn test_hex_to_base58() {
        // Test with valid hex (21 bytes = 42 hex chars)
        let hex = format!("41{}", "0".repeat(40)); // 0x41 prefix + 20 bytes of zeros
        let result = hex_to_base58(&hex);
        assert!(result.is_ok());
        
        // Test with 0x prefix
        let hex_with_prefix = format!("0x{}", hex);
        let result2 = hex_to_base58(&hex_with_prefix);
        assert!(result2.is_ok());
        
        // Invalid: wrong length
        assert!(hex_to_base58("41").is_err());
        assert!(hex_to_base58("414141").is_err());
        
        // Invalid: non-hex characters
        assert!(hex_to_base58("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn test_amount_formatting_roundtrip() {
        // Test roundtrip: parse -> format -> parse
        let amounts = vec![
            1_000_000u64,
            1_500_000u64,
            100u64,
            0u64,
            999_999_999_999u64,
        ];
        
        for amount in amounts {
            let formatted = format_usdt_amount(amount);
            let parsed = parse_usdt_amount(&formatted).unwrap();
            assert_eq!(amount, parsed, "Roundtrip failed for amount: {}", amount);
        }
    }

    #[test]
    fn test_parse_usdt_amount_edge_cases() {
        // Test various input formats
        assert_eq!(parse_usdt_amount("0").unwrap(), 0);
        assert_eq!(parse_usdt_amount("0.0").unwrap(), 0);
        assert_eq!(parse_usdt_amount("0.000000").unwrap(), 0);
        assert_eq!(parse_usdt_amount("1.123456").unwrap(), 1_123_456);
        assert_eq!(parse_usdt_amount("100.5").unwrap(), 100_500_000);
        
        // Test truncation (more than 6 decimals)
        assert_eq!(parse_usdt_amount("1.1234567").unwrap(), 1_123_456);
        
        // Invalid formats
        assert!(parse_usdt_amount("1.2.3").is_err());
        assert!(parse_usdt_amount("abc").is_err());
        assert!(parse_usdt_amount("").is_err());
    }
}

