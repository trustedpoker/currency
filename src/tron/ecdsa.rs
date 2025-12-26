/// IC Threshold ECDSA integration for Tron address derivation and signing
///
/// This module uses Internet Computer's threshold ECDSA to:
/// 1. Derive unique Tron addresses for each user
/// 2. Sign withdrawal transactions securely
///
/// Benefits:
/// - No single private key (distributed across subnet)
/// - Each user gets unique address derived from their Principal
/// - Secure signing without key extraction

use candid::Principal;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    SignWithEcdsaArgument,
};
use sha2::{Sha256, Digest};
use sha3::Keccak256;

use crate::currency_error::CurrencyError;
use super::utils::public_key_to_tron_address;

/// Key ID for IC threshold ECDSA (secp256k1)
/// Note: Use test key for development, production key for mainnet
pub fn get_ecdsa_key_id(is_production: bool) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: if is_production {
            "key_1".to_string() // Production key
        } else {
            "dfx_test_key".to_string() // Local/test key
        },
    }
}

/// Derive a unique Tron address for a user based on their Principal
///
/// This function uses IC's threshold ECDSA to generate a deterministic
/// public key for each user, which is then converted to a Tron address.
///
/// # Parameters
/// * `user_principal` - The user's IC Principal
/// * `is_production` - Whether to use production or test ECDSA key
///
/// # Returns
/// * `(tron_address, public_key)` - The derived Tron address and public key bytes
pub async fn derive_tron_address_for_user(
    user_principal: Principal,
    is_production: bool,
) -> Result<(String, Vec<u8>), CurrencyError> {
    // Create derivation path from user's principal
    // This ensures each user gets a unique, deterministic address
    let derivation_path = vec![user_principal.as_slice().to_vec()];
    
    let key_id = get_ecdsa_key_id(is_production);
    
    // Request public key from IC's threshold ECDSA
    let args = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path,
        key_id: key_id.clone(),
    };
    
    let (response,) = ecdsa_public_key(args)
        .await
        .map_err(|(code, msg)| {
            CurrencyError::InvalidKey(format!(
                "Failed to get ECDSA public key: {:?} - {}",
                code, msg
            ))
        })?;
    
    let public_key = response.public_key;
    
    // Convert public key to Tron address
    let tron_address = public_key_to_tron_address(&public_key)?;
    
    Ok((tron_address, public_key))
}

/// Sign a transaction hash using IC threshold ECDSA
///
/// This is used to sign withdrawal transactions without exposing private keys.
///
/// # Parameters
/// * `user_principal` - The user's IC Principal (for derivation path)
/// * `message_hash` - The 32-byte hash to sign (usually transaction hash)
/// * `is_production` - Whether to use production or test ECDSA key
///
/// # Returns
/// * Signature bytes (64 bytes: r + s)
pub async fn sign_with_threshold_ecdsa(
    user_principal: Principal,
    message_hash: &[u8],
    is_production: bool,
) -> Result<Vec<u8>, CurrencyError> {
    if message_hash.len() != 32 {
        return Err(CurrencyError::InvalidKey(
            "Message hash must be 32 bytes".to_string(),
        ));
    }
    
    let derivation_path = vec![user_principal.as_slice().to_vec()];
    let key_id = get_ecdsa_key_id(is_production);
    
    let args = SignWithEcdsaArgument {
        message_hash: message_hash.to_vec(),
        derivation_path,
        key_id,
    };
    
    let (response,) = sign_with_ecdsa(args)
        .await
        .map_err(|(code, msg)| {
            CurrencyError::InvalidKey(format!(
                "Failed to sign with ECDSA: {:?} - {}",
                code, msg
            ))
        })?;
    
    Ok(response.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_id_selection() {
        let test_key = get_ecdsa_key_id(false);
        assert_eq!(test_key.name, "dfx_test_key");
        assert_eq!(test_key.curve, EcdsaCurve::Secp256k1);
        
        let prod_key = get_ecdsa_key_id(true);
        assert_eq!(prod_key.name, "key_1");
        assert_eq!(prod_key.curve, EcdsaCurve::Secp256k1);
    }
}

