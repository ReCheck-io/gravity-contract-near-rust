use near_sdk::{near_bindgen, BorshStorageKey, require, Timestamp, CryptoHash, log};
use near_sdk::env::{block_timestamp, keccak256_array};
use near_sdk::collections::{UnorderedMap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use ed25519_dalek::{PublicKey, Verifier};
use hex::{FromHex, encode};

// 1. Main Struct
// Main contract structure serialized with Borsh
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
#[allow(non_snake_case)]
struct TermsOfService {
    signatures: UnorderedMap<CryptoHash, TermsSignature>,
}

// Helper structure serialized with Borsh
#[allow(non_snake_case)]
#[derive(BorshDeserialize, BorshSerialize)]
struct TermsSignature {
    signee: CryptoHash,
    signeeSignature: [u8; 64],
    termsHash: CryptoHash,
    timestamp: Timestamp,
}

// 2. Default Implementation
// Helper for default UnorderedMap and Vector
#[derive(BorshStorageKey, BorshSerialize)]
pub enum StorageKeys {
    SignaturesMap,
}

#[allow(non_snake_case)]
impl Default for TermsOfService {
    fn default() -> Self {
        Self {
            signatures: UnorderedMap::new(StorageKeys::SignaturesMap),
        }
    }
}

// 3. Core Logic
// Helper functions
impl TermsOfService {
    fn only_once(contract_self: &TermsOfService, keccak256_hash: CryptoHash) {
        require!(contract_self.signatures.get(&keccak256_hash).is_none(), "Sender already signed this ToS version.");
    }

    fn verify_message_signature(&mut self,
                                pub_key_string: String,
                                signature_string: String,
                                message_string: String) {
        let signature_bytes: [u8; 64] = <[u8; 64]>::from_hex(signature_string)
            .expect("Decoding signature bytes failed.");

        let signature = ed25519_dalek::Signature::try_from(signature_bytes.as_ref())
            .expect("Ed25519 signature format error.");

        let pub_key_bytes: CryptoHash = <CryptoHash>::from_hex(pub_key_string)
            .expect("Decoding public key bytes failed");

        let public_key: PublicKey = ed25519_dalek::PublicKey::from_bytes(&pub_key_bytes)
            .expect("Ed25519 public key format error.");

        require!(public_key.verify(message_string.as_bytes(), &signature).is_ok(), "Invalid message signature.");
    }

    fn get_tos_keccak216_hash_bytes(signer_string: String,
                                    terms_hash_string: String) -> CryptoHash {
        let concatenated_string: String = [signer_string.clone(), terms_hash_string.clone()].join("");

        let concatenated_string_bytes: &[u8] = concatenated_string.as_bytes();

        return keccak256_array(concatenated_string_bytes);
    }

    fn string_to_hex_bytes(str: String) -> CryptoHash {
        let hex_bytes: CryptoHash = <CryptoHash>::from_hex(str).expect("Invalid hex string.");
        return hex_bytes;
    }

    fn hex_bytes_to_string(hex_bytes: CryptoHash) -> String {
        return encode(hex_bytes);
    }

    fn signature_string_to_hex_bytes(signature_string: String) -> [u8; 64] {
        let signature_hex_bytes: [u8; 64] = <[u8; 64]>::from_hex(signature_string)
            .expect("Invalid signature hex.");
        return signature_hex_bytes;
    }

    fn signature_hex_bytes_to_string(signature_hex_bytes: [u8; 64]) -> String {
        return encode(signature_hex_bytes);
    }

    fn null_record() -> (String,
                         String,
                         String,
                         Timestamp) {
        return (
            String::from("0"),
            String::from("0"),
            String::from("0"),
            0
        );
    }
}

#[near_bindgen]
#[allow(non_snake_case)]
impl TermsOfService {
    pub fn signTerms(&mut self,
                     signer_string: String,
                     signer_signature_string: String,
                     terms_hash_string: String) {
        let signee_terms_keccak256_hash_bytes: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_string.clone(),
            terms_hash_string.clone(),
        );

        TermsOfService::only_once(self, signee_terms_keccak256_hash_bytes.clone());

        TermsOfService::verify_message_signature(self, signer_string.clone(),
                                                 signer_signature_string.clone(),
                                                 terms_hash_string.clone(),
        );

        let signature = TermsSignature {
            signee: TermsOfService::string_to_hex_bytes(signer_string),
            signeeSignature: TermsOfService::signature_string_to_hex_bytes(signer_signature_string),
            termsHash: TermsOfService::string_to_hex_bytes(terms_hash_string),
            timestamp: block_timestamp(),
        };

        self.signatures.insert(&signee_terms_keccak256_hash_bytes, &signature);
    }

    pub fn validateSignature(self,
                             signer_string: String,
                             terms_hash_string: String) -> (String,
                                                            String,
                                                            String,
                                                            Timestamp) {
        let signee_terms_keccak256_hash_bytes: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_string.clone(),
            terms_hash_string.clone(),
        );

        if self.signatures.get(&signee_terms_keccak256_hash_bytes).is_none() {
            return TermsOfService::null_record();
        }

        let signature: TermsSignature = self.signatures.get(&signee_terms_keccak256_hash_bytes)
            .expect("No existing signature for those terms.");

        if TermsOfService::hex_bytes_to_string(signature.signee) == signer_string {
            return (
                TermsOfService::hex_bytes_to_string(signature.signee),
                TermsOfService::signature_hex_bytes_to_string(signature.signeeSignature),
                TermsOfService::hex_bytes_to_string(signature.termsHash),
                signature.timestamp,
            );
        } else {
            return TermsOfService::null_record();
        }
    }
}

// 4. Tests
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{AccountId, log, testing_env};

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder.current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);

        return builder;
    }

    fn create_random_hash_string() -> String {
        use rand_v8::{Rng, thread_rng};

        const HEX_CHARSET: &[u8] = b"abcdef0123456789";
        const HASH_LEN: usize = 64;
        let mut rng = thread_rng();

        let random_hash: String = (0..HASH_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..HEX_CHARSET.len());
                HEX_CHARSET[idx] as char
            })
            .collect();


        return random_hash;
    }

    fn create_random_input() -> (String,
                                 String,
                                 String) {
        use rand_v7::rngs::OsRng;
        use ed25519_dalek::{Keypair, Signer};

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key: String = encode(keypair.public.to_bytes());

        let terms_hash = create_random_hash_string();

        let message = TermsOfService::get_tos_keccak216_hash_bytes(
            public_key.clone(),
            terms_hash.clone(),
        );

        let signature: String = encode(keypair.sign(&message).to_bytes());

        return (public_key,
                signature,
                terms_hash
        );
    }

    #[test]
    fn sign_terms_and_validate_signature() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let mut contract = TermsOfService::default();
        testing_env!(context.is_view(false).build());

        let signer_string = "144fec2534a2c01ae676786863ea5121978596f236fa21d4c200c710beee8f9a";
        let signer_signature_string = "635b27e997bbcbe5b93607ce14423a332dbda499ec3543c5b3a721867824e1c004f2c151a843a458c9c2957ae630d5e5a15c44448ffa4c058b1740186835de0a";
        let terms_hash_string = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"; //hash("test")

        contract.signTerms(signer_string.to_string(),
                           signer_signature_string.to_string(),
                           terms_hash_string.to_string());

        let result = contract.validateSignature(signer_string.to_string(),
                                                terms_hash_string.to_string(),
        );

        log!("result{:?}",result);

        let expected = (
            signer_string.to_string(),
            signer_signature_string.to_string(),
            terms_hash_string.to_string(),
            0
        );

        assert_eq!(result, expected);
    }

    #[test]
    #[should_panic(expected = "Sender already signed this ToS version.")]
    fn sign_already_signed_terms() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let mut contract = TermsOfService::default();
        testing_env!(context.is_view(false).build());

        let signer_string = "144fec2534a2c01ae676786863ea5121978596f236fa21d4c200c710beee8f9a";
        let signer_signature_string = "635b27e997bbcbe5b93607ce14423a332dbda499ec3543c5b3a721867824e1c004f2c151a843a458c9c2957ae630d5e5a15c44448ffa4c058b1740186835de0a";
        let terms_hash_string = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"; //hash("test")

        contract.signTerms(signer_string.to_string(),
                           signer_signature_string.to_string(),
                           terms_hash_string.to_string());

        contract.signTerms(signer_string.to_string(),
                           signer_signature_string.to_string(),
                           terms_hash_string.to_string());
    }
}
