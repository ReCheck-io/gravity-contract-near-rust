use near_sdk::{near_bindgen, BorshStorageKey, require, Timestamp, CryptoHash, bs58};
use near_sdk::env::{block_timestamp, keccak256_array};
use near_sdk::collections::{UnorderedMap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use ed25519_dalek::{PublicKey, Signature, Verifier};
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

    fn verify_message_signature(pub_key_string: String,
                                signature_string: String,
                                message_string: String) {
        let signature_bytes: [u8; 64] = <[u8; 64]>::from_hex(signature_string)
            .expect("Decoding signature bytes failed.");

        let signature: Signature = Signature::try_from(signature_bytes.as_ref())
            .expect("Ed25519 signature format error.");

        let pub_key_bytes: Vec<u8> = TermsOfService::get_pub_key_bytes_from_string(pub_key_string);

        let public_key: PublicKey = PublicKey::from_bytes(&pub_key_bytes)
            .expect("Ed25519 public key format error.");

        require!(public_key.verify(message_string.as_bytes(), &signature).is_ok(), "Invalid message signature.");
    }

    fn get_account_id_string_from_pub_key_string(pub_key_string: String) -> String {
        let pub_key_bytes: Vec<u8> = TermsOfService::get_pub_key_bytes_from_string(pub_key_string);

        let account_id_string: String = encode(pub_key_bytes);

        return account_id_string;
    }

    fn get_pub_key_bytes_from_string(pub_key_string: String) -> Vec<u8> {
        let pub_key_bytes: Vec<u8> = bs58::decode(pub_key_string).into_vec()
            .expect("Decoding public key bytes failed");

        return pub_key_bytes;
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
        let string: String = encode(hex_bytes);
        return string;
    }

    fn signature_string_to_hex_bytes(signature_string: String) -> [u8; 64] {
        let signature_hex_bytes: [u8; 64] = <[u8; 64]>::from_hex(signature_string)
            .expect("Invalid signature hex.");
        return signature_hex_bytes;
    }

    fn signature_hex_bytes_to_string(signature_hex_bytes: [u8; 64]) -> String {
        let signature_string: String = encode(signature_hex_bytes);
        return signature_string;
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

//Write functions
#[near_bindgen]
#[allow(non_snake_case)]
impl TermsOfService {
    #[private]
    #[allow(non_snake_case)]
    pub fn signTerms(&mut self,
                     signer_key_string: String,
                     signer_signature_string: String,
                     terms_hash_string: String) {
        let signee_terms_keccak256_hash_bytes: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        TermsOfService::only_once(self, signee_terms_keccak256_hash_bytes.clone());

        TermsOfService::verify_message_signature(signer_key_string.clone(),
                                                 signer_signature_string.clone(),
                                                 terms_hash_string.clone(),
        );

        let account_id_string: String = TermsOfService::get_account_id_string_from_pub_key_string(signer_key_string);

        let signature = TermsSignature {
            signee: TermsOfService::string_to_hex_bytes(account_id_string),
            signeeSignature: TermsOfService::signature_string_to_hex_bytes(signer_signature_string),
            termsHash: TermsOfService::string_to_hex_bytes(terms_hash_string),
            timestamp: block_timestamp(),
        };

        self.signatures.insert(&signee_terms_keccak256_hash_bytes, &signature);
    }
}

//Read-only functions
#[near_bindgen]
#[allow(non_snake_case)]
impl TermsOfService {
    #[allow(non_snake_case)]
    pub fn validateSignature(self,
                             signer_key_string: String,
                             terms_hash_string: String) -> (String,
                                                            String,
                                                            String,
                                                            Timestamp) {
        let signee_terms_keccak256_hash_bytes: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        if self.signatures.get(&signee_terms_keccak256_hash_bytes).is_none() {
            return TermsOfService::null_record();
        }

        let term_signature: TermsSignature = self.signatures.get(&signee_terms_keccak256_hash_bytes)
            .expect("No existing signature for those terms.");

        let account_id_string: String = TermsOfService::get_account_id_string_from_pub_key_string(signer_key_string.clone());

        if TermsOfService::hex_bytes_to_string(term_signature.signee) == account_id_string {
            return (
                signer_key_string,
                TermsOfService::signature_hex_bytes_to_string(term_signature.signeeSignature),
                TermsOfService::hex_bytes_to_string(term_signature.termsHash),
                term_signature.timestamp,
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
    use near_sdk::{AccountId, log, testing_env};
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use hex::ToHex;

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

    fn create_random_sign_terms_input() -> (String,
                                            String,
                                            String) {
        use rand_v7::rngs::OsRng;
        use ed25519_dalek::{Keypair, Signer};

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let public_key_string: String = bs58::encode(&keypair.public).into_string();

        let terms_hash_string: String = create_random_hash_string();

        let signature_string: String = keypair.sign(terms_hash_string.as_bytes()).encode_hex();

        return (public_key_string,
                signature_string,
                terms_hash_string
        );
    }

    #[test]
    fn sign_terms_and_validate_terms_signature() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let mut contract = TermsOfService::default();
        testing_env!(context.is_view(false).build());

        let (signer_key_string,
            signer_signature_string,
            terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        log!("signer_key_string{:?}",signer_key_string.clone());
        log!("signer_signature_string{:?}",signer_signature_string.clone());
        log!("terms_hash_string{:?}",terms_hash_string.clone());

        contract.signTerms(signer_key_string.clone(),
                           signer_signature_string.clone(),
                           terms_hash_string.clone());

        let result: (String, String, String, Timestamp) = contract.validateSignature(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        log!("result{:?}",result);

        let expected: (String, String, String, Timestamp) = (
            signer_key_string,
            signer_signature_string,
            terms_hash_string,
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

        let (signer_key_string,
            signer_signature_string,
            terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        log!("signer_key_string{:?}",signer_key_string.clone());
        log!("signer_signature_string{:?}",signer_signature_string.clone());
        log!("terms_hash_string{:?}",terms_hash_string.clone());

        contract.signTerms(signer_key_string.clone(),
                           signer_signature_string.clone(),
                           terms_hash_string.clone());

        contract.signTerms(signer_key_string.clone(),
                           signer_signature_string.clone(),
                           terms_hash_string.clone());
    }

    #[test]
    fn validate_non_existing_terms_signature() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let contract = TermsOfService::default();
        testing_env!(context.is_view(true).build());

        let (signer_key_string,
            _signer_signature_string,
            terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        log!("signer_key_string{:?}",signer_key_string.clone());
        log!("terms_hash_string{:?}",terms_hash_string.clone());

        let result: (String, String, String, Timestamp) = contract.validateSignature(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        log!("result{:?}",result);

        let expected: (String, String, String, Timestamp) = TermsOfService::null_record();

        assert_eq!(result, expected);
    }

    #[test]
    #[should_panic(expected = "Invalid message signature.")]
    fn do_not_validate_wrong_pub_key() {
        let (_signer_key_string,
            signer_signature_string,
            terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        let (wrong_signer_key_string,
            _signer_signature_string,
            _terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        log!("wrong_signer_key_string{:?}",wrong_signer_key_string.clone());
        log!("signer_signature_string{:?}",signer_signature_string.clone());
        log!("terms_hash_string{:?}",terms_hash_string.clone());

        TermsOfService::verify_message_signature(wrong_signer_key_string.clone(),
                                                 signer_signature_string.clone(),
                                                 terms_hash_string.clone());
    }

    #[test]
    #[should_panic(expected = "Invalid message signature.")]
    fn do_not_validate_wrong_signature() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let mut contract = TermsOfService::default();
        testing_env!(context.is_view(false).build());

        let (signer_key_string,
            _signer_signature_string,
            terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        let (_signer_key_string,
            wrong_signer_signature_string,
            _terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        log!("signer_key_string{:?}",signer_key_string.clone());
        log!("wrong_signer_signature_string{:?}",wrong_signer_signature_string.clone());
        log!("terms_hash_string{:?}",terms_hash_string.clone());

        contract.signTerms(signer_key_string.clone(),
                           wrong_signer_signature_string.clone(),
                           terms_hash_string.clone());
    }

    #[test]
    #[should_panic(expected = "Invalid message signature.")]
    fn do_not_validate_wrong_terms() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let mut contract = TermsOfService::default();
        testing_env!(context.is_view(false).build());

        let (signer_key_string,
            signer_signature_string,
            _terms_hash_string): (String, String, String) = create_random_sign_terms_input();

        let wrong_terms_hash_string: String = create_random_hash_string();

        log!("signer_key_string{:?}",signer_key_string.clone());
        log!("signer_signature_string{:?}",signer_signature_string.clone());
        log!("wrong_terms_hash_string{:?}",wrong_terms_hash_string.clone());

        contract.signTerms(signer_key_string.clone(),
                           signer_signature_string.clone(),
                           wrong_terms_hash_string.clone());
    }

    #[test]
    fn get_correct_tos_keccak216_hash_bytes() {
        let signer_key_string: String = "9K2ktz4U2tGWtw1sad3dMqLQJEM2egi7CbWdRuDi3KNH".to_string();
        let terms_hash_string: String = "d0ac5893c435ce0506ba227018f5d0b61e371bdffdb91030b8b502db632ee020".to_string();

        let result: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        log!("result{:?}",result);

        let expected: CryptoHash = [168, 131, 185, 82, 111, 53, 17, 206, 175, 210, 109, 54, 6, 192, 209, 133, 145, 68, 134, 89, 36, 89, 147, 184, 129, 168, 19, 203, 35, 33, 172, 170];

        assert_eq!(result, expected);
    }

    #[test]
    fn get_wrong_tos_keccak216_hash_bytes() {
        let signer_key_string: String = "9K2ktz4U2tGWtw1sad3dMqLQJEM2egi7CbWdRuDi3KNH".to_string();
        let terms_hash_string: String = "a0ac5893c435ce0506ba227018f5d0b61e371bdffdb91030b8b502db632ee020".to_string();

        let result: CryptoHash = TermsOfService::get_tos_keccak216_hash_bytes(
            signer_key_string.clone(),
            terms_hash_string.clone(),
        );

        log!("result{:?}",result);

        let expected: CryptoHash = [168, 131, 185, 82, 111, 53, 17, 206, 175, 210, 109, 54, 6, 192, 209, 133, 145, 68, 134, 89, 36, 89, 147, 184, 129, 168, 19, 203, 35, 33, 172, 170];

        assert_ne!(result, expected);
    }

    #[test]
    fn check_string_to_hex_to_string_conversion() {
        let hex_string_input: String = "a0ac5893c435ce0506ba227018f5d0b61e371bdffdb91030b8b502db632ee020".to_string();

        let result_hex_bytes: CryptoHash = TermsOfService::string_to_hex_bytes(hex_string_input.clone());

        log!("result bytes{:?}",result_hex_bytes);

        let expected_hex_bytes: CryptoHash = [160, 172, 88, 147, 196, 53, 206, 5, 6, 186, 34, 112, 24, 245, 208, 182, 30, 55, 27, 223, 253, 185, 16, 48, 184, 181, 2, 219, 99, 46, 224, 32];

        assert_eq!(result_hex_bytes, expected_hex_bytes);

        let hex_string_result: String = TermsOfService::hex_bytes_to_string(result_hex_bytes.clone
        ());

        log!("result string{:?}",hex_string_result);

        assert_eq!(hex_string_result, hex_string_input);
    }

    #[test]
    fn check_sign_string_to_sign_hex_to_sign_string_conversion() {
        let sign_hex_string_input: String =
            "d34f3182a22c27a06133419bf0b908a8542f74977781a4717aef5981fc58b3af3293f90de7e5dc6371f55cc357fbcbc71593d95b4806676690aae34dcc83e60f".to_string();

        let result_sign_hex_bytes: [u8; 64] = TermsOfService::signature_string_to_hex_bytes
            (sign_hex_string_input.clone());

        log!("result bytes{:?}",result_sign_hex_bytes);

        let expected_sign_hex_bytes: [u8; 64] = [211, 79, 49, 130, 162, 44, 39, 160, 97, 51, 65, 155, 240, 185, 8, 168, 84, 47, 116, 151, 119, 129, 164, 113, 122, 239, 89, 129, 252, 88, 179, 175, 50, 147, 249, 13, 231, 229, 220, 99, 113, 245, 92, 195, 87, 251, 203, 199, 21, 147, 217, 91, 72, 6, 103, 102, 144, 170, 227, 77, 204, 131, 230, 15];

        assert_eq!(result_sign_hex_bytes, expected_sign_hex_bytes);

        let sing_hex_string_result: String = TermsOfService::signature_hex_bytes_to_string(result_sign_hex_bytes.clone());

        log!("result string{:?}",sing_hex_string_result);

        assert_eq!(sing_hex_string_result, sign_hex_string_input);
    }
}
