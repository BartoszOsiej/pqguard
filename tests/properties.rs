use pqguard::crypto::{decrypt_bytes, encrypt_bytes, generate_kem_keypair, SealedEnvelope};
use pqguard::keyfile::{decode_key, encode_key};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(25))]

    #[test]
    fn encrypt_decrypt_roundtrip(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        let (ek, dk) = generate_kem_keypair().unwrap();
        let envelope = encrypt_bytes(&ek, &data).unwrap();
        let recovered = decrypt_bytes(&dk, &envelope).unwrap();
        prop_assert_eq!(&data, &recovered);
    }

    #[test]
    fn ciphertext_is_randomized(data in prop::collection::vec(any::<u8>(), 1..4096)) {
        let (ek, dk) = generate_kem_keypair().unwrap();
        let env1 = encrypt_bytes(&ek, &data).unwrap();
        let env2 = encrypt_bytes(&ek, &data).unwrap();
        prop_assert!(env1.kem_ciphertext != env2.kem_ciphertext);
        let r1 = decrypt_bytes(&dk, &env1).unwrap();
        let r2 = decrypt_bytes(&dk, &env2).unwrap();
        prop_assert_eq!(&r1, &r2);
        prop_assert_eq!(&r1, &data);
    }

    #[test]
    fn wrong_key_fails(data in prop::collection::vec(any::<u8>(), 1..1024)) {
        let (ek1, _dk1) = generate_kem_keypair().unwrap();
        let (_ek2, dk2) = generate_kem_keypair().unwrap();
        let envelope = encrypt_bytes(&ek1, &data).unwrap();
        if let Ok(wrong_data) = decrypt_bytes(&dk2, &envelope) {
            prop_assert_ne!(&wrong_data, &data);
        }
    }

    #[test]
    fn envelope_serialize_roundtrip(data in prop::collection::vec(any::<u8>(), 1..4096)) {
        let (ek, dk) = generate_kem_keypair().unwrap();
        let envelope = encrypt_bytes(&ek, &data).unwrap();
        let bytes = envelope.to_bytes();
        let recovered_env = SealedEnvelope::from_bytes(&bytes).unwrap();
        let plaintext = decrypt_bytes(&dk, &recovered_env).unwrap();
        prop_assert_eq!(&data, &plaintext);
    }

    #[test]
    fn key_encode_decode_roundtrip(
        data in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        let encoded = encode_key(&data);
        let decoded = decode_key(&encoded).unwrap();
        prop_assert_eq!(&data, &decoded);
    }

    #[test]
    fn encoded_keys_are_valid_base64(
        data in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        let encoded = encode_key(&data);
        let result = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded.trim(),
        );
        prop_assert!(result.is_ok());
    }
}
