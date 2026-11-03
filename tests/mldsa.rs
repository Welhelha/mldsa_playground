//! Tests d'intégration ML-DSA pour le fork askar ciblé.
use std::{env, fs, str::FromStr, sync::Arc, thread};

use askar_crypto::{
    alg::{AnyKey, AnyKeyCreate, KeyAlg},
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    jwk::{FromJwk, JwkParts, ToJwk},
    kdf::KeyExchange,
    repr::ToPublicBytes,
    sign::{KeySigVerify, KeySign, SignatureType},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

const SEED: [u8; 32] = [0x42; 32];
const ALGS: [KeyAlg; 3] = [KeyAlg::MlDsa44, KeyAlg::MlDsa65, KeyAlg::MlDsa87];

fn expected_sizes(alg: KeyAlg) -> (usize, usize) {
    match alg {
        KeyAlg::MlDsa44 => (1312, 2420),
        KeyAlg::MlDsa65 => (1952, 3309),
        KeyAlg::MlDsa87 => (2592, 4627),
        _ => unreachable!(),
    }
}

fn sig_type(alg: KeyAlg) -> SignatureType {
    match alg {
        KeyAlg::MlDsa44 => SignatureType::MLDSA44,
        KeyAlg::MlDsa65 => SignatureType::MLDSA65,
        KeyAlg::MlDsa87 => SignatureType::MLDSA87,
        _ => unreachable!(),
    }
}

// Retourner une valeur possédée évite de référencer le JwkParts local.
fn jwk_member(jwk: &str, name: &str) -> String {
    let parts = JwkParts::try_from_str(jwk).unwrap();
    match name {
        "kty" => parts.kty.to_string(),
        "alg" => parts.alg.as_opt_str().unwrap_or_default().to_string(),
        "pub" => parts.pub_key.as_opt_str().unwrap_or_default().to_string(),
        "priv" => parts.priv_key.as_opt_str().unwrap_or_default().to_string(),
        _ => panic!("membre JWK inconnu: {name}"),
    }
}

fn key(alg: KeyAlg) -> Box<AnyKey> {
    Box::<AnyKey>::from_secret_bytes(alg, &SEED).unwrap()
}

#[test]
fn generation_signing_and_signature_sizes_cover_all_variants() {
    for alg in ALGS {
        let (pub_len, sig_len) = expected_sizes(alg);
        let key = Box::<AnyKey>::random_det(alg, b"generation test").unwrap();
        assert_eq!(key.to_public_bytes().unwrap().len(), pub_len);
        let sig = key
            .create_signature(b"message", Some(sig_type(alg)))
            .unwrap();
        assert_eq!(sig.len(), sig_len);
        assert!(key
            .verify_signature(b"message", &sig, Some(sig_type(alg)))
            .unwrap());
    }
}

#[test]
fn seeded_key_import_and_signatures_are_deterministic() {
    for alg in ALGS {
        let a = key(alg);
        let b = Box::<AnyKey>::from_secret_bytes(alg, &SEED).unwrap();
        assert_eq!(
            a.to_public_bytes().unwrap().as_ref(),
            b.to_public_bytes().unwrap().as_ref()
        );
        assert_eq!(
            a.create_signature(b"same", None).unwrap().as_ref(),
            b.create_signature(b"same", None).unwrap().as_ref()
        );
    }
}

#[test]
fn random_key_generation_does_not_repeat_outputs() {
    for alg in ALGS {
        let a = Box::<AnyKey>::random(alg).unwrap();
        let b = Box::<AnyKey>::random(alg).unwrap();
        assert_ne!(
            a.to_public_bytes().unwrap().as_ref(),
            b.to_public_bytes().unwrap().as_ref()
        );
    }
}

#[test]
fn messages_of_boundary_sizes_sign_and_verify() {
    for alg in ALGS {
        let key = key(alg);
        for size in [0, 1, 1 << 20] {
            let msg = vec![0xa5; size];
            let sig = key.create_signature(&msg, None).unwrap();
            assert!(key.verify_signature(&msg, &sig, None).unwrap());
        }
    }
}

#[test]
fn invalid_signatures_and_other_keys_are_rejected() {
    for alg in ALGS {
        let a = key(alg);
        let b = Box::<AnyKey>::random_det(alg, b"other key").unwrap();
        let sig = a.create_signature(b"message", None).unwrap();
        assert!(!a.verify_signature(b"wrong", &sig, None).unwrap());
        assert!(!b.verify_signature(b"message", &sig, None).unwrap());
        let mut altered = sig.as_ref().to_vec();
        altered[0] ^= 1;
        assert!(!a.verify_signature(b"message", &altered, None).unwrap());
        assert!(a
            .verify_signature(b"message", &altered[..altered.len() - 1], None)
            .is_err());
    }
}

#[test]
fn signature_type_mismatch_is_rejected() {
    for alg in ALGS {
        let key = key(alg);
        let wrong = match alg {
            KeyAlg::MlDsa44 => SignatureType::MLDSA65,
            _ => SignatureType::MLDSA44,
        };
        assert!(key.create_signature(b"x", Some(wrong)).is_err());
        let sig = key.create_signature(b"x", None).unwrap();
        assert!(key.verify_signature(b"x", &sig, Some(wrong)).is_err());
    }
}

#[test]
fn jwk_exports_have_expected_rfc9964_fields_and_encodings() {
    for alg in ALGS {
        let key = key(alg);
        let pub_jwk = key.to_jwk_public(None).unwrap();
        let secret = key.to_jwk_secret(None).unwrap();
        let secret_jwk = std::str::from_utf8(&secret).unwrap();
        let (pub_len, _) = expected_sizes(alg);
        let expected_alg = format!(
            "ML-DSA-{}",
            match alg {
                KeyAlg::MlDsa44 => 44,
                KeyAlg::MlDsa65 => 65,
                KeyAlg::MlDsa87 => 87,
                _ => unreachable!(),
            }
        );
        assert_eq!(jwk_member(&pub_jwk, "kty"), "AKP");
        assert_eq!(jwk_member(&pub_jwk, "alg"), expected_alg);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(jwk_member(&pub_jwk, "pub"))
                .unwrap()
                .len(),
            pub_len
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(jwk_member(secret_jwk, "priv"))
                .unwrap()
                .len(),
            32
        );
        assert!(!jwk_member(&pub_jwk, "pub").contains('='));
    }
}

#[test]
fn public_and_secret_jwk_roundtrips_preserve_signature_and_thumbprint() {
    for alg in ALGS {
        let original = key(alg);
        let sig = original.create_signature(b"round trip", None).unwrap();
        let public = Box::<AnyKey>::from_jwk(&original.to_jwk_public(None).unwrap()).unwrap();
        let secret = original.to_jwk_secret(None).unwrap();
        let private = Box::<AnyKey>::from_jwk(std::str::from_utf8(&secret).unwrap()).unwrap();
        assert!(public.verify_signature(b"round trip", &sig, None).unwrap());
        assert_eq!(
            original.to_jwk_thumbprint(None).unwrap(),
            public.to_jwk_thumbprint(None).unwrap()
        );
        assert!(private
            .verify_signature(
                b"round trip",
                &private.create_signature(b"round trip", None).unwrap(),
                None
            )
            .unwrap());
    }
}

#[test]
fn jwk_member_order_and_noncritical_unknown_fields_do_not_change_key() {
    let original = key(KeyAlg::MlDsa44);
    let pub_jwk = original.to_jwk_public(None).unwrap();
    let p = JwkParts::try_from_str(&pub_jwk).unwrap();
    let reordered = format!(
        r#"{{"unknown":"x","pub":"{}","alg":"{}","kty":"AKP"}}"#,
        p.pub_key.as_ref(),
        p.alg.as_ref()
    );
    let imported = Box::<AnyKey>::from_jwk(&reordered).unwrap();
    assert_eq!(
        original.to_jwk_thumbprint(None).unwrap(),
        imported.to_jwk_thumbprint(None).unwrap()
    );
}

#[test]
fn malformed_jwk_fields_are_rejected_without_panicking() {
    let cases = [
        r#"{"kty":"AKP","alg":"ML-DSA-44","pub":"!"}"#,
        r#"{"kty":"AKP","alg":"ML-DSA-44","pub":"AA"}"#,
        r#"{"kty":"OKP","alg":"ML-DSA-44","pub":"AA"}"#,
        r#"{"kty":"AKP","alg":"NOPE","pub":"AA"}"#,
    ];
    for jwk in cases {
        assert!(Box::<AnyKey>::from_jwk(jwk).is_err());
    }
}

#[test]
fn jwk_private_seed_must_match_public_key_and_be_exactly_32_bytes() {
    let original = key(KeyAlg::MlDsa44);
    let pub_jwk = original.to_jwk_public(None).unwrap();
    let pub_value = jwk_member(&pub_jwk, "pub");
    let bad_seed = URL_SAFE_NO_PAD.encode([0x43; 32]);
    let mismatch =
        format!(r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{pub_value}","priv":"{bad_seed}"}}"#);
    assert!(Box::<AnyKey>::from_jwk(&mismatch).is_err());
    for len in [0, 31, 33] {
        let seed = URL_SAFE_NO_PAD.encode(vec![0x42; len]);
        let jwk =
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{pub_value}","priv":"{seed}"}}"#);
        assert!(Box::<AnyKey>::from_jwk(&jwk).is_err());
    }
}

#[test]
fn thumbprints_are_stable_and_independent_of_private_and_unknown_members() {
    let key = key(KeyAlg::MlDsa65);
    let public = key.to_jwk_public(None).unwrap();
    let p = JwkParts::try_from_str(&public).unwrap();
    let canonical = format!(
        r#"{{"alg":"{}","kty":"AKP","pub":"{}"}}"#,
        p.alg.as_ref(),
        p.pub_key.as_ref()
    );
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    assert_eq!(
        key.to_jwk_thumbprint(None).unwrap(),
        URL_SAFE_NO_PAD.encode(h.finalize())
    );
    let with_unknown = format!(
        r#"{{"x-extra":1,"kty":"AKP","alg":"{}","pub":"{}"}}"#,
        p.alg.as_ref(),
        p.pub_key.as_ref()
    );
    let imported = Box::<AnyKey>::from_jwk(&with_unknown).unwrap();
    assert_eq!(
        key.to_jwk_thumbprint(None).unwrap(),
        imported.to_jwk_thumbprint(None).unwrap()
    );
}

#[test]
fn key_algorithm_strings_roundtrip_canonically() {
    for (alg, text) in [
        (KeyAlg::MlDsa44, "mldsa44"),
        (KeyAlg::MlDsa65, "mldsa65"),
        (KeyAlg::MlDsa87, "mldsa87"),
    ] {
        assert_eq!(KeyAlg::from_str(text).unwrap(), alg);
        assert_eq!(alg.as_str(), text);
    }
}

#[test]
fn mldsa_operations_not_supported_for_exchange_or_encryption() {
    let key = key(KeyAlg::MlDsa44);
    let mut out = SecretBytes::with_capacity(1);
    assert!(key.write_key_exchange(&key, &mut out).is_err());
    let mut data = SecretBytes::from_slice(b"data");
    assert!(key.encrypt_in_place(&mut data, &[], &[]).is_err());
}

#[test]
fn public_keys_and_shared_keys_work_across_threads() {
    let key = Arc::<AnyKey>::random_det(KeyAlg::MlDsa44, b"thread key").unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let key = Arc::clone(&key);
        handles.push(thread::spawn(move || {
            let sig = key.create_signature(b"thread", None).unwrap();
            key.verify_signature(b"thread", &sig, None).unwrap()
        }));
    }
    for handle in handles {
        assert!(handle.join().unwrap());
    }
}

#[test]
fn debug_output_does_not_disclose_seed_bytes() {
    let key = key(KeyAlg::MlDsa44);
    let debug = format!("{key:?}");
    assert!(!debug.contains(&"42".repeat(32)));
    assert!(debug.contains("<secret>"));
}

#[test]
fn jwk_json_and_utf8_errors_are_returned() {
    assert!(Box::<AnyKey>::from_jwk("not json").is_err());
    assert!(Box::<AnyKey>::from_jwk_slice(&[0xff, 0xfe]).is_err());
}

#[test]
fn fixed_seed_keys_keep_their_algorithm_after_type_erasure() {
    for alg in ALGS {
        assert_eq!(key(alg).algorithm(), alg);
    }
}

#[test]
fn invalid_seed_lengths_are_rejected() {
    for alg in ALGS {
        for len in [0, 31, 33] {
            assert!(Box::<AnyKey>::from_secret_bytes(alg, &vec![0; len]).is_err());
        }
    }
}

#[test]
fn seed_bytes_are_not_disclosed_in_debug() {
    let key = key(KeyAlg::MlDsa44);
    let debug = format!("{key:?}");
    assert!(!debug.contains(&"42".repeat(32)));
    assert!(debug.contains("<secret>"));
}

#[test]
fn jwk_member_order_and_kid_do_not_change_key() {
    for alg in ALGS {
        let key = key(alg);
        let public = key.to_jwk_public(None).unwrap();
        let reordered = format!(
            r#"{{"pub":"{}","kid":"some-id","alg":"{}","kty":"AKP"}}"#,
            jwk_member(&public, "pub"),
            jwk_member(&public, "alg")
        );
        let imported = Box::<AnyKey>::from_jwk(&reordered).unwrap();
        assert_eq!(
            key.to_jwk_thumbprint(None).unwrap(),
            imported.to_jwk_thumbprint(None).unwrap()
        );
    }
}

#[test]
fn thumbprints_are_independent_of_kid_member() {
    for alg in ALGS {
        let key = key(alg);
        let thumbprint = key.to_jwk_thumbprint(None).unwrap();
        let public = key.to_jwk_public(None).unwrap();
        let with_kid = format!(
            r#"{{"kid":"another-id","pub":"{}","alg":"{}","kty":"AKP"}}"#,
            jwk_member(&public, "pub"),
            jwk_member(&public, "alg")
        );
        let imported = Box::<AnyKey>::from_jwk(&with_kid).unwrap();
        assert_eq!(thumbprint, imported.to_jwk_thumbprint(None).unwrap());
        assert_eq!(thumbprint.len(), 43);
    }
}

#[test]
fn unknown_jwk_members_current_behavior() {
    // Documente le comportement actuel : à adapter si le parseur change.
    let key = key(KeyAlg::MlDsa44);
    let public = key.to_jwk_public(None).unwrap();
    let jwk = format!(
        r#"{{"kty":"AKP","alg":"ML-DSA-44","pub":"{}","unknown":"x"}}"#,
        jwk_member(&public, "pub")
    );
    let result = Box::<AnyKey>::from_jwk(&jwk);
    println!("unknown member accepted: {}", result.is_ok());
}

fn noble_cross_check_export() {
    let mut results = Vec::new();
    for alg in ALGS {
        let key = key(alg);
        let (pub_len, sig_len) = expected_sizes(alg);
        let public_key = key.to_public_bytes().unwrap();
        let signature = key
            .create_signature(b"message", Some(sig_type(alg)))
            .unwrap();
        assert_eq!(public_key.len(), pub_len);
        assert_eq!(signature.len(), sig_len);
        results.push(format!(
            "\"{}\":{{\"publicKey\":\"{}\",\"signature\":\"{}\"}}",
            match alg {
                KeyAlg::MlDsa44 => "ML-DSA-44",
                KeyAlg::MlDsa65 => "ML-DSA-65",
                KeyAlg::MlDsa87 => "ML-DSA-87",
                _ => unreachable!(),
            },
            base64::engine::general_purpose::STANDARD.encode(public_key),
            base64::engine::general_purpose::STANDARD.encode(signature)
        ));
    }
    println!("NOBLE_CROSS_CHECK={{{}}}", results.join(","));
}

#[test]
fn noble_cross_check_exports() {
    noble_cross_check_export();
}

fn noble_cross_check_import(alg: KeyAlg) {
    let Ok(path) = env::var("NOBLE_SIGNATURE_PATH") else {
        return;
    };
    let signature = fs::read(path).unwrap();
    assert!(key(alg)
        .verify_signature(b"message", &signature, Some(sig_type(alg)))
        .unwrap());
}

#[test]
fn noble_cross_check_imports_ml_dsa_44() {
    noble_cross_check_import(KeyAlg::MlDsa44);
}

#[test]
fn noble_cross_check_imports_ml_dsa_65() {
    noble_cross_check_import(KeyAlg::MlDsa65);
}

#[test]
fn noble_cross_check_imports_ml_dsa_87() {
    noble_cross_check_import(KeyAlg::MlDsa87);
}
