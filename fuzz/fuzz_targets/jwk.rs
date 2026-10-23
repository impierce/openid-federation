//! JWKs and JWK Sets (RFC 7517): arbitrary JSON deserializes without panicking, every key converts
//! to a `jsonwebtoken` decoding and encoding key or fails cleanly, `kid` lookup and signature-key
//! selection never panic, and whatever parses survives a round trip through JSON.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openid_federation::{Jwk, JwkSet};

fn roundtrip<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("a parsed value serializes");
    let again: T = serde_json::from_str(&json).expect("a serialized value parses");
    assert_eq!(&again, value);
}

fn exercise(jwk: &Jwk) {
    let _ = jwk.to_decoding_key();
    let _ = jwk.to_encoding_key();
}

fuzz_target!(|data: &[u8]| {
    if let Ok(jwk) = serde_json::from_slice::<Jwk>(data) {
        exercise(&jwk);
        roundtrip(&jwk);
    }
    if let Ok(set) = serde_json::from_slice::<JwkSet>(data) {
        for jwk in &set.keys {
            exercise(jwk);
            if let Some(kid) = &jwk.kid {
                let _ = set.find_key(kid);
            }
        }
        let _ = set.find_key("missing");
        let _ = set.signature_keys().len();
        roundtrip(&set);
    }
});
