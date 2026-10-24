//! Trust Marks (Trust Marks section): a `TrustMarkEntry` built from the first line as type and the
//! rest as Trust Mark JWT validates without panicking, and `TrustMark`, `TrustMarkIssuers` and
//! `TrustMarkOwners` parsed from the whole input survive a round trip through JSON.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openid_federation::{TrustMark, TrustMarkEntry, TrustMarkIssuers, TrustMarkOwners};

fn roundtrip<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("a parsed value serializes");
    let again: T = serde_json::from_str(&json).expect("a serialized value parses");
    assert_eq!(&again, value);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let (trust_mark_type, trust_mark) = input.split_once('\n').unwrap_or((input, ""));
        let entry = TrustMarkEntry {
            trust_mark_type: trust_mark_type.to_owned(),
            trust_mark: trust_mark.to_owned(),
        };
        let _ = entry.validate();
        roundtrip(&entry);
    }
    if let Ok(trust_mark) = serde_json::from_slice::<TrustMark>(data) {
        roundtrip(&trust_mark);
    }
    if let Ok(issuers) = serde_json::from_slice::<TrustMarkIssuers>(data) {
        roundtrip(&issuers);
    }
    if let Ok(owners) = serde_json::from_slice::<TrustMarkOwners>(data) {
        roundtrip(&owners);
    }
});
