//! Entity Identifiers and endpoint URLs: any string that `url` parses goes through
//! `UrlValidator::validate_entity_id` and `validate_endpoint_url` without panicking, and a URL that
//! validates as an Entity Identifier prints and re-parses to the same URL.
//!
//! The round trip is asserted for valid Entity Identifiers only: `url` does not round-trip every
//! URL it parses (a `file:` URL with tab characters parses to a different host the second time),
//! and that is a property of `url`, not of this crate.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openid_federation::UrlValidator;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(url) = Url::parse(input) else {
        return;
    };
    let _ = UrlValidator::validate_endpoint_url(&url);
    if UrlValidator::validate_entity_id(&url).is_ok() {
        let again = Url::parse(url.as_str()).expect("a printed Entity Identifier parses");
        assert_eq!(again, url);
    }
});
