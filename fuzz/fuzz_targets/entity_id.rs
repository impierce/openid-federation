//! Entity Identifiers and endpoint URLs: any string that `url` parses goes through
//! `UrlValidator::validate_entity_id` and `validate_endpoint_url` without panicking, and a URL that
//! prints and re-parses is the same URL.
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
    let _ = UrlValidator::validate_entity_id(&url);
    let _ = UrlValidator::validate_endpoint_url(&url);
    let again = Url::parse(url.as_str()).expect("a printed URL parses");
    assert_eq!(again, url);
});
