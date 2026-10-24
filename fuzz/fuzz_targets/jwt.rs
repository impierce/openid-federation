//! JWTs in compact serialization: header decoding, `typ` validation, unverified claim extraction,
//! `from_verified_jwt` against a fixed entity, and `TrustChain::try_new` over the input's lines
//! never panic. Nothing here verifies, since no key is known; a result is accepted either way.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openid_federation::{
    extract_claims_unverified, EntityConfiguration, JwtArtifactType, SubordinateStatement, TrustChain, TrustMark,
};
use url::Url;

const ARTIFACT_TYPES: [JwtArtifactType; 7] = [
    JwtArtifactType::EntityStatement,
    JwtArtifactType::TrustMark,
    JwtArtifactType::ResolveResponse,
    JwtArtifactType::ExplicitRegistrationResponse,
    JwtArtifactType::SignedJwkSet,
    JwtArtifactType::TrustMarkDelegation,
    JwtArtifactType::TrustMarkStatusResponse,
];

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(header) = jsonwebtoken::decode_header(input) {
        for artifact_type in ARTIFACT_TYPES {
            let _ = artifact_type.validate_header_typ(header.typ.as_deref());
        }
    }

    let _ = extract_claims_unverified::<serde_json::Value>(input);
    let _ = extract_claims_unverified::<EntityConfiguration>(input);
    let _ = extract_claims_unverified::<SubordinateStatement>(input);
    let _ = extract_claims_unverified::<TrustMark>(input);

    let entity = Url::parse("https://entity.example").expect("a fixed URL parses");
    let _ = EntityConfiguration::from_verified_jwt(input, &entity);

    // One statement per line; a chain needs at least a leaf and an anchor.
    let chain: Vec<String> = input.lines().map(str::to_owned).collect();
    if let Ok(trust_chain) = TrustChain::try_new(chain) {
        let _ = trust_chain.expiration_timestamp();
        let _ = trust_chain.is_expired();
        let _ = trust_chain.leaf_entity_id_and_configuration();
        let _ = trust_chain.trust_anchor_entity_id_and_configuration();
    }
});
