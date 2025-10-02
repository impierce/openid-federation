//! # OpenID Federation
//!
//! A Rust implementation of the OpenID Federation 1.0 standard.
//!
//! This library provides support for OpenID Federation, which allows
//! for the creation of trust relationships between OpenID Connect providers
//! and relying parties through a federation of trust anchors.

#![warn(missing_docs)]
#![warn(clippy::all)]

/// OpenID Federation library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}