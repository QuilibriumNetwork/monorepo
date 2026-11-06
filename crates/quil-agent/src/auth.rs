//! API-key check. A missing or wrong key is the same answer, and the
//! comparison does not stop at the first differing byte.
//!
//! A match is reported by the key's name so logs never include the secret.

use crate::config::{ApiKey, KeyAccess};

/// Whether `presented` is the configured key. An empty configured key
/// matches nothing.
pub fn keys_match(presented: &str, expected: &str) -> bool {
    let presented = presented.as_bytes();
    let expected = expected.as_bytes();
    if expected.is_empty() || presented.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in presented.iter().zip(expected.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// The bearer token in `Authorization`, when the scheme is Bearer.
pub fn bearer_token(authorization: &str) -> Option<&str> {
    let mut parts = authorization.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token)
    } else {
        None
    }
}

/// Which key a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// The operator key: reads, quotes, and submits.
    Full,
    /// Reads only (`node_info`, `token_query`).
    ReadOnly,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::ReadOnly => "read-only",
        }
    }
}

impl From<KeyAccess> for Access {
    fn from(access: KeyAccess) -> Self {
        match access {
            KeyAccess::Full => Self::Full,
            KeyAccess::ReadOnly => Self::ReadOnly,
        }
    }
}

/// The named key a request matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub access: Access,
}

/// The first configured key the headers match, otherwise no access.
///
/// Every key is checked. When both headers are present they must name the
/// same key. An empty configured secret matches nothing.
pub fn request_access(
    authorization: Option<&str>,
    api_key: Option<&str>,
    keys: &[ApiKey],
) -> Option<Principal> {
    let mut matched = None;
    for key in keys {
        if request_authorized(authorization, api_key, &key.secret) && matched.is_none() {
            matched = Some(Principal {
                name: key.name.clone(),
                access: key.access.into(),
            });
        }
    }
    matched
}

/// Both headers are optional. When both are present, each must be the key.
/// An empty configured key rejects every request.
pub fn request_authorized(
    authorization: Option<&str>,
    api_key: Option<&str>,
    expected: &str,
) -> bool {
    if expected.is_empty() {
        return false;
    }
    let header_key = api_key.map(str::trim).filter(|value| !value.is_empty());
    match (authorization, header_key) {
        (None, None) => false,
        (Some(authorization), None) => {
            bearer_token(authorization).is_some_and(|token| keys_match(token, expected))
        }
        (None, Some(key)) => keys_match(key, expected),
        (Some(authorization), Some(key)) => {
            bearer_token(authorization).is_some_and(|token| keys_match(token, expected))
                && keys_match(key, expected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, KeyAccess};

    #[test]
    fn only_the_configured_key_is_accepted() {
        assert!(keys_match("abc", "abc"));
        assert!(!keys_match("abd", "abc"));
        assert!(!keys_match("ab", "abc"));
        assert!(!keys_match("abcd", "abc"));
        assert!(!keys_match("", ""));
        assert!(!keys_match("abc", ""));
    }

    #[test]
    fn bearer_and_api_key_headers_both_authorize() {
        assert!(request_authorized(Some("Bearer secret"), None, "secret"));
        assert!(request_authorized(Some("bearer secret"), None, "secret"));
        assert!(request_authorized(None, Some("secret"), "secret"));
        assert!(!request_authorized(Some("Basic secret"), None, "secret"));
        assert!(!request_authorized(None, None, "secret"));
        assert!(!request_authorized(Some("Bearer other"), None, "secret"));
        assert!(!request_authorized(
            Some("Bearer secret"),
            Some("other"),
            "secret"
        ));
        assert!(request_authorized(
            Some("Bearer secret"),
            Some("secret"),
            "secret"
        ));
        assert!(!request_authorized(Some("Bearer secret"), None, ""));
    }

    #[test]
    fn the_matching_key_is_reported_by_name() {
        let keys = vec![
            ApiKey::new("operator", "full", KeyAccess::Full),
            ApiKey::new("dashboard", "read", KeyAccess::ReadOnly),
            ApiKey::new("laptop", "other", KeyAccess::Full),
        ];
        assert_eq!(
            request_access(Some("Bearer other"), None, &keys),
            Some(Principal {
                name: "laptop".into(),
                access: Access::Full,
            })
        );
        assert_eq!(
            request_access(None, Some("read"), &keys),
            Some(Principal {
                name: "dashboard".into(),
                access: Access::ReadOnly,
            })
        );
        assert_eq!(request_access(Some("Bearer nope"), None, &keys), None);
        let empty = vec![ApiKey::new("blank", "", KeyAccess::ReadOnly)];
        assert_eq!(request_access(None, Some("read"), &empty), None);
    }
}
