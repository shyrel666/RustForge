use serde::Serialize;
use sha2::{Digest, Sha256};

pub const TEMPLATE_REGISTRY_VERSION: &str = "2026.08.2";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SafeTemplate {
    pub id: &'static str,
    pub version: &'static str,
    pub verifier_id: &'static str,
    pub verifier_version: &'static str,
    pub allowed_identity_modes: &'static [&'static str],
    pub requires_parameter: bool,
    pub request_cost: u8,
    pub can_auto_confirm: bool,
}

pub const SAFE_TEMPLATES: &[SafeTemplate] = &[
    SafeTemplate {
        id: "security_headers_cookie",
        version: "1.0.0",
        verifier_id: "security_headers_cookie",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: false,
        request_cost: 0,
        can_auto_confirm: true,
    },
    SafeTemplate {
        id: "credentialed_cors",
        version: "1.1.0",
        verifier_id: "credentialed_cors",
        verifier_version: "1.1.0",
        allowed_identity_modes: &["a", "b"],
        requires_parameter: false,
        request_cost: 2,
        can_auto_confirm: true,
    },
    SafeTemplate {
        id: "jwt_integrity",
        version: "1.0.0",
        verifier_id: "jwt_integrity",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["a", "b"],
        requires_parameter: false,
        request_cost: 4,
        can_auto_confirm: true,
    },
    SafeTemplate {
        id: "open_redirect",
        version: "1.0.0",
        verifier_id: "open_redirect",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        request_cost: 1,
        can_auto_confirm: true,
    },
    SafeTemplate {
        id: "lazy_reflection",
        version: "1.0.0",
        verifier_id: "lazy_reflection",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["anonymous", "a", "b"],
        requires_parameter: true,
        request_cost: 1,
        can_auto_confirm: false,
    },
    SafeTemplate {
        id: "readonly_idor",
        version: "1.0.0",
        verifier_id: "readonly_idor",
        verifier_version: "1.0.0",
        allowed_identity_modes: &["a_vs_b"],
        requires_parameter: false,
        request_cost: 2,
        can_auto_confirm: true,
    },
];

pub fn template(id: &str) -> Option<&'static SafeTemplate> {
    SAFE_TEMPLATES.iter().find(|template| template.id == id)
}

pub fn registry_hash() -> String {
    let canonical = serde_json::to_vec(&(TEMPLATE_REGISTRY_VERSION, SAFE_TEMPLATES))
        .expect("static template registry serializes");
    let digest = Sha256::digest(canonical);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_unique_versioned_and_bounded() {
        let mut ids = std::collections::HashSet::new();
        for template in SAFE_TEMPLATES {
            assert!(ids.insert(template.id));
            assert!(template.request_cost <= 4);
            assert!(!template.allowed_identity_modes.is_empty());
        }
        assert_eq!(registry_hash().len(), 64);
    }
}
