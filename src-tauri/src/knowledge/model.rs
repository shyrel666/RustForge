use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KNOWLEDGE_SCHEMA_VERSION: u32 = 1;
pub const FRAMEWORK_OWASP_TOP10: &str = "owasp-top10";
pub const FRAMEWORK_OWASP_API_TOP10: &str = "owasp-api-top10";
pub const FRAMEWORK_ASVS: &str = "asvs";
pub const FRAMEWORK_WSTG: &str = "wstg";
pub const FRAMEWORK_CWE: &str = "cwe";

pub const SUPPORTED_FRAMEWORKS: &[&str] = &[
    FRAMEWORK_OWASP_TOP10,
    FRAMEWORK_OWASP_API_TOP10,
    FRAMEWORK_ASVS,
    FRAMEWORK_WSTG,
    FRAMEWORK_CWE,
];

/// Stable identity for a security-standard entry. Titles are deliberately not
/// persisted in Findings or tasks because they are derived from the pinned pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct StandardReference {
    pub framework: String,
    pub version: String,
    pub id: String,
}

impl StandardReference {
    pub fn new(framework: &str, version: &str, id: &str) -> Self {
        Self {
            framework: framework.to_string(),
            version: version.to_string(),
            id: id.to_string(),
        }
    }

    pub fn normalized(mut self) -> Self {
        self.framework = self.framework.trim().to_ascii_lowercase();
        self.version = self.version.trim().to_string();
        self.id = self.id.trim().to_ascii_uppercase();
        self
    }

    pub fn identity(&self) -> String {
        format!("{}@{}/{}", self.framework, self.version, self.id)
    }

    pub fn display_key(&self) -> String {
        match self.framework.as_str() {
            FRAMEWORK_OWASP_TOP10 | FRAMEWORK_OWASP_API_TOP10 => {
                format!("{}:{}", self.id, self.version)
            }
            FRAMEWORK_ASVS => format!("ASVS v{}-{}", self.version, self.id),
            FRAMEWORK_WSTG => {
                let compact_version = self.version.replace('.', "");
                let suffix = self.id.strip_prefix("WSTG-").unwrap_or(&self.id);
                format!("WSTG-v{compact_version}-{suffix}")
            }
            FRAMEWORK_CWE => format!("{} (v{})", self.id, self.version),
            _ => self.identity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackLicense {
    pub name: String,
    pub url: String,
}

/// A single knowledge card.
///
/// Every field must serialize in a deterministic order because
/// [`KnowledgePack::computed_content_sha256`] hashes the serde encoding of
/// `entries` directly. Only ordered types are allowed here: adding an unordered
/// container (`serde_json::Map`, `HashMap`, `HashSet`, ...) would make the
/// content hash unstable across runs and silently break pack verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEntry {
    pub id: String,
    pub title: String,
    pub principle: String,
    pub impact: String,
    pub cause: String,
    pub remediation: String,
    #[serde(default)]
    pub related_references: Vec<StandardReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgePack {
    pub schema_version: u32,
    pub pack_id: String,
    pub framework: String,
    pub version: String,
    pub title: String,
    pub source_url: String,
    pub published_at: String,
    pub license: PackLicense,
    /// SHA-256 of the canonical serde JSON encoding of `entries`.
    pub content_sha256: String,
    pub entries: Vec<KnowledgeEntry>,
}

impl KnowledgePack {
    pub fn entry_reference(&self, entry: &KnowledgeEntry) -> StandardReference {
        StandardReference::new(&self.framework, &self.version, &entry.id)
    }

    /// Content hash of `entries`.
    ///
    /// This is serde's field-ordered encoding, not RFC 8785 canonical JSON. It
    /// is stable only because every type reachable from [`KnowledgeEntry`] is a
    /// struct or a `Vec`; see the constraint documented on that type before
    /// changing the entry shape.
    pub fn computed_content_sha256(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&self.entries)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeCard {
    pub reference: StandardReference,
    pub key: String,
    pub framework_label: String,
    pub pack_title: String,
    pub title: String,
    pub principle: String,
    pub impact: String,
    pub cause: String,
    pub remediation: String,
    pub source_url: String,
    pub published_at: String,
    pub license_name: String,
    pub license_url: String,
}
