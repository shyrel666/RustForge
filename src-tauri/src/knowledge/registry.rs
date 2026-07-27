use super::model::{
    KnowledgeCard, KnowledgeEntry, KnowledgePack, StandardReference, FRAMEWORK_ASVS, FRAMEWORK_CWE,
    FRAMEWORK_OWASP_API_TOP10, FRAMEWORK_OWASP_TOP10, FRAMEWORK_WSTG, KNOWLEDGE_SCHEMA_VERSION,
    SUPPORTED_FRAMEWORKS,
};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use thiserror::Error;

const BUILTIN_PACKS: &[(&str, &str)] = &[
    (
        "owasp-top10-2021.json",
        include_str!("packs/owasp-top10-2021.json"),
    ),
    (
        "owasp-top10-2025.json",
        include_str!("packs/owasp-top10-2025.json"),
    ),
    (
        "owasp-api-top10-2023.json",
        include_str!("packs/owasp-api-top10-2023.json"),
    ),
    ("asvs-5.0.0.json", include_str!("packs/asvs-5.0.0.json")),
    ("wstg-4.2.json", include_str!("packs/wstg-4.2.json")),
    ("cwe-4.20.json", include_str!("packs/cwe-4.20.json")),
];

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("知识包 `{pack}` 不是有效 JSON: {reason}")]
    InvalidJson { pack: String, reason: String },
    #[error("知识包 `{pack}` 校验失败: {reason}")]
    InvalidPack { pack: String, reason: String },
    #[error("未知安全标准引用 `{0}`")]
    UnknownReference(String),
    #[error("安全标准引用列表损坏: {0}")]
    InvalidReferences(String),
}

#[derive(Debug, Clone)]
struct RegisteredEntry {
    pack: KnowledgePack,
    entry: KnowledgeEntry,
}

#[derive(Debug, Clone)]
pub struct KnowledgeRegistry {
    packs: Vec<KnowledgePack>,
    entries: HashMap<StandardReference, RegisteredEntry>,
}

static BUILTIN_REGISTRY: LazyLock<Result<KnowledgeRegistry, String>> = LazyLock::new(|| {
    KnowledgeRegistry::from_json_documents(BUILTIN_PACKS).map_err(|e| e.to_string())
});

fn required(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("`{field}` 不能为空"))
    } else {
        Ok(())
    }
}

fn validate_url(value: &str, field: &str) -> Result<(), String> {
    required(value, field)?;
    let url = url::Url::parse(value).map_err(|error| format!("`{field}` URL 无效: {error}"))?;
    if url.scheme() != "https" {
        return Err(format!("`{field}` 必须使用 https"));
    }
    Ok(())
}

fn validate_reference_shape(reference: &StandardReference) -> Result<(), String> {
    required(&reference.framework, "reference.framework")?;
    required(&reference.version, "reference.version")?;
    required(&reference.id, "reference.id")?;
    if !SUPPORTED_FRAMEWORKS.contains(&reference.framework.as_str()) {
        return Err(format!("不支持的 framework `{}`", reference.framework));
    }
    if reference.framework != reference.framework.trim().to_ascii_lowercase()
        || reference.version != reference.version.trim()
        || reference.id != reference.id.trim().to_ascii_uppercase()
    {
        return Err(format!(
            "引用必须使用规范格式，实际为 `{}`",
            reference.identity()
        ));
    }
    Ok(())
}

fn validate_entry_id(framework: &str, id: &str) -> Result<(), String> {
    let valid = match framework {
        FRAMEWORK_OWASP_TOP10 => {
            id.len() == 3
                && id.starts_with('A')
                && id[1..].parse::<u8>().is_ok_and(|n| (1..=10).contains(&n))
        }
        FRAMEWORK_OWASP_API_TOP10 => id
            .strip_prefix("API")
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| (1..=10).contains(&n)),
        FRAMEWORK_ASVS => {
            let parts: Vec<&str> = id.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        }
        FRAMEWORK_WSTG => {
            let parts: Vec<&str> = id.split('-').collect();
            parts.len() == 3
                && parts[0] == "WSTG"
                && parts[1].len() == 4
                && parts[1].chars().all(|c| c.is_ascii_uppercase())
                && parts[2].len() == 2
                && parts[2].chars().all(|c| c.is_ascii_digit())
        }
        FRAMEWORK_CWE => id
            .strip_prefix("CWE-")
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n > 0),
        _ => false,
    };
    valid
        .then_some(())
        .ok_or_else(|| format!("`{id}` 不是 `{framework}` 的合法条目 ID"))
}

impl KnowledgeRegistry {
    pub fn from_json_documents(documents: &[(&str, &str)]) -> Result<Self, KnowledgeError> {
        let mut packs = Vec::with_capacity(documents.len());
        let mut pack_versions = HashSet::new();
        let mut entries = HashMap::new();

        for (name, raw) in documents {
            let pack: KnowledgePack =
                serde_json::from_str(raw).map_err(|error| KnowledgeError::InvalidJson {
                    pack: (*name).to_string(),
                    reason: error.to_string(),
                })?;
            Self::validate_pack(name, &pack)?;
            let pack_key = (pack.framework.clone(), pack.version.clone());
            if !pack_versions.insert(pack_key) {
                return Err(KnowledgeError::InvalidPack {
                    pack: (*name).to_string(),
                    reason: "framework + version 重复".to_string(),
                });
            }
            for entry in &pack.entries {
                let reference = pack.entry_reference(entry);
                let registered = RegisteredEntry {
                    pack: pack.clone(),
                    entry: entry.clone(),
                };
                if entries.insert(reference.clone(), registered).is_some() {
                    return Err(KnowledgeError::InvalidPack {
                        pack: (*name).to_string(),
                        reason: format!("全局引用 `{}` 重复", reference.identity()),
                    });
                }
            }
            packs.push(pack);
        }

        for pack in &packs {
            for entry in &pack.entries {
                for related in &entry.related_references {
                    if !entries.contains_key(related) {
                        return Err(KnowledgeError::InvalidPack {
                            pack: pack.pack_id.clone(),
                            reason: format!(
                                "条目 `{}` 指向未知引用 `{}`",
                                entry.id,
                                related.identity()
                            ),
                        });
                    }
                }
            }
        }

        Ok(Self { packs, entries })
    }

    fn validate_pack(name: &str, pack: &KnowledgePack) -> Result<(), KnowledgeError> {
        let invalid = |reason: String| KnowledgeError::InvalidPack {
            pack: name.to_string(),
            reason,
        };
        if pack.schema_version != KNOWLEDGE_SCHEMA_VERSION {
            return Err(invalid(format!(
                "schema_version 应为 {KNOWLEDGE_SCHEMA_VERSION}，实际为 {}",
                pack.schema_version
            )));
        }
        for (value, field) in [
            (&pack.pack_id, "pack_id"),
            (&pack.framework, "framework"),
            (&pack.version, "version"),
            (&pack.title, "title"),
            (&pack.published_at, "published_at"),
            (&pack.license.name, "license.name"),
        ] {
            required(value, field).map_err(invalid)?;
        }
        if !SUPPORTED_FRAMEWORKS.contains(&pack.framework.as_str()) {
            return Err(invalid(format!("不支持的 framework `{}`", pack.framework)));
        }
        validate_url(&pack.source_url, "source_url").map_err(invalid)?;
        validate_url(&pack.license.url, "license.url").map_err(invalid)?;
        if pack.entries.is_empty() {
            return Err(invalid("entries 不能为空".to_string()));
        }
        let expected = pack
            .computed_content_sha256()
            .map_err(|e| invalid(e.to_string()))?;
        if pack.content_sha256 != expected {
            return Err(invalid(format!(
                "内容哈希不匹配：声明 {}，计算 {}",
                pack.content_sha256, expected
            )));
        }
        let mut ids = HashSet::new();
        for entry in &pack.entries {
            validate_entry_id(&pack.framework, &entry.id).map_err(&invalid)?;
            if !ids.insert(&entry.id) {
                return Err(invalid(format!("条目 ID `{}` 重复", entry.id)));
            }
            for (value, field) in [
                (&entry.title, "entry.title"),
                (&entry.principle, "entry.principle"),
                (&entry.impact, "entry.impact"),
                (&entry.cause, "entry.cause"),
                (&entry.remediation, "entry.remediation"),
            ] {
                required(value, field).map_err(&invalid)?;
            }
            for related in &entry.related_references {
                validate_reference_shape(related).map_err(&invalid)?;
            }
        }
        Ok(())
    }

    pub fn packs(&self) -> &[KnowledgePack] {
        &self.packs
    }

    pub fn validate_references(
        &self,
        references: &[StandardReference],
    ) -> Result<Vec<StandardReference>, KnowledgeError> {
        let mut canonical = Vec::with_capacity(references.len());
        let mut seen = HashSet::new();
        for raw in references {
            let reference = raw.clone().normalized();
            validate_reference_shape(&reference).map_err(KnowledgeError::InvalidReferences)?;
            if !self.entries.contains_key(&reference) {
                return Err(KnowledgeError::UnknownReference(reference.identity()));
            }
            if seen.insert(reference.clone()) {
                canonical.push(reference);
            }
        }
        Ok(canonical)
    }

    pub fn lookup(
        &self,
        references: &[StandardReference],
    ) -> Result<Vec<KnowledgeCard>, KnowledgeError> {
        self.validate_references(references)?
            .into_iter()
            .map(|reference| {
                let registered = self
                    .entries
                    .get(&reference)
                    .ok_or_else(|| KnowledgeError::UnknownReference(reference.identity()))?;
                let entry = &registered.entry;
                let pack = &registered.pack;
                Ok(KnowledgeCard {
                    key: reference.display_key(),
                    framework_label: framework_label(&reference.framework).to_string(),
                    reference,
                    pack_title: pack.title.clone(),
                    title: entry.title.clone(),
                    principle: entry.principle.clone(),
                    impact: entry.impact.clone(),
                    cause: entry.cause.clone(),
                    remediation: entry.remediation.clone(),
                    source_url: pack.source_url.clone(),
                    published_at: pack.published_at.clone(),
                    license_name: pack.license.name.clone(),
                    license_url: pack.license.url.clone(),
                })
            })
            .collect()
    }
}

pub fn framework_label(framework: &str) -> &'static str {
    match framework {
        FRAMEWORK_OWASP_TOP10 => "OWASP Top 10",
        FRAMEWORK_OWASP_API_TOP10 => "OWASP API Security Top 10",
        FRAMEWORK_ASVS => "OWASP ASVS",
        FRAMEWORK_WSTG => "OWASP WSTG",
        FRAMEWORK_CWE => "MITRE CWE",
        _ => "Unknown",
    }
}

pub fn builtin_registry() -> Result<&'static KnowledgeRegistry, KnowledgeError> {
    BUILTIN_REGISTRY
        .as_ref()
        .map_err(|error| KnowledgeError::InvalidPack {
            pack: "builtin".to_string(),
            reason: error.clone(),
        })
}

pub fn validate_builtin_registry() -> Result<(), String> {
    builtin_registry().map(|_| ()).map_err(|e| e.to_string())
}

pub fn validate_references(
    references: &[StandardReference],
) -> Result<Vec<StandardReference>, String> {
    builtin_registry()
        .map_err(|e| e.to_string())?
        .validate_references(references)
        .map_err(|e| e.to_string())
}

pub fn references_to_json(references: &[StandardReference]) -> Result<String, String> {
    let canonical = validate_references(references)?;
    serde_json::to_string(&canonical).map_err(|e| e.to_string())
}

pub fn references_from_json(raw: &str) -> Result<Vec<StandardReference>, String> {
    let references: Vec<StandardReference> = serde_json::from_str(raw)
        .map_err(|e| KnowledgeError::InvalidReferences(e.to_string()).to_string())?;
    validate_references(&references)
}

pub fn lookup(references: &[StandardReference]) -> Result<Vec<KnowledgeCard>, String> {
    builtin_registry()
        .map_err(|e| e.to_string())?
        .lookup(references)
        .map_err(|e| e.to_string())
}

pub fn remediation_for(references: &[StandardReference]) -> Result<String, String> {
    Ok(lookup(references)?
        .iter()
        .map(|card| format!("（{}）{}", card.key, card.remediation))
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(framework: &str, version: &str, id: &str) -> StandardReference {
        StandardReference::new(framework, version, id)
    }

    #[test]
    fn all_builtin_packs_pass_schema_uniqueness_references_and_hashes() {
        let registry = builtin_registry().unwrap();
        assert_eq!(registry.packs().len(), BUILTIN_PACKS.len());
        for pack in registry.packs() {
            assert_eq!(
                pack.computed_content_sha256().unwrap(),
                pack.content_sha256,
                "{}",
                pack.pack_id
            );
            assert!(!pack.source_url.is_empty());
            assert!(!pack.published_at.is_empty());
            assert!(!pack.license.name.is_empty());
        }
    }

    #[test]
    fn same_owasp_id_in_2021_and_2025_resolves_to_different_cards() {
        let cards = lookup(&[
            reference(FRAMEWORK_OWASP_TOP10, "2021", "A03"),
            reference(FRAMEWORK_OWASP_TOP10, "2025", "A03"),
        ])
        .unwrap();
        assert_eq!(cards[0].key, "A03:2021");
        assert_eq!(cards[1].key, "A03:2025");
        assert_ne!(cards[0].title, cards[1].title);
        assert!(cards[0].title.contains("注入"));
        assert!(cards[1].title.contains("供应链"));
    }

    #[test]
    fn unknown_year_or_id_is_never_mapped_to_a_default() {
        let error = lookup(&[reference(FRAMEWORK_OWASP_TOP10, "2024", "A03")]).unwrap_err();
        assert!(error.contains("未知安全标准引用"));
        assert!(!error.contains("2021/"));

        let error = lookup(&[reference(FRAMEWORK_CWE, "4.20", "CWE-9999")]).unwrap_err();
        assert!(error.contains("CWE-9999"));
    }

    #[test]
    fn tampered_content_hash_is_rejected() {
        let mut value: serde_json::Value = serde_json::from_str(BUILTIN_PACKS[0].1).unwrap();
        value["entries"][0]["title"] = serde_json::Value::String("tampered".to_string());
        let raw = value.to_string();
        let error = KnowledgeRegistry::from_json_documents(&[("tampered.json", &raw)]).unwrap_err();
        assert!(error.to_string().contains("内容哈希不匹配"));
    }

    #[test]
    fn structured_reference_json_round_trips_without_title_fields() {
        let input = vec![
            reference(FRAMEWORK_OWASP_TOP10, "2025", "A05"),
            reference(FRAMEWORK_CWE, "4.20", "CWE-89"),
        ];
        let json = references_to_json(&input).unwrap();
        assert!(!json.contains("Injection"));
        assert_eq!(references_from_json(&json).unwrap(), input);
    }
}
