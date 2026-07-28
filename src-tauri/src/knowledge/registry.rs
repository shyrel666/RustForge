use super::model::{
    KnowledgeCard, KnowledgeEntry, KnowledgePack, StandardReference, FRAMEWORK_ASVS, FRAMEWORK_CWE,
    FRAMEWORK_OWASP_API_TOP10, FRAMEWORK_OWASP_TOP10, FRAMEWORK_WSTG, KNOWLEDGE_SCHEMA_VERSION,
    SUPPORTED_FRAMEWORKS,
};
use serde::{Deserialize, Serialize};
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
    #[error("安全标准引用 `{0}` 编号合法，但当前内置精选知识包未收录该条目")]
    UnlistedReference(String),
    #[error("安全标准引用列表损坏: {0}")]
    InvalidReferences(String),
}

/// 一条引用在 `packs` 里的位置。只存下标，避免每个条目各留一份整包副本
/// （那会让内存随条目数近似二次方增长）。
#[derive(Debug, Clone, Copy)]
struct EntryIndex {
    pack: usize,
    entry: usize,
}

#[derive(Debug, Clone)]
pub struct KnowledgeRegistry {
    packs: Vec<KnowledgePack>,
    entries: HashMap<StandardReference, EntryIndex>,
}

/// 引用相对于当前内置精选知识包的状态。
///
/// `NotInPack` 与 `Invalid` 必须区分：前者是"编号本身合法、只是这套精选包没
/// 收录"，后者是"编号根本不成立"。无论哪种都不会退回到任何已知条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceState {
    Known,
    NotInPack,
    Invalid,
}

impl ReferenceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::NotInPack => "not_in_pack",
            Self::Invalid => "invalid",
        }
    }
}

/// 无法解析成知识卡的引用。保留规范化后的引用与展示键，让 UI 能原样标注，
/// 而不是拿一个近似条目顶替。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnresolvedReference {
    pub reference: StandardReference,
    pub key: String,
    pub framework_label: String,
    /// `not_in_pack` 或 `invalid`
    pub state: String,
    pub reason: String,
}

/// 宽松解析结果：能查到的给卡片，查不到的逐条说明原因。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct KnowledgeLookup {
    pub cards: Vec<KnowledgeCard>,
    pub unresolved: Vec<UnresolvedReference>,
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
            packs.push(pack);
        }

        let mut entries: HashMap<StandardReference, EntryIndex> = HashMap::new();
        for (pack_index, pack) in packs.iter().enumerate() {
            for (entry_index, entry) in pack.entries.iter().enumerate() {
                let reference = pack.entry_reference(entry);
                let position = EntryIndex {
                    pack: pack_index,
                    entry: entry_index,
                };
                if entries.insert(reference.clone(), position).is_some() {
                    return Err(KnowledgeError::InvalidPack {
                        pack: documents[pack_index].0.to_string(),
                        reason: format!("全局引用 `{}` 重复", reference.identity()),
                    });
                }
            }
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

    fn entry_at(&self, index: EntryIndex) -> (&KnowledgePack, &KnowledgeEntry) {
        let pack = &self.packs[index.pack];
        (pack, &pack.entries[index.entry])
    }

    fn has_pack(&self, framework: &str, version: &str) -> bool {
        self.packs
            .iter()
            .any(|pack| pack.framework == framework && pack.version == version)
    }

    /// 判断一条引用相对当前精选包的状态，并给出可直接展示的原因。
    /// 这里永远不会返回"最接近的已知条目"。
    pub fn classify(&self, reference: &StandardReference) -> (ReferenceState, String) {
        let reference = reference.clone().normalized();
        if let Err(reason) = validate_reference_shape(&reference) {
            return (ReferenceState::Invalid, reason);
        }
        if let Err(reason) = validate_entry_id(&reference.framework, &reference.id) {
            return (ReferenceState::Invalid, reason);
        }
        if self.entries.contains_key(&reference) {
            return (ReferenceState::Known, String::new());
        }
        let reason = if self.has_pack(&reference.framework, &reference.version) {
            format!(
                "`{}` 未收录在 {} {} 精选知识包中",
                reference.id,
                framework_label(&reference.framework),
                reference.version
            )
        } else {
            format!(
                "未内置 {} 版本 `{}` 的知识包",
                framework_label(&reference.framework),
                reference.version
            )
        };
        (ReferenceState::NotInPack, reason)
    }

    pub fn validate_references(
        &self,
        references: &[StandardReference],
    ) -> Result<Vec<StandardReference>, KnowledgeError> {
        let mut canonical = Vec::with_capacity(references.len());
        let mut seen = HashSet::new();
        for raw in references {
            let reference = raw.clone().normalized();
            match self.classify(&reference) {
                (ReferenceState::Known, _) => {}
                // 两种失败都拒绝写入，只是原因不同：一种是编号不成立，
                // 另一种是编号成立但没有可派生标题/修复建议的条目。
                (ReferenceState::NotInPack, _) => {
                    return Err(KnowledgeError::UnlistedReference(reference.identity()))
                }
                (ReferenceState::Invalid, reason) => {
                    return Err(KnowledgeError::InvalidReferences(reason))
                }
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
                let index = *self
                    .entries
                    .get(&reference)
                    .ok_or_else(|| KnowledgeError::UnknownReference(reference.identity()))?;
                Ok(self.card_at(reference, index))
            })
            .collect()
    }

    /// 宽松解析：能查到的返回卡片，查不到的逐条给出 `not_in_pack` / `invalid`
    /// 状态。给 UI 用，让"未收录"不再表现为整块红色报错。
    pub fn resolve(&self, references: &[StandardReference]) -> KnowledgeLookup {
        let mut lookup = KnowledgeLookup::default();
        let mut seen = HashSet::new();
        for raw in references {
            let reference = raw.clone().normalized();
            if !seen.insert(reference.clone()) {
                continue;
            }
            match self.classify(&reference) {
                (ReferenceState::Known, _) => {
                    let index = self.entries[&reference];
                    lookup.cards.push(self.card_at(reference, index));
                }
                (state, reason) => lookup.unresolved.push(UnresolvedReference {
                    key: reference.display_key(),
                    framework_label: framework_label(&reference.framework).to_string(),
                    reference,
                    state: state.as_str().to_string(),
                    reason,
                }),
            }
        }
        lookup
    }

    fn card_at(&self, reference: StandardReference, index: EntryIndex) -> KnowledgeCard {
        let (pack, entry) = self.entry_at(index);
        KnowledgeCard {
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
        }
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

/// 只有内置注册表本身损坏才会失败；单条引用未收录不算错误。
pub fn resolve(references: &[StandardReference]) -> Result<KnowledgeLookup, String> {
    Ok(builtin_registry()
        .map_err(|e| e.to_string())?
        .resolve(references))
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
        assert!(error.contains("owasp-top10@2024/A03"), "{error}");
        assert!(!error.contains("2021/"), "{error}");

        let error = lookup(&[reference(FRAMEWORK_CWE, "4.20", "CWE-9999")]).unwrap_err();
        assert!(error.contains("CWE-9999"), "{error}");

        // 未收录不等于可以退回近似条目：解析结果里既没有卡片，也没有别的编号
        let unresolved = resolve(&[reference(FRAMEWORK_OWASP_TOP10, "2024", "A03")]).unwrap();
        assert!(unresolved.cards.is_empty());
        assert_eq!(unresolved.unresolved[0].reference.id, "A03");
        assert_eq!(unresolved.unresolved[0].reference.version, "2024");
    }

    #[test]
    fn unlisted_but_well_formed_ids_are_separated_from_malformed_ones() {
        let registry = builtin_registry().unwrap();

        // 编号成立、只是精选包没收录
        for candidate in [
            reference(FRAMEWORK_CWE, "4.20", "CWE-9999"),
            reference(FRAMEWORK_OWASP_TOP10, "2024", "A03"),
            reference(FRAMEWORK_ASVS, "5.0.0", "99.99.99"),
        ] {
            let (state, reason) = registry.classify(&candidate);
            assert_eq!(state, ReferenceState::NotInPack, "{}", candidate.identity());
            assert!(!reason.is_empty());
            assert!(matches!(
                registry.validate_references(&[candidate]),
                Err(KnowledgeError::UnlistedReference(_))
            ));
        }

        // 编号根本不成立
        for candidate in [
            reference(FRAMEWORK_CWE, "4.20", "CWE-ABC"),
            reference(FRAMEWORK_OWASP_TOP10, "2021", "B03"),
            reference("made-up", "1", "X1"),
        ] {
            let (state, _) = registry.classify(&candidate);
            assert_eq!(state, ReferenceState::Invalid, "{}", candidate.identity());
            assert!(matches!(
                registry.validate_references(&[candidate]),
                Err(KnowledgeError::InvalidReferences(_))
            ));
        }
    }

    #[test]
    fn resolve_reports_each_reference_state_without_failing_the_batch() {
        let lookup = resolve(&[
            reference(FRAMEWORK_OWASP_TOP10, "2021", "A03"),
            reference(FRAMEWORK_CWE, "4.20", "CWE-9999"),
            reference(FRAMEWORK_CWE, "4.20", "CWE-ABC"),
            reference(FRAMEWORK_OWASP_TOP10, "2021", "A03"),
        ])
        .unwrap();

        assert_eq!(lookup.cards.len(), 1, "重复引用应被折叠");
        assert_eq!(lookup.cards[0].key, "A03:2021");
        let states: Vec<&str> = lookup
            .unresolved
            .iter()
            .map(|item| item.state.as_str())
            .collect();
        assert_eq!(states, ["not_in_pack", "invalid"]);
        assert_eq!(lookup.unresolved[0].key, "CWE-9999 (v4.20)");
        assert!(!lookup.unresolved[0].reason.is_empty());
    }

    #[test]
    fn entry_serialization_keeps_a_fixed_field_order_for_the_content_hash() {
        // content_sha256 依赖 serde 的字段顺序编码；任何无序容器进入 entries
        // 都会让同一份数据算出不同哈希，这里把顺序钉死。
        let entry = &builtin_registry().unwrap().packs()[0].entries[0];
        let encoded = serde_json::to_string(entry).unwrap();
        let mut cursor = 0;
        for key in [
            "\"id\":",
            "\"title\":",
            "\"principle\":",
            "\"impact\":",
            "\"cause\":",
            "\"remediation\":",
            "\"related_references\":",
        ] {
            let offset = encoded[cursor..]
                .find(key)
                .unwrap_or_else(|| panic!("字段 {key} 不在预期顺序上: {encoded}"));
            cursor += offset + key.len();
        }
        assert_eq!(
            serde_json::to_string(entry).unwrap(),
            encoded,
            "同一条目重复序列化必须完全一致"
        );
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
