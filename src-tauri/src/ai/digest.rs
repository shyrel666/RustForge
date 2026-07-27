//! 流量摘要：给 AI 规划器看的"侦察报告"。
//! 成本控制红线：只给聚合摘要，不给全量流量——端点 Top N、标签计数、
//! Finding 摘要，总长控制在 ~2K token 内。

use super::redaction::{redact_fallback_text, RedactionManifest};
use rusqlite::Connection;

/// 端点聚合行
struct EndpointRow {
    method: String,
    host: String,
    path: String,
    count: i64,
    tags: String,
}

const MAX_ENDPOINTS: usize = 30;
const MAX_PATH_LEN: usize = 60;

fn redact_path_query(path: &str, location: &str, manifest: &mut RedactionManifest) -> String {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let mut redacted = route.to_string();
    if !query.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, _) in url::form_urlencoded::parse(query.as_bytes()) {
            serializer.append_pair(&name, "[REDACTED:query_value]");
            manifest.record_redaction(&format!("{location}.query.{name}"), "query_value");
        }
        let query = serializer.finish();
        if !query.is_empty() {
            redacted.push('?');
            redacted.push_str(&query);
        }
    }
    redact_fallback_text(&redacted, location, true, manifest)
}

/// 构造项目流量摘要文本
pub fn build_digest(conn: &Connection, project_id: i64) -> Result<String, String> {
    build_redacted_digest(conn, project_id, &mut RedactionManifest::default())
}

/// 构造可发送给任务规划器的摘要。查询值和秘密格式在聚合前后均不会
/// 原样进入 prompt，所有处理都会记录到与预览一同持久化的 manifest。
pub fn build_redacted_digest(
    conn: &Connection,
    project_id: i64,
    manifest: &mut RedactionManifest,
) -> Result<String, String> {
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM traffic WHERE project_id = ?1",
            [project_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if total == 0 {
        return Err("当前项目还没有流量。先启动代理抓一段目标流量，再生成任务树。".into());
    }

    let target: String = conn
        .query_row(
            "SELECT target_host FROM projects WHERE id = ?1",
            [project_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    // 端点聚合：按 方法+host+path 分组计数，合并该端点出现过的标签
    let mut stmt = conn
        .prepare(
            "SELECT method, host, path, COUNT(*) AS cnt,
                    GROUP_CONCAT(DISTINCT rule_tags) AS tags
             FROM traffic WHERE project_id = ?1
             GROUP BY method, host, path
             ORDER BY cnt DESC LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;
    let endpoints: Vec<EndpointRow> = stmt
        .query_map(rusqlite::params![project_id, MAX_ENDPOINTS as i64], |r| {
            Ok(EndpointRow {
                method: r.get(0)?,
                host: r.get(1)?,
                path: r.get(2)?,
                count: r.get(3)?,
                tags: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;

    // 标签总计数（规则命中的整体分布）
    let tag_counts = {
        let mut counts: std::collections::HashMap<String, i64> = Default::default();
        let mut s = conn
            .prepare("SELECT rule_tags FROM traffic WHERE project_id = ?1 AND rule_tags != '[]'")
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([project_id], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            if let Ok(tags) = serde_json::from_str::<Vec<String>>(&row) {
                for t in tags {
                    *counts.entry(t).or_default() += 1;
                }
            }
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    };

    // Finding 摘要（含 id，供 AI 建立双向关联）
    let mut findings_text = String::new();
    {
        let mut s = conn
            .prepare(
                "SELECT id, title, severity, confidence, status FROM findings
                 WHERE project_id = ?1 ORDER BY id LIMIT 50",
            )
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([project_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            findings_text.push_str(&format!(
                "- [#{}] {}（{}，置信度 {}，{}）\n",
                row.0, row.1, row.2, row.3, row.4
            ));
        }
    }

    let target = redact_fallback_text(&target, "planner.target", true, manifest);
    let mut out = format!(
        "目标: {}\n已抓取流量: {} 条\n\n## 端点聚合（按频次）\n",
        if target.is_empty() {
            "（未填写）"
        } else {
            &target
        },
        total
    );
    for (index, e) in endpoints.iter().enumerate() {
        let location = format!("planner.endpoint[{index}].path");
        let path = redact_path_query(&e.path, &location, manifest);
        let path: String = path.chars().take(MAX_PATH_LEN).collect();
        let host = redact_fallback_text(
            &e.host,
            &format!("planner.endpoint[{index}].host"),
            true,
            manifest,
        );
        let tags = if e.tags.is_empty() || e.tags == "[]" {
            String::new()
        } else {
            format!(
                " 标签: {}",
                e.tags.replace("[", "").replace("]", "").replace("\"", "")
            )
        };
        out.push_str(&format!(
            "- {} {} {} ({}次){}\n",
            e.method, host, path, e.count, tags
        ));
    }
    if !tag_counts.is_empty() {
        out.push_str("\n## 被动规则命中分布\n");
        for (tag, n) in &tag_counts {
            out.push_str(&format!("- {}: {} 次\n", tag, n));
        }
    }
    if !findings_text.is_empty() {
        out.push_str("\n## 已有发现（可在任务节点用 finding_ids 关联）\n");
        out.push_str(&redact_fallback_text(
            &findings_text,
            "planner.findings",
            true,
            manifest,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::Db;

    #[test]
    fn digest_summarizes() {
        let dir = std::env::temp_dir().join(format!("rustforge-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("t.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t','t.cn','[]')",
                [],
            )
            .unwrap();
        let pid = db.conn.last_insert_rowid();
        for i in 0..3 {
            db.conn
                .execute(
                    "INSERT INTO traffic(project_id, method, host, path, url, rule_tags)
                     VALUES(?1, 'GET', 't.cn', ?2, 'https://t.cn/x', ?3)",
                    rusqlite::params![
                        pid,
                        if i == 0 {
                            "/a0?token=secret&next=%2Fhome".to_string()
                        } else {
                            format!("/a{i}")
                        },
                        if i == 0 { "[\"JWT\"]" } else { "[]" }
                    ],
                )
                .unwrap();
        }
        let text = build_digest(&db.conn, pid).unwrap();
        assert!(text.contains("已抓取流量: 3 条"));
        assert!(text.contains("GET t.cn /a0"));
        assert!(text.contains("JWT: 1 次"));
        assert!(!text.contains("secret"));
        assert!(!text.contains("%2Fhome"));
        assert!(text.contains("REDACTED"));
    }

    #[test]
    fn digest_empty_project_errors() {
        let dir =
            std::env::temp_dir().join(format!("rustforge-digest-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("t.db")).unwrap();
        db.conn
            .execute("INSERT INTO projects(name) VALUES('empty')", [])
            .unwrap();
        let pid = db.conn.last_insert_rowid();
        assert!(build_digest(&db.conn, pid).is_err());
    }
}
