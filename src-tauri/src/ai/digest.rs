//! 流量摘要：给 AI 规划器看的"侦察报告"。
//! 成本控制红线：只给聚合摘要，不给全量流量。端点在本地按规范化 route
//! 聚合并重排，查询值永不进入聚合身份或提示词。

use super::redaction::{redact_fallback_text, RedactionManifest};
use rusqlite::Connection;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const MAX_ENDPOINTS: usize = 30;
const MAX_ROUTE_LEN: usize = 100;
const MAX_ENDPOINT_FACETS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EndpointKey {
    method: String,
    scheme: String,
    host: String,
    port: i64,
    route: String,
}

#[derive(Debug)]
struct EndpointAggregate {
    key: EndpointKey,
    count: i64,
    first_id: i64,
    last_id: i64,
    statuses: BTreeMap<String, i64>,
    content_types: BTreeMap<String, i64>,
    roles: BTreeMap<String, i64>,
    query_names: BTreeSet<String>,
    tags: BTreeSet<String>,
}

#[derive(Debug)]
struct NormalizedRoute {
    path: String,
    query_names: BTreeSet<String>,
}

fn normalize_route(raw: &str) -> NormalizedRoute {
    let (path, query) = if let Ok(parsed) = url::Url::parse(raw) {
        (
            parsed.path().to_string(),
            parsed.query().unwrap_or_default().to_string(),
        )
    } else {
        let without_fragment = raw.split('#').next().unwrap_or(raw);
        let (path, query) = without_fragment
            .split_once('?')
            .unwrap_or((without_fragment, ""));
        (path.to_string(), query.to_string())
    };
    let path = match path.trim() {
        "" => "/".to_string(),
        "*" => "*".to_string(),
        path if path.starts_with('/') => path.to_string(),
        path => format!("/{path}"),
    };
    let query_names = url::form_urlencoded::parse(query.as_bytes())
        .map(|(name, _)| name.into_owned())
        .filter(|name| !name.is_empty())
        .collect();
    NormalizedRoute { path, query_names }
}

fn normalize_content_type(content_type: Option<String>) -> String {
    let value: String = content_type
        .as_deref()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(80)
        .collect();
    if value.is_empty() {
        "unknown".to_string()
    } else {
        value
    }
}

fn request_role(req_headers: &str) -> String {
    let Ok(serde_json::Value::Object(headers)) =
        serde_json::from_str::<serde_json::Value>(req_headers)
    else {
        return "未知".to_string();
    };
    let names: BTreeSet<String> = headers
        .keys()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    let has_authorization = names.iter().any(|name| {
        matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "x-api-key"
                | "api-key"
                | "x-auth-token"
                | "x-access-token"
        )
    });
    let has_cookie = names.contains("cookie");
    match (has_authorization, has_cookie) {
        (true, true) => "混合凭据".to_string(),
        (true, false) => "Authorization".to_string(),
        (false, true) => "会话 Cookie".to_string(),
        (false, false) => "匿名".to_string(),
    }
}

fn normalize_authority(key: &EndpointKey) -> String {
    let host = if key.host.contains(':') && !key.host.starts_with('[') {
        format!("[{}]", key.host)
    } else {
        key.host.clone()
    };
    let default_port =
        (key.scheme == "http" && key.port == 80) || (key.scheme == "https" && key.port == 443);
    if default_port || key.port <= 0 {
        format!("{}://{host}", key.scheme)
    } else {
        format!("{}://{host}:{}", key.scheme, key.port)
    }
}

fn is_static_endpoint(endpoint: &EndpointAggregate) -> bool {
    let route = endpoint.key.route.to_ascii_lowercase();
    let static_extension = [
        ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webm",
    ]
    .iter()
    .any(|extension| route.ends_with(extension));
    static_extension
        || endpoint.content_types.keys().any(|content_type| {
            content_type.starts_with("image/")
                || content_type.starts_with("font/")
                || content_type.starts_with("audio/")
                || content_type.starts_with("video/")
                || matches!(
                    content_type.as_str(),
                    "text/css" | "text/javascript" | "application/javascript"
                )
        })
}

fn is_noise_endpoint(endpoint: &EndpointAggregate) -> bool {
    let route = endpoint
        .key
        .route
        .trim_end_matches('/')
        .to_ascii_lowercase();
    [
        "/health",
        "/healthz",
        "/live",
        "/livez",
        "/ready",
        "/readyz",
        "/metrics",
        "/favicon.ico",
        "/robots.txt",
    ]
    .iter()
    .any(|suffix| route == *suffix || route.ends_with(&format!("/{}", &suffix[1..])))
}

fn endpoint_score(endpoint: &EndpointAggregate, min_id: i64, max_id: i64) -> i64 {
    let span = (max_id - min_id).max(1);
    let recency = ((endpoint.last_id - min_id).max(0) * 100 / span).clamp(0, 100);
    let mut score = 500 + recency;
    score += match endpoint.count {
        1 => 160,
        2..=3 => 100,
        4..=10 => 40,
        _ => -((endpoint.count as u64).ilog2() as i64 * 25),
    };
    if endpoint.key.method != "GET" && endpoint.key.method != "HEAD" {
        score += 80;
    }
    if endpoint
        .statuses
        .keys()
        .any(|status| status.starts_with('4') || status.starts_with('5'))
    {
        score += 80;
    }
    if endpoint
        .content_types
        .keys()
        .any(|content_type| content_type == "application/json" || content_type == "text/html")
    {
        score += 50;
    }
    if endpoint.roles.len() > 1 {
        score += 70;
    }
    if !endpoint.tags.is_empty() {
        score += 240;
    }
    if is_static_endpoint(endpoint) {
        score -= 450;
    }
    if is_noise_endpoint(endpoint) {
        score -= 500 + (endpoint.count as u64).ilog2() as i64 * 40;
    }
    score
}

fn top_counts(counts: &BTreeMap<String, i64>) -> String {
    let mut values: Vec<_> = counts.iter().collect();
    values.sort_by_key(|(label, count)| (Reverse(**count), (*label).clone()));
    values
        .into_iter()
        .take(MAX_ENDPOINT_FACETS)
        .map(|(label, count)| format!("{label}×{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn novelty_label(endpoint: &EndpointAggregate, min_id: i64, max_id: i64) -> &'static str {
    if endpoint.count == 1 {
        return "唯一";
    }
    let recent_threshold = min_id + ((max_id - min_id).max(0) * 4 / 5);
    if endpoint.first_id >= recent_threshold {
        "近期新增"
    } else if endpoint.count <= 3 {
        "低频"
    } else {
        "重复"
    }
}

fn display_route(
    endpoint: &EndpointAggregate,
    index: usize,
    manifest: &mut RedactionManifest,
) -> String {
    let location = format!("planner.endpoint[{index}].route");
    let mut route = redact_fallback_text(&endpoint.key.route, &location, true, manifest);
    if !endpoint.query_names.is_empty() {
        let query = endpoint
            .query_names
            .iter()
            .enumerate()
            .map(|(query_index, name)| {
                let location = format!("planner.endpoint[{index}].query[{query_index}]");
                manifest.record_redaction(&location, "query_value");
                let name = redact_fallback_text(name, &location, true, manifest);
                let name: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
                format!("{name}=[REDACTED:query_value]")
            })
            .collect::<Vec<_>>()
            .join("&");
        route.push('?');
        route.push_str(&query);
    }
    route.chars().take(MAX_ROUTE_LEN).collect()
}

/// 构造项目流量摘要文本。
pub fn build_digest(conn: &Connection, project_id: i64) -> Result<String, String> {
    build_redacted_digest(conn, project_id, &mut RedactionManifest::default())
}

/// 构造可发送给任务规划器的摘要。所有 route 聚合、权重计算和角色分类均在
/// 本地完成；角色只按凭据类 header 名分类，绝不读取或输出凭据值。
pub fn build_redacted_digest(
    conn: &Connection,
    project_id: i64,
    manifest: &mut RedactionManifest,
) -> Result<String, String> {
    let (total, min_id, max_id): (i64, Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT COUNT(*), MIN(id), MAX(id) FROM traffic WHERE project_id = ?1",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| error.to_string())?;
    if total == 0 {
        return Err("当前项目还没有流量。先启动代理抓一段目标流量，再生成测试计划。".into());
    }
    let min_id = min_id.unwrap_or_default();
    let max_id = max_id.unwrap_or(min_id);

    let target: String = conn
        .query_row(
            "SELECT target_host FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .unwrap_or_default();

    let mut endpoint_map: HashMap<EndpointKey, EndpointAggregate> = HashMap::new();
    let mut tag_counts: HashMap<String, i64> = HashMap::new();
    let mut stmt = conn
        .prepare(
            "SELECT id, method, scheme, host, port, path, status, content_type,
                    req_headers, rule_tags
             FROM traffic WHERE project_id = ?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let mut rows = stmt
        .query([project_id])
        .map_err(|error| error.to_string())?;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let id: i64 = row.get(0).map_err(|error| error.to_string())?;
        let method: String = row.get(1).map_err(|error| error.to_string())?;
        let scheme: String = row.get(2).map_err(|error| error.to_string())?;
        let host: String = row.get(3).map_err(|error| error.to_string())?;
        let port: i64 = row.get(4).map_err(|error| error.to_string())?;
        let path: String = row.get(5).map_err(|error| error.to_string())?;
        let status: Option<i64> = row.get(6).map_err(|error| error.to_string())?;
        let content_type: Option<String> = row.get(7).map_err(|error| error.to_string())?;
        let req_headers: String = row.get(8).map_err(|error| error.to_string())?;
        let rule_tags: String = row.get(9).map_err(|error| error.to_string())?;

        let normalized = normalize_route(&path);
        let key = EndpointKey {
            method: method.trim().to_ascii_uppercase(),
            scheme: scheme.trim().to_ascii_lowercase(),
            host: host.trim().trim_end_matches('.').to_ascii_lowercase(),
            port,
            route: normalized.path,
        };
        let endpoint = endpoint_map
            .entry(key.clone())
            .or_insert_with(|| EndpointAggregate {
                key,
                count: 0,
                first_id: id,
                last_id: id,
                statuses: BTreeMap::new(),
                content_types: BTreeMap::new(),
                roles: BTreeMap::new(),
                query_names: BTreeSet::new(),
                tags: BTreeSet::new(),
            });
        endpoint.count += 1;
        endpoint.first_id = endpoint.first_id.min(id);
        endpoint.last_id = endpoint.last_id.max(id);
        endpoint.query_names.extend(normalized.query_names);
        *endpoint
            .statuses
            .entry(status.map_or_else(|| "无响应".to_string(), |value| value.to_string()))
            .or_default() += 1;
        *endpoint
            .content_types
            .entry(normalize_content_type(content_type))
            .or_default() += 1;
        *endpoint
            .roles
            .entry(request_role(&req_headers))
            .or_default() += 1;
        if let Ok(tags) = serde_json::from_str::<Vec<String>>(&rule_tags) {
            for tag in tags {
                endpoint.tags.insert(tag.clone());
                *tag_counts.entry(tag).or_default() += 1;
            }
        }
    }

    let mut endpoints: Vec<_> = endpoint_map.into_values().collect();
    endpoints.sort_by(|left, right| {
        endpoint_score(right, min_id, max_id)
            .cmp(&endpoint_score(left, min_id, max_id))
            .then_with(|| right.last_id.cmp(&left.last_id))
            .then_with(|| left.key.method.cmp(&right.key.method))
            .then_with(|| left.key.host.cmp(&right.key.host))
            .then_with(|| left.key.route.cmp(&right.key.route))
    });
    endpoints.truncate(MAX_ENDPOINTS);

    let target = redact_fallback_text(&target, "planner.target", true, manifest);
    let mut out = format!(
        "目标: {}\n已抓取流量: {} 条\n\n## 端点聚合（风险/新颖度加权，静态与高频噪声降权）\n",
        if target.is_empty() {
            "（未填写）"
        } else {
            &target
        },
        total
    );
    for (index, endpoint) in endpoints.iter().enumerate() {
        let method = redact_fallback_text(
            &endpoint.key.method,
            &format!("planner.endpoint[{index}].method"),
            true,
            manifest,
        );
        let authority = redact_fallback_text(
            &normalize_authority(&endpoint.key),
            &format!("planner.endpoint[{index}].authority"),
            true,
            manifest,
        );
        let route = display_route(endpoint, index, manifest);
        let tags = if endpoint.tags.is_empty() {
            String::new()
        } else {
            let tags = endpoint
                .tags
                .iter()
                .map(|tag| {
                    redact_fallback_text(
                        tag,
                        &format!("planner.endpoint[{index}].tag"),
                        true,
                        manifest,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("；标签: {tags}")
        };
        let content_types = redact_fallback_text(
            &top_counts(&endpoint.content_types),
            &format!("planner.endpoint[{index}].content_types"),
            true,
            manifest,
        );
        out.push_str(&format!(
            "- {} {} {} ({}次；状态: {}；Content-Type: {}；角色: {}；新颖度: {}，最近流量 #{}{})\n",
            method,
            authority,
            route,
            endpoint.count,
            top_counts(&endpoint.statuses),
            content_types,
            top_counts(&endpoint.roles),
            novelty_label(endpoint, min_id, max_id),
            endpoint.last_id,
            tags,
        ));
    }

    if !tag_counts.is_empty() {
        let mut tags: Vec<_> = tag_counts.into_iter().collect();
        tags.sort_by_key(|(tag, count)| (Reverse(*count), tag.clone()));
        out.push_str("\n## 被动规则命中分布\n");
        for (tag, count) in tags {
            let tag = redact_fallback_text(&tag, "planner.rule_tag", true, manifest);
            out.push_str(&format!("- {tag}: {count} 次\n"));
        }
    }

    let mut findings_text = String::new();
    {
        let mut findings = conn
            .prepare(
                "SELECT id, title, severity, confidence, status FROM findings
                 WHERE project_id = ?1 AND status <> 'rejected'
                 ORDER BY id LIMIT 50",
            )
            .map_err(|error| error.to_string())?;
        let rows = findings
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (id, title, severity, confidence, status) =
                row.map_err(|error| error.to_string())?;
            findings_text.push_str(&format!(
                "- [#{id}] {title}（{severity}，置信度 {confidence}，{status}）\n"
            ));
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

    let (revision, needs_update, update_reason): (i64, i64, String) = conn
        .query_row(
            "SELECT
                 COALESCE((SELECT revision FROM test_plans WHERE project_id=?1), 0),
                 COALESCE((SELECT needs_update FROM test_plans WHERE project_id=?1), 0),
                 COALESCE((SELECT update_reason FROM test_plans WHERE project_id=?1), '')",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| error.to_string())?;
    let mut plan_lines = String::new();
    let mut plan_nodes = conn
        .prepare(
            "SELECT node.stable_key, node.node_type, node.title, node.status, node.priority,
                    node.source, node.locked_fields,
                    (SELECT COUNT(*) FROM task_evidence link WHERE link.task_id=node.id),
                    COALESCE((
                        SELECT group_concat(prerequisite.stable_key, ',')
                        FROM task_prerequisites edge
                        JOIN task_nodes prerequisite ON prerequisite.id=edge.prerequisite_id
                        WHERE edge.task_id=node.id
                    ), '')
             FROM task_nodes node
             WHERE node.project_id=?1 AND node.archived=0
             ORDER BY node.sort_order, node.id
             LIMIT 40",
        )
        .map_err(|error| error.to_string())?;
    let rows = plan_nodes
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    for (index, row) in rows.enumerate() {
        let (
            stable_key,
            node_type,
            title,
            status,
            priority,
            source,
            locks,
            evidence,
            prerequisites,
        ) = row.map_err(|error| error.to_string())?;
        let title = redact_fallback_text(
            &title,
            &format!("planner.current_plan[{index}].title"),
            true,
            manifest,
        );
        plan_lines.push_str(&format!(
            "- key={stable_key}；type={node_type}；title={title}；status={status}；\
             priority={priority}；source={source}；locks={locks}；Evidence={evidence}；\
             prerequisites=[{prerequisites}]\n"
        ));
    }
    if !plan_lines.is_empty() {
        let update_reason = redact_fallback_text(
            &update_reason,
            "planner.current_plan.update_reason",
            true,
            manifest,
        );
        out.push_str(&format!(
            "\n## 当前测试计划（revision {revision}；可更新={}；原因={}）\n",
            needs_update != 0,
            if update_reason.is_empty() {
                "无"
            } else {
                &update_reason
            }
        ));
        out.push_str(&plan_lines);
        out.push_str(
            "保持人工节点、人工状态、实际观察、锁定字段和 Evidence；语义相同节点复用 key。\n",
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::Db;

    fn test_db(name: &str) -> (tempfile::TempDir, Db, i64) {
        let dir = tempfile::Builder::new()
            .prefix(&format!("rustforge-digest-{name}-"))
            .tempdir()
            .unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t','t.cn','[]')",
                [],
            )
            .unwrap();
        let project_id = db.conn.last_insert_rowid();
        (dir, db, project_id)
    }

    #[test]
    fn digest_summarizes_and_never_emits_query_values() {
        let (_dir, db, project_id) = test_db("summary");
        for (path, headers, tags) in [
            (
                "/login?token=secret&next=%2Fhome",
                r#"{"cookie":"sid=one"}"#,
                r#"["JWT"]"#,
            ),
            (
                "/login?next=%2Fadmin&token=other-secret",
                r#"{"authorization":"Bearer secret"}"#,
                "[]",
            ),
            ("/admin", "{}", "[]"),
        ] {
            db.conn
                .execute(
                    "INSERT INTO traffic(
                        project_id, method, host, path, url, status, content_type,
                        req_headers, rule_tags
                     ) VALUES(?1, 'GET', 't.cn', ?2, 'https://t.cn/x', 200,
                              'application/json; charset=utf-8', ?3, ?4)",
                    rusqlite::params![project_id, path, headers, tags],
                )
                .unwrap();
        }

        let text = build_digest(&db.conn, project_id).unwrap();
        assert!(text.contains("已抓取流量: 3 条"));
        assert_eq!(
            text.lines().filter(|line| line.contains("/login")).count(),
            1
        );
        assert!(text.contains("/login?next=[REDACTED:query_value]"));
        assert!(text.contains("(2次；状态: 200×2"));
        assert!(text.contains("Content-Type: application/json×2"));
        assert!(text.contains("角色: Authorization×1, 会话 Cookie×1"));
        assert!(text.contains("新颖度:"));
        assert!(text.contains("JWT: 1 次"));
        assert!(!text.contains("secret"));
        assert!(!text.contains("%2Fhome"));
        assert!(!text.contains("%2Fadmin"));
    }

    #[test]
    fn rejected_findings_are_excluded_from_planning() {
        let (_dir, db, project_id) = test_db("rejected");
        db.conn
            .execute(
                "INSERT INTO traffic(project_id, method, host, path, url)
                 VALUES(?1, 'GET', 't.cn', '/', 'https://t.cn/')",
                [project_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(project_id, source, title)
                 VALUES(?1, 'rule', '保留的待验证发现')",
                [project_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(project_id, source, title)
                 VALUES(?1, 'rule', '不应重进规划的发现')",
                [project_id],
            )
            .unwrap();
        let rejected_id = db.conn.last_insert_rowid();
        db.conn
            .execute(
                "INSERT INTO finding_events(
                    finding_id, event_type, old_value, new_value, reason, actor
                 ) VALUES(?1, 'status_changed', 'pending', 'rejected',
                          '人工判定误报', 'analyst:test')",
                [rejected_id],
            )
            .unwrap();
        db.conn
            .execute(
                "UPDATE findings SET status = 'rejected' WHERE id = ?1",
                [rejected_id],
            )
            .unwrap();

        let text = build_digest(&db.conn, project_id).unwrap();
        assert!(text.contains("保留的待验证发现"));
        assert!(!text.contains("不应重进规划的发现"));
    }

    #[test]
    fn static_and_high_frequency_noise_are_ranked_below_novel_routes() {
        let (_dir, db, project_id) = test_db("weight");
        for _ in 0..60 {
            db.conn
                .execute(
                    "INSERT INTO traffic(
                        project_id, method, host, path, url, status, content_type
                     ) VALUES(?1, 'GET', 't.cn', '/assets/app.js',
                              'https://t.cn/assets/app.js', 200, 'application/javascript')",
                    [project_id],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO traffic(
                        project_id, method, host, path, url, status, content_type
                     ) VALUES(?1, 'GET', 't.cn', '/health',
                              'https://t.cn/health', 200, 'text/plain')",
                    [project_id],
                )
                .unwrap();
        }
        db.conn
            .execute(
                "INSERT INTO traffic(
                    project_id, method, host, path, url, status, content_type
                 ) VALUES(?1, 'POST', 't.cn', '/admin/users',
                          'https://t.cn/admin/users', 403, 'application/json')",
                [project_id],
            )
            .unwrap();

        let text = build_digest(&db.conn, project_id).unwrap();
        let admin = text.find("/admin/users").unwrap();
        assert!(admin < text.find("/assets/app.js").unwrap());
        assert!(admin < text.find("/health").unwrap());
    }

    #[test]
    fn digest_empty_project_errors() {
        let (_dir, db, project_id) = test_db("empty");
        assert!(build_digest(&db.conn, project_id).is_err());
    }
}
