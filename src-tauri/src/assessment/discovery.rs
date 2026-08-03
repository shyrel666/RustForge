use super::executor::{AssessmentExecutor, IdentitySelection, StopCondition};
use super::model::AssessmentEndpoint;
use super::policy::{exact_origin, RequestPhase};
use crate::replay::model::ReplayRun;
use crate::storage::db::Pool;
use regex::Regex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use url::Url;

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub endpoint: AssessmentEndpoint,
    pub discovery_replay_run_id: Option<i64>,
}

#[derive(Debug)]
pub struct DiscoveryResult {
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub stop_condition: Option<StopCondition>,
}

#[derive(Debug, Clone)]
struct Candidate {
    url: String,
    source_kind: &'static str,
}

pub async fn discover(
    pool: &Pool,
    executor: &mut AssessmentExecutor,
) -> Result<DiscoveryResult, String> {
    let discovery_identity = if executor.identity_available(IdentitySelection::A) {
        IdentitySelection::A
    } else {
        IdentitySelection::Anonymous
    };
    let start_url = executor.contract().normalized_start_url.clone();
    let actual_run_id = executor.run_id();
    let mut queue = VecDeque::from([Candidate {
        url: start_url,
        source_kind: "start_url",
    }]);
    let mut queued = HashSet::new();
    let mut discovered = HashMap::<String, DiscoveredEndpoint>::new();
    let mut stop_condition = None;

    while let Some(candidate) = queue.pop_front() {
        if executor.request_count() >= executor.discovery_limit() || executor.is_cancelled() {
            break;
        }
        let normalized = normalize_candidate_url(&candidate.url)?;
        if !queued.insert(normalized.clone()) {
            continue;
        }
        if let Err(reason) = executor.authorize_candidate("GET", &normalized, Vec::new()) {
            insert_gap(
                pool,
                actual_run_id,
                "policy",
                "discovery_candidate_rejected",
                &reason,
            )?;
            continue;
        }
        let (replay, stop) = executor
            .execute(
                RequestPhase::Discovery,
                "GET",
                &normalized,
                Vec::new(),
                discovery_identity,
                "discovery",
            )
            .await?;
        let endpoint = persist_replay_endpoint(
            pool,
            actual_run_id,
            &replay,
            candidate.source_kind,
            discovery_identity != IdentitySelection::Anonymous,
            executor.contract(),
        )?;
        let endpoint_key = endpoint.endpoint.endpoint_id.clone();
        discovered.insert(endpoint_key, endpoint);

        if let Some(condition) = stop {
            stop_condition = Some(condition);
            break;
        }
        if replay.outcome != "completed" {
            insert_gap(
                pool,
                actual_run_id,
                "response",
                "discovery_response_incomplete",
                "发现响应不完整，未解析页面链接",
            )?;
            continue;
        }
        if let Some(location) = response_header(&replay, "location") {
            enqueue_redirect(
                pool,
                executor,
                actual_run_id,
                &replay.url,
                &location,
                &mut queue,
            )?;
        }
        if response_header(&replay, "content-type")
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
        {
            if let Some(html) = replay.response_body_text.as_deref() {
                for href in extract_anchor_hrefs(html) {
                    if let Some(url) = resolve_href(&replay.url, &href) {
                        match executor.authorize_candidate("GET", &url, Vec::new()) {
                            Ok(()) => queue.push_back(Candidate {
                                url,
                                source_kind: "crawl",
                            }),
                            Err(reason) => insert_gap(
                                pool,
                                actual_run_id,
                                "policy",
                                "linked_candidate_rejected",
                                &reason,
                            )?,
                        }
                    }
                }
            }
        }
    }

    if !queue.is_empty() && executor.request_count() >= executor.discovery_limit() {
        insert_gap(
            pool,
            actual_run_id,
            "budget",
            "discovery_budget_exhausted",
            "发现请求预算已用尽；剩余实际链接未访问，预算保留给安全验证",
        )?;
    }

    if executor.contract().include_recent_traffic {
        merge_recent_traffic(pool, actual_run_id, executor, &mut discovered)?;
    }
    let mut endpoints = discovered.into_values().collect::<Vec<_>>();
    endpoints.sort_by(|left, right| left.endpoint.endpoint_id.cmp(&right.endpoint.endpoint_id));
    Ok(DiscoveryResult {
        endpoints,
        stop_condition,
    })
}

fn persist_replay_endpoint(
    pool: &Pool,
    run_id: i64,
    replay: &ReplayRun,
    source_kind: &str,
    has_authentication: bool,
    contract: &super::model::AssessmentContractPreview,
) -> Result<DiscoveredEndpoint, String> {
    let url = Url::parse(&replay.url).map_err(|_| "发现响应 URL 已损坏".to_string())?;
    let status = replay.status;
    let content_type = response_header(replay, "content-type").unwrap_or_default();
    let endpoint = persist_endpoint(
        pool,
        run_id,
        &replay.method,
        url,
        source_kind,
        None,
        status,
        content_type,
        has_authentication,
        Vec::new(),
        replay.outcome == "completed",
        contract,
    )?;
    Ok(DiscoveredEndpoint {
        endpoint,
        discovery_replay_run_id: Some(replay.id),
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_endpoint(
    pool: &Pool,
    run_id: i64,
    method: &str,
    mut url: Url,
    source_kind: &str,
    source_traffic_id: Option<i64>,
    status: Option<u16>,
    content_type: String,
    has_authentication: bool,
    passive_tags: Vec<String>,
    response_complete: bool,
    contract: &super::model::AssessmentContractPreview,
) -> Result<AssessmentEndpoint, String> {
    url.set_fragment(None);
    let canonical_url = url.to_string();
    let endpoint_key =
        sha256(format!("{}\n{canonical_url}", method.to_ascii_uppercase()).as_bytes());
    let opaque_id = format!("ep_{}", &endpoint_key[..24]);
    let mut query_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    query_names.sort();
    query_names.dedup();
    let path = url.path().to_string();
    let resource_owner_profile_id = contract
        .resource_ownership
        .iter()
        .find(|claim| path_matches_claim(&path, &claim.path))
        .map(|claim| claim.owner_profile_id);
    let query_json = serde_json::to_string(&query_names).map_err(|error| error.to_string())?;
    let tags_json = serde_json::to_string(&passive_tags).map_err(|error| error.to_string())?;
    let conn = pool.get().map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_endpoints(
             run_id, endpoint_key, method, url, path, query_parameter_names,
             source_kind, source_traffic_id, status, content_type,
             has_authentication, passive_tags, response_complete,
             resource_owner_profile_id
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(run_id, endpoint_key) DO UPDATE SET
             status = COALESCE(excluded.status, assessment_endpoints.status),
             content_type = CASE WHEN excluded.content_type = ''
                                 THEN assessment_endpoints.content_type
                                 ELSE excluded.content_type END,
             has_authentication = MAX(
                 assessment_endpoints.has_authentication,
                 excluded.has_authentication
             ),
             response_complete = MIN(
                 assessment_endpoints.response_complete,
                 excluded.response_complete
             ),
             passive_tags = CASE WHEN excluded.passive_tags = '[]'
                                 THEN assessment_endpoints.passive_tags
                                 ELSE excluded.passive_tags END",
        rusqlite::params![
            run_id,
            endpoint_key,
            method.to_ascii_uppercase(),
            canonical_url,
            path,
            query_json,
            source_kind,
            source_traffic_id,
            status,
            content_type,
            has_authentication,
            tags_json,
            response_complete,
            resource_owner_profile_id,
        ],
    )
    .map_err(|error| error.to_string())?;
    let id: i64 = conn
        .query_row(
            "SELECT id FROM assessment_endpoints WHERE run_id = ?1 AND endpoint_key = ?2",
            rusqlite::params![run_id, endpoint_key],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    Ok(AssessmentEndpoint {
        id,
        run_id,
        endpoint_id: opaque_id,
        method: method.to_ascii_uppercase(),
        url: url.to_string(),
        path: url.path().to_string(),
        query_parameter_names: query_names,
        source_kind: source_kind.to_string(),
        status,
        content_type,
        has_authentication,
        passive_tags,
        response_complete,
        resource_owner_profile_id,
    })
}

fn merge_recent_traffic(
    pool: &Pool,
    run_id: i64,
    executor: &AssessmentExecutor,
    discovered: &mut HashMap<String, DiscoveredEndpoint>,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    let mut statement = conn
        .prepare(
            "SELECT id, method, url, status, content_type, rule_tags, resp_truncated
             FROM traffic
             WHERE project_id = ?1
               AND method IN ('GET', 'HEAD')
               AND (req_body IS NULL OR length(req_body) = 0)
             ORDER BY id DESC LIMIT 500",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([executor.contract().project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<u16>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    drop(conn);

    for (traffic_id, method, raw_url, status, content_type, tags, truncated) in rows {
        if executor
            .authorize_candidate(&method, &raw_url, Vec::new())
            .is_err()
        {
            continue;
        }
        let url = match Url::parse(&raw_url) {
            Ok(url)
                if exact_origin(&url).ok().as_deref()
                    == Some(&executor.contract().exact_origin) =>
            {
                url
            }
            _ => continue,
        };
        let passive_tags = serde_json::from_str(&tags).unwrap_or_default();
        let endpoint = persist_endpoint(
            pool,
            run_id,
            &method,
            url,
            "traffic",
            Some(traffic_id),
            status,
            content_type.unwrap_or_default(),
            false,
            passive_tags,
            !truncated,
            executor.contract(),
        )?;
        discovered
            .entry(endpoint.endpoint_id.clone())
            .or_insert(DiscoveredEndpoint {
                endpoint,
                discovery_replay_run_id: None,
            });
    }
    Ok(())
}

fn enqueue_redirect(
    pool: &Pool,
    executor: &AssessmentExecutor,
    run_id: i64,
    base_url: &str,
    location: &str,
    queue: &mut VecDeque<Candidate>,
) -> Result<(), String> {
    let Some(resolved) = resolve_href(base_url, location) else {
        return Ok(());
    };
    if executor
        .authorize_candidate("GET", &resolved, Vec::new())
        .is_ok()
    {
        queue.push_back(Candidate {
            url: resolved,
            source_kind: "redirect",
        });
    } else {
        insert_gap(
            pool,
            run_id,
            "origin",
            "redirect_not_followed",
            "重定向目标不满足精确 origin 或安全路径策略",
        )?;
    }
    Ok(())
}

fn extract_anchor_hrefs(html: &str) -> Vec<String> {
    static ANCHOR: OnceLock<Regex> = OnceLock::new();
    let regex = ANCHOR.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#)
            .expect("valid anchor href regex")
    });
    regex
        .captures_iter(html)
        .take(1000)
        .filter_map(|capture| {
            capture
                .get(1)
                .or_else(|| capture.get(2))
                .or_else(|| capture.get(3))
        })
        .map(|value| decode_minimal_html_entities(value.as_str()))
        .collect()
}

fn resolve_href(base_url: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty()
        || href.starts_with('#')
        || href.to_ascii_lowercase().starts_with("javascript:")
        || href.to_ascii_lowercase().starts_with("mailto:")
        || href.to_ascii_lowercase().starts_with("data:")
    {
        return None;
    }
    let base = Url::parse(base_url).ok()?;
    let mut resolved = base.join(href).ok()?;
    resolved.set_fragment(None);
    Some(resolved.to_string())
}

fn normalize_candidate_url(raw: &str) -> Result<String, String> {
    let mut url = Url::parse(raw).map_err(|_| "发现候选 URL 无效".to_string())?;
    url.set_fragment(None);
    Ok(url.to_string())
}

fn response_header(run: &ReplayRun, expected: &str) -> Option<String> {
    run.response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(expected))
        .map(|header| header.value.clone())
}

fn decode_minimal_html_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn path_matches_claim(path: &str, claim: &str) -> bool {
    claim == "/"
        || path == claim
        || path
            .strip_prefix(claim)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn insert_gap(
    pool: &Pool,
    run_id: i64,
    category: &str,
    reason_code: &str,
    detail: &str,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_coverage_gaps(run_id, category, reason_code, detail)
         VALUES(?1, ?2, ?3, ?4)",
        rusqlite::params![run_id, category, reason_code, detail],
    )
    .map_err(|error| error.to_string())?;
    super::service::append_event(
        &conn,
        run_id,
        None,
        "coverage_gap_added",
        None,
        Some(reason_code),
        &json!({ "category": category }),
    )?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::model::{AssessmentContractInput, AssessmentStatus};
    use crate::replay::model::TlsPolicy;
    use crate::secrets::MemorySecretStore;
    use crate::storage::db::open_pool;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn extracts_only_anchor_hrefs_and_resolves_without_fragments() {
        let html = r#"
            <script>fetch('/not-allowed')</script>
            <img src="/asset.png">
            <a href="/one?q=a&amp;b=c#section">one</a>
            <A HREF='/two'>two</A>
            <a href="javascript:alert(1)">bad</a>
        "#;
        let hrefs = extract_anchor_hrefs(html);
        assert_eq!(hrefs.len(), 3);
        assert_eq!(
            resolve_href("https://example.test/start", &hrefs[0]).unwrap(),
            "https://example.test/one?q=a&b=c"
        );
        assert!(resolve_href("https://example.test/", &hrefs[2]).is_none());
    }

    #[tokio::test]
    async fn discovery_starts_without_traffic_and_fetches_only_linked_safe_same_origin_pages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for index in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = socket.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let first_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                paths.push(first_line.clone());
                let (content_type, body) = if index == 0 {
                    (
                        "text/html",
                        concat!(
                            "<a href='/safe?x=1'>safe</a>",
                            "<a href='/account/delete'>danger</a>",
                            "<a href='http://outside.test/other'>cross</a>",
                            "<img src='/static.png'>",
                            "<form action='/submit'><button>submit</button></form>",
                            "<script>fetch('/script-request')</script>"
                        ),
                    )
                } else {
                    ("text/plain", "done")
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            paths
        });

        let dir = tempdir().unwrap();
        let pool = open_pool(&dir.path().join("discovery.db")).unwrap();
        let project_id;
        let run_id;
        {
            let mut conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO projects(name, target_host, scope)
                 VALUES('discovery', '127.0.0.1', '[\"127.0.0.1\"]')",
                [],
            )
            .unwrap();
            project_id = conn.last_insert_rowid();
            conn.execute_batch(
                "INSERT INTO settings(key, value) VALUES
                    ('ai_current', 'provider'),
                    ('ai_enabled', 'true'),
                    ('ai_providers',
                     '[{\"id\":\"provider\",\"name\":\"Fixture\",\"base_url\":\"https://provider.test/v1\",\"model\":\"model\",\"note\":\"\",\"supports_json_schema\":true}]');",
            )
            .unwrap();
            let store = MemorySecretStore::default();
            let preview = super::super::service::preview_contract(
                &conn,
                &store,
                &AssessmentContractInput {
                    project_id,
                    start_url: format!("http://{address}/start"),
                    excluded_paths: Vec::new(),
                    tls_policy: "strict".into(),
                    request_budget: 12,
                    requests_per_second: 2.0,
                    identity_a_profile_id: None,
                    identity_b_profile_id: None,
                    resource_ownership: Vec::new(),
                    include_recent_traffic: false,
                    provider_id: "provider".into(),
                    model: "model".into(),
                    max_rounds: 1,
                    written_authorization_confirmed: true,
                },
            )
            .unwrap();
            let run = super::super::service::create_run(&mut conn, &preview).unwrap();
            run_id = run.id;
            super::super::service::transition_run(
                &mut conn,
                project_id,
                run_id,
                AssessmentStatus::Discovering,
                None,
            )
            .unwrap();
        }
        let session_id = {
            let conn = pool.get().unwrap();
            crate::replay::service::create_assessment_session(
                &conn,
                project_id,
                run_id,
                TlsPolicy::Strict,
            )
            .unwrap()
        };
        let (cancel_tx, cancel) = tokio::sync::watch::channel(false);
        let mut executor = AssessmentExecutor::new(
            pool.clone(),
            Arc::new(MemorySecretStore::default()),
            project_id,
            run_id,
            session_id,
            cancel,
        )
        .unwrap();
        let result = discover(&pool, &mut executor).await.unwrap();
        drop(cancel_tx);
        let paths = server.await.unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths[0].starts_with("GET /start "));
        assert!(paths[1].starts_with("GET /safe?x=1 "));
        assert_eq!(result.endpoints.len(), 2);
        assert!(result.stop_condition.is_none());
        let conn = pool.get().unwrap();
        let counts: (i64, i64) = conn
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM traffic WHERE project_id=?1),
                     (SELECT COUNT(*) FROM assessment_coverage_gaps WHERE run_id=?2)",
                rusqlite::params![project_id, run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts.0, 0, "proxy Traffic is not a discovery prerequisite");
        assert!(
            counts.1 >= 2,
            "dangerous and cross-origin links become gaps"
        );
    }
}
