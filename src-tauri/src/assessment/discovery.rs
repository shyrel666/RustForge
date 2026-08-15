use super::executor::{AssessmentExecutor, IdentitySelection, StopCondition};
use super::model::AssessmentEndpoint;
use super::policy::{exact_origin, RequestPhase};
use super::verifier::{self, ResponseObservation};
use crate::replay::model::ReplayRun;
use crate::storage::db::Pool;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
};
use regex::Regex;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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
    content_kind: CandidateContentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateContentKind {
    Page,
    Script,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HtmlFormField {
    name: String,
    input_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HtmlFormInventory {
    action: String,
    method: String,
    fields: Vec<HtmlFormField>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HtmlInventory {
    title: String,
    anchors: Vec<String>,
    forms: Vec<HtmlFormInventory>,
    scripts: Vec<String>,
    resources: Vec<String>,
}

pub async fn discover(
    pool: &Pool,
    executor: &mut AssessmentExecutor,
) -> Result<DiscoveryResult, String> {
    let discovery_identity = IdentitySelection::Anonymous;
    let start_url = executor.contract().normalized_start_url.clone();
    let actual_run_id = executor.run_id();
    let mut queue = VecDeque::from([Candidate {
        url: start_url,
        source_kind: "start_url",
        content_kind: CandidateContentKind::Page,
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
        persist_response_surface(
            pool,
            actual_run_id,
            &endpoint.endpoint,
            &replay,
            candidate.content_kind,
            candidate.source_kind,
            discovery_identity,
        )?;
        run_local_baseline(
            pool,
            executor.contract().project_id,
            &endpoint.endpoint,
            &replay,
            discovery_identity,
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
                let inventory = parse_html_inventory(html);
                for href in inventory.anchors {
                    if let Some(url) = resolve_href(&replay.url, &href) {
                        match executor.authorize_candidate("GET", &url, Vec::new()) {
                            Ok(()) => queue.push_back(Candidate {
                                url,
                                source_kind: "crawl",
                                content_kind: CandidateContentKind::Page,
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
                register_forms_and_resources(
                    pool,
                    executor,
                    actual_run_id,
                    &replay.url,
                    inventory.forms,
                    inventory.resources,
                )?;
                for source in inventory.scripts {
                    let Some(url) = resolve_href(&replay.url, &source) else {
                        continue;
                    };
                    match executor.authorize_candidate("GET", &url, Vec::new()) {
                        Ok(()) => {
                            persist_passive_surface(
                                pool,
                                actual_run_id,
                                PassiveSurfaceInput {
                                    surface_kind: "script",
                                    method: "GET",
                                    raw_url: &url,
                                    fields: &[],
                                    source_kind: "html_script",
                                    safe_to_request: true,
                                },
                            )?;
                            queue.push_back(Candidate {
                                url,
                                source_kind: "crawl",
                                content_kind: CandidateContentKind::Script,
                            });
                        }
                        Err(reason) => insert_gap(
                            pool,
                            actual_run_id,
                            "policy",
                            "script_candidate_rejected",
                            &reason,
                        )?,
                    }
                }
            }
        } else if candidate.content_kind == CandidateContentKind::Script
            && response_header(&replay, "content-type").is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("javascript") || value.contains("ecmascript")
            })
        {
            if let Some(script) = replay.response_body_text.as_deref() {
                for route in extract_static_script_routes(script) {
                    if let Some(url) = resolve_href(&replay.url, &route) {
                        match executor.authorize_candidate("GET", &url, Vec::new()) {
                            Ok(()) => queue.push_back(Candidate {
                                url,
                                source_kind: "crawl",
                                content_kind: CandidateContentKind::Page,
                            }),
                            Err(reason) => insert_gap(
                                pool,
                                actual_run_id,
                                "policy",
                                "static_route_candidate_rejected",
                                &reason,
                            )?,
                        }
                    }
                }
            }
        }
    }

    // Anonymous is the discovery baseline. At most one additional request per
    // configured identity is used for start-surface visibility; requests remain
    // serial and pass the same exact-origin policy.
    for identity in [IdentitySelection::A, IdentitySelection::B] {
        if !executor.identity_available(identity)
            || executor.request_count() >= executor.discovery_limit()
            || executor.is_cancelled()
        {
            continue;
        }
        let start_url = executor.contract().normalized_start_url.clone();
        if executor
            .authorize_candidate("GET", &start_url, Vec::new())
            .is_err()
        {
            continue;
        }
        let (replay, stop) = executor
            .execute(
                RequestPhase::Discovery,
                "GET",
                &start_url,
                Vec::new(),
                identity,
                "identity_visibility",
            )
            .await?;
        let endpoint = persist_replay_endpoint(
            pool,
            actual_run_id,
            &replay,
            "start_url",
            true,
            executor.contract(),
        )?;
        persist_response_surface(
            pool,
            actual_run_id,
            &endpoint.endpoint,
            &replay,
            CandidateContentKind::Page,
            "identity_visibility",
            identity,
        )?;
        run_local_baseline(
            pool,
            executor.contract().project_id,
            &endpoint.endpoint,
            &replay,
            identity,
        )?;
        discovered
            .entry(endpoint.endpoint.endpoint_id.clone())
            .and_modify(|existing| existing.endpoint.has_authentication = true)
            .or_insert(endpoint);
        if let Some(condition) = stop {
            stop_condition = Some(condition);
            break;
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
    merge_mission_resources(pool, actual_run_id, executor, &mut discovered)?;
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
    let mut query_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    query_names.sort();
    query_names.dedup();
    let actual_path = url.path().to_string();
    let path = super::mission::normalize_path_shape(&actual_path);
    let endpoint_key = sha256(
        format!(
            "{}\n{}\n{}",
            method.to_ascii_uppercase(),
            path,
            query_names.join("\n")
        )
        .as_bytes(),
    );
    let opaque_id = format!("ep_{}", &endpoint_key[..24]);
    let resource_owner_profile_id = contract
        .resource_ownership
        .iter()
        .find(|claim| path_matches_claim(&actual_path, &claim.path))
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
        path,
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
        persist_passive_surface(
            pool,
            run_id,
            PassiveSurfaceInput {
                surface_kind: "traffic",
                method: &method,
                raw_url: &raw_url,
                fields: &[],
                source_kind: "traffic",
                safe_to_request: true,
            },
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
            content_kind: CandidateContentKind::Page,
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

#[derive(Default)]
struct HtmlInventoryBuilder {
    inventory: HtmlInventory,
    current_form: Option<usize>,
    in_title: bool,
}

fn merge_mission_resources(
    pool: &Pool,
    run_id: i64,
    executor: &AssessmentExecutor,
    discovered: &mut HashMap<String, DiscoveredEndpoint>,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    let mission_id: Option<i64> = conn
        .query_row(
            "SELECT mission_id FROM assessment_mission_runs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(mission_id) = mission_id else {
        return Ok(());
    };
    let mut statement = conn
        .prepare(
            "SELECT resource_type, source_id, summary_json
             FROM assessment_mission_resources WHERE mission_id=?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let resources = statement
        .query_map([mission_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    drop(conn);
    for (resource_type, source_id, summary_json) in resources {
        match resource_type.as_str() {
            "traffic" => {
                if let Some(traffic_id) = source_id {
                    merge_selected_traffic(pool, run_id, executor, traffic_id, discovered)?;
                }
            }
            "finding" => {
                let Some(finding_id) = source_id else {
                    continue;
                };
                let conn = pool.get().map_err(|error| error.to_string())?;
                let mut statement = conn
                    .prepare(
                        "SELECT traffic_id FROM finding_traffic WHERE finding_id=?1
                         UNION SELECT traffic_id FROM findings
                         WHERE id=?1 AND traffic_id IS NOT NULL LIMIT 100",
                    )
                    .map_err(|error| error.to_string())?;
                let traffic_ids = statement
                    .query_map([finding_id], |row| row.get::<_, i64>(0))
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                drop(statement);
                drop(conn);
                for traffic_id in traffic_ids {
                    merge_selected_traffic(pool, run_id, executor, traffic_id, discovered)?;
                }
            }
            "assessment_run" => {
                let Some(source_run_id) = source_id else {
                    continue;
                };
                copy_prior_surfaces(pool, run_id, source_run_id, executor)?;
            }
            "openapi" => {
                let summary: Value = serde_json::from_str(&summary_json).unwrap_or(Value::Null);
                import_openapi_surfaces(pool, run_id, executor, &summary)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn merge_selected_traffic(
    pool: &Pool,
    run_id: i64,
    executor: &AssessmentExecutor,
    traffic_id: i64,
    discovered: &mut HashMap<String, DiscoveredEndpoint>,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    let row: Option<(String, String, Option<u16>, String, String, bool)> = conn
        .query_row(
            "SELECT method, url, status, COALESCE(content_type,''), rule_tags, resp_truncated
             FROM traffic WHERE id=?1 AND project_id=?2",
            rusqlite::params![traffic_id, executor.contract().project_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    drop(conn);
    let Some((method, raw_url, status, content_type, tags, truncated)) = row else {
        return Ok(());
    };
    let url = match Url::parse(&raw_url) {
        Ok(url)
            if exact_origin(&url).ok().as_deref()
                == Some(executor.contract().exact_origin.as_str()) =>
        {
            url
        }
        _ => return Ok(()),
    };
    let passive_tags = serde_json::from_str(&tags).unwrap_or_default();
    if matches!(method.as_str(), "GET" | "HEAD")
        && executor
            .authorize_candidate(&method, &raw_url, Vec::new())
            .is_ok()
    {
        let endpoint = persist_endpoint(
            pool,
            run_id,
            &method,
            url.clone(),
            "traffic",
            Some(traffic_id),
            status,
            content_type.clone(),
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
    persist_passive_surface(
        pool,
        run_id,
        PassiveSurfaceInput {
            surface_kind: "traffic",
            method: &method,
            raw_url: &raw_url,
            fields: &[],
            source_kind: "mission_resource",
            safe_to_request: matches!(method.as_str(), "GET" | "HEAD"),
        },
    )
}

fn copy_prior_surfaces(
    pool: &Pool,
    run_id: i64,
    source_run_id: i64,
    executor: &AssessmentExecutor,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    let mut statement = conn
        .prepare(
            "SELECT surface_kind, method, path_shape, query_parameter_names,
                    form_fields_json, content_types_json, safe_to_request
             FROM assessment_surfaces s
             JOIN assessment_runs r ON r.id=s.run_id
             WHERE s.run_id=?1 AND r.project_id=?2 LIMIT 500",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(
            rusqlite::params![source_run_id, executor.contract().project_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    drop(conn);
    for (kind, method, path, query_json, fields_json, content_json, safe) in rows {
        let mut url = Url::parse(&executor.contract().normalized_start_url)
            .map_err(|error| error.to_string())?;
        url.set_path(&path);
        url.set_query(None);
        let query = serde_json::from_str::<Vec<String>>(&query_json).unwrap_or_default();
        let fields = serde_json::from_str::<Vec<Value>>(&fields_json).unwrap_or_default();
        let content = serde_json::from_str::<Vec<String>>(&content_json).unwrap_or_default();
        upsert_surface(
            pool,
            run_id,
            &kind,
            &method,
            &url,
            &query,
            &fields,
            &content,
            None,
            "assessment_run_resource",
            safe,
            None,
        )?;
    }
    Ok(())
}

fn import_openapi_surfaces(
    pool: &Pool,
    run_id: i64,
    executor: &AssessmentExecutor,
    summary: &Value,
) -> Result<(), String> {
    let Some(surfaces) = summary.get("surfaces").and_then(Value::as_array) else {
        return Ok(());
    };
    for surface in surfaces.iter().take(500) {
        let Some(path) = surface.get("pathShape").and_then(Value::as_str) else {
            continue;
        };
        let parameters = surface
            .get("parameterNames")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut url = Url::parse(&executor.contract().normalized_start_url)
            .map_err(|error| error.to_string())?;
        url.set_path(path);
        url.set_query(None);
        for method in surface
            .get("methods")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let method = method.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE" | "TRACE"
            ) {
                continue;
            }
            upsert_surface(
                pool,
                run_id,
                "api",
                &method,
                &url,
                &parameters,
                &[],
                &[],
                None,
                "openapi_resource",
                matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
                None,
            )?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct HtmlInventorySink(RefCell<HtmlInventoryBuilder>);

impl HtmlInventorySink {
    fn snapshot(&self) -> HtmlInventory {
        self.0.borrow().inventory.clone()
    }
}

impl TokenSink for HtmlInventorySink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        let mut state = self.0.borrow_mut();
        match token {
            TagToken(tag) if tag.kind == StartTag => {
                let name = tag.name.as_ref();
                match name {
                    "title" => state.in_title = true,
                    "a" if state.inventory.anchors.len() < 1000 => {
                        if let Some(href) = tag_attribute(&tag, "href") {
                            state.inventory.anchors.push(href);
                        }
                    }
                    "form" if state.inventory.forms.len() < 500 => {
                        let method = tag_attribute(&tag, "method")
                            .unwrap_or_else(|| "GET".into())
                            .to_ascii_uppercase();
                        let method = if matches!(
                            method.as_str(),
                            "GET"
                                | "HEAD"
                                | "OPTIONS"
                                | "POST"
                                | "PUT"
                                | "PATCH"
                                | "DELETE"
                                | "TRACE"
                        ) {
                            method
                        } else {
                            "GET".into()
                        };
                        let index = state.inventory.forms.len();
                        state.inventory.forms.push(HtmlFormInventory {
                            action: tag_attribute(&tag, "action").unwrap_or_default(),
                            method,
                            fields: Vec::new(),
                        });
                        state.current_form = Some(index);
                    }
                    "input" | "textarea" | "select" | "button" => {
                        if let Some(index) = state.current_form {
                            let field_count = state.inventory.forms[index].fields.len();
                            if field_count < 200 {
                                if let Some(field_name) = tag_attribute(&tag, "name") {
                                    if !field_name.trim().is_empty() && field_name.len() <= 240 {
                                        let input_type = if tag.name.as_ref() == "input" {
                                            tag_attribute(&tag, "type")
                                                .unwrap_or_else(|| "text".into())
                                        } else {
                                            name.to_string()
                                        };
                                        state.inventory.forms[index].fields.push(HtmlFormField {
                                            name: field_name,
                                            input_type: input_type.chars().take(80).collect(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    "script" if state.inventory.scripts.len() < 200 => {
                        if let Some(source) = tag_attribute(&tag, "src") {
                            state.inventory.scripts.push(source);
                        }
                    }
                    "link" if state.inventory.resources.len() < 500 => {
                        if let Some(href) = tag_attribute(&tag, "href") {
                            state.inventory.resources.push(href);
                        }
                    }
                    "img" | "source" | "video" | "audio"
                        if state.inventory.resources.len() < 500 =>
                    {
                        if let Some(source) = tag_attribute(&tag, "src") {
                            state.inventory.resources.push(source);
                        }
                    }
                    _ => {}
                }
            }
            TagToken(tag) if tag.kind == EndTag => match tag.name.as_ref() {
                "form" => state.current_form = None,
                "title" => state.in_title = false,
                _ => {}
            },
            Token::CharacterTokens(text) if state.in_title && state.inventory.title.len() < 256 => {
                let remaining = 256 - state.inventory.title.len();
                state
                    .inventory
                    .title
                    .push_str(&text.chars().take(remaining).collect::<String>());
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

fn tag_attribute(tag: &html5ever::tokenizer::Tag, expected: &str) -> Option<String> {
    tag.attrs
        .iter()
        .find(|attribute| attribute.name.local.as_ref().eq_ignore_ascii_case(expected))
        .map(|attribute| attribute.value.to_string())
}

fn parse_html_inventory(html: &str) -> HtmlInventory {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));
    let tokenizer = Tokenizer::new(HtmlInventorySink::default(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    let mut inventory = tokenizer.sink.snapshot();
    inventory.title = inventory
        .title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    inventory
}

fn extract_static_script_routes(script: &str) -> Vec<String> {
    if script.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }
    static ROUTE_LITERAL: OnceLock<Regex> = OnceLock::new();
    let regex = ROUTE_LITERAL.get_or_init(|| {
        Regex::new(r#"["'`](/(?:[A-Za-z0-9._~!$&()*+,;=:@%{}-]+/?){1,16}(?:\?[A-Za-z0-9._~!$&()*+,;=:@%{}?/-]*)?)["'`]"#)
            .expect("valid static route literal regex")
    });
    let mut routes = regex
        .captures_iter(script)
        .take(500)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .filter(|route| route.len() <= 2048 && !route.starts_with("//"))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    routes.truncate(200);
    routes
}

fn register_forms_and_resources(
    pool: &Pool,
    executor: &AssessmentExecutor,
    run_id: i64,
    base_url: &str,
    forms: Vec<HtmlFormInventory>,
    resources: Vec<String>,
) -> Result<(), String> {
    for form in forms {
        let target = if form.action.trim().is_empty() {
            normalize_candidate_url(base_url).ok()
        } else {
            resolve_href(base_url, &form.action)
        };
        let Some(target) = target else { continue };
        let in_origin = Url::parse(&target)
            .ok()
            .and_then(|url| exact_origin(&url).ok())
            .as_deref()
            == Some(executor.contract().exact_origin.as_str());
        if !in_origin {
            insert_gap(
                pool,
                run_id,
                "origin",
                "form_action_cross_origin",
                "表单 action 不属于精确 origin；仅登记覆盖缺口且没有提交表单",
            )?;
            continue;
        }
        let fields = form
            .fields
            .iter()
            .map(|field| json!({"name": field.name, "type": field.input_type}))
            .collect::<Vec<_>>();
        persist_passive_surface(
            pool,
            run_id,
            PassiveSurfaceInput {
                surface_kind: "form",
                method: &form.method,
                raw_url: &target,
                fields: &fields,
                source_kind: "html_form",
                safe_to_request: false,
            },
        )?;
    }
    for resource in resources {
        let Some(target) = resolve_href(base_url, &resource) else {
            continue;
        };
        let in_origin = Url::parse(&target)
            .ok()
            .and_then(|url| exact_origin(&url).ok())
            .as_deref()
            == Some(executor.contract().exact_origin.as_str());
        if in_origin {
            persist_passive_surface(
                pool,
                run_id,
                PassiveSurfaceInput {
                    surface_kind: "resource",
                    method: "GET",
                    raw_url: &target,
                    fields: &[],
                    source_kind: "html_resource",
                    safe_to_request: false,
                },
            )?;
        }
    }
    Ok(())
}

fn persist_response_surface(
    pool: &Pool,
    run_id: i64,
    endpoint: &AssessmentEndpoint,
    replay: &ReplayRun,
    content_kind: CandidateContentKind,
    source_kind: &str,
    identity: IdentitySelection,
) -> Result<(), String> {
    let url = Url::parse(&replay.url).map_err(|_| "响应 URL 无法形成 surface".to_string())?;
    let content_type = response_header(replay, "content-type").unwrap_or_default();
    let structure_hash = response_structure_hash(replay);
    let identity_key = match identity {
        IdentitySelection::Anonymous => "anonymous",
        IdentitySelection::A => "a",
        IdentitySelection::B => "b",
    };
    let surface_kind = if source_kind == "redirect" {
        "redirect"
    } else if content_kind == CandidateContentKind::Script {
        "script"
    } else {
        "page"
    };
    upsert_surface(
        pool,
        run_id,
        surface_kind,
        &endpoint.method,
        &url,
        &endpoint.query_parameter_names,
        &[],
        if content_type.is_empty() {
            &[]
        } else {
            std::slice::from_ref(&content_type)
        },
        Some((identity_key, replay.status, structure_hash.as_str())),
        source_kind,
        matches!(endpoint.method.as_str(), "GET" | "HEAD" | "OPTIONS"),
        Some(&structure_hash),
    )
}

struct PassiveSurfaceInput<'a> {
    surface_kind: &'a str,
    method: &'a str,
    raw_url: &'a str,
    fields: &'a [Value],
    source_kind: &'a str,
    safe_to_request: bool,
}

fn persist_passive_surface(
    pool: &Pool,
    run_id: i64,
    input: PassiveSurfaceInput<'_>,
) -> Result<(), String> {
    let url = Url::parse(input.raw_url).map_err(|_| "被动 surface URL 无效".to_string())?;
    let mut query_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    query_names.sort();
    query_names.dedup();
    upsert_surface(
        pool,
        run_id,
        input.surface_kind,
        input.method,
        &url,
        &query_names,
        input.fields,
        &[],
        None,
        input.source_kind,
        input.safe_to_request,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn upsert_surface(
    pool: &Pool,
    run_id: i64,
    surface_kind: &str,
    method: &str,
    url: &Url,
    query_names: &[String],
    fields: &[Value],
    content_types: &[String],
    identity: Option<(&str, Option<u16>, &str)>,
    source_kind: &str,
    safe_to_request: bool,
    structure_hash: Option<&str>,
) -> Result<(), String> {
    let path_shape = super::mission::normalize_path_shape(url.path());
    let mut field_keys = fields
        .iter()
        .map(|field| serde_json::to_string(field).unwrap_or_default())
        .filter(|field| !field.is_empty())
        .collect::<BTreeSet<_>>();
    let field_shape = field_keys.iter().cloned().collect::<Vec<_>>().join("\n");
    let mut normalized_query = query_names.to_vec();
    normalized_query.sort();
    normalized_query.dedup();
    let surface_id = format!(
        "surface_{}",
        &sha256(
            format!(
                "{}\n{}\n{}\n{}\n{}",
                surface_kind,
                method.to_ascii_uppercase(),
                path_shape,
                normalized_query.join("\n"),
                field_shape
            )
            .as_bytes()
        )[..24]
    );
    let conn = pool.get().map_err(|error| error.to_string())?;
    let existing: Option<(String, String, String, String, Option<String>, i64)> = conn
        .query_row(
            "SELECT form_fields_json, content_types_json,
                    identity_visibility_json, source_kinds_json,
                    response_structure_hash, concrete_count
             FROM assessment_surfaces WHERE run_id=?1 AND surface_id=?2",
            rusqlite::params![run_id, surface_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let mut merged_content = content_types.iter().cloned().collect::<BTreeSet<_>>();
    let mut merged_sources = BTreeSet::from([source_kind.to_string()]);
    let mut visibility = serde_json::Map::new();
    let mut concrete_count = 1_i64;
    let mut structure_hashes = BTreeSet::new();
    if let Some((old_fields, old_content, old_visibility, old_sources, old_hash, old_count)) =
        existing
    {
        field_keys.extend(
            serde_json::from_str::<Vec<Value>>(&old_fields)
                .unwrap_or_default()
                .iter()
                .filter_map(|value| serde_json::to_string(value).ok()),
        );
        merged_content
            .extend(serde_json::from_str::<Vec<String>>(&old_content).unwrap_or_default());
        merged_sources
            .extend(serde_json::from_str::<Vec<String>>(&old_sources).unwrap_or_default());
        visibility = serde_json::from_str::<Value>(&old_visibility)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        if let Some(hash) = old_hash {
            structure_hashes.insert(hash);
        }
        concrete_count = old_count.saturating_add(1);
    }
    if let Some(hash) = structure_hash {
        structure_hashes.insert(hash.to_string());
    }
    if let Some((identity_key, status, hash)) = identity {
        visibility.insert(
            identity_key.to_string(),
            json!({"status": status, "responseStructureHash": hash}),
        );
    }
    let merged_structure_hash = match structure_hashes.len() {
        0 => None,
        1 => structure_hashes.iter().next().cloned(),
        _ => Some(sha256(
            structure_hashes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
                .as_bytes(),
        )),
    };
    let merged_fields = field_keys
        .into_iter()
        .filter_map(|raw| serde_json::from_str::<Value>(&raw).ok())
        .collect::<Vec<_>>();
    conn.execute(
        "INSERT INTO assessment_surfaces(
             run_id, surface_id, surface_kind, method, path_shape,
             query_parameter_names, form_fields_json, content_types_json,
             identity_visibility_json, response_structure_hash,
             source_kinds_json, safe_to_request, concrete_count
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(run_id, surface_id) DO UPDATE SET
             form_fields_json=excluded.form_fields_json,
             content_types_json=excluded.content_types_json,
             identity_visibility_json=excluded.identity_visibility_json,
             response_structure_hash=excluded.response_structure_hash,
             source_kinds_json=excluded.source_kinds_json,
             safe_to_request=MAX(assessment_surfaces.safe_to_request, excluded.safe_to_request),
             concrete_count=excluded.concrete_count,
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')",
        rusqlite::params![
            run_id,
            surface_id,
            surface_kind,
            method.to_ascii_uppercase(),
            path_shape,
            serde_json::to_string(&normalized_query).map_err(|error| error.to_string())?,
            serde_json::to_string(&merged_fields).map_err(|error| error.to_string())?,
            serde_json::to_string(&merged_content.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string())?,
            serde_json::to_string(&visibility).map_err(|error| error.to_string())?,
            merged_structure_hash,
            serde_json::to_string(&merged_sources.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string())?,
            safe_to_request,
            concrete_count,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn response_structure_hash(replay: &ReplayRun) -> String {
    let content_type = response_header(replay, "content-type").unwrap_or_default();
    let lower = content_type.to_ascii_lowercase();
    let body = replay.response_body_text.as_deref().unwrap_or_default();
    let structure = if lower.contains("json") {
        let mut paths = BTreeSet::new();
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            collect_json_key_paths(&value, "$", 0, &mut paths);
        }
        json!({"kind": "json", "keyPaths": paths})
    } else if lower.contains("html") {
        let inventory = parse_html_inventory(body);
        json!({
            "kind": "html",
            "title": inventory.title,
            "anchorCount": inventory.anchors.len(),
            "forms": inventory.forms.iter().map(|form| json!({
                "method": form.method,
                "fieldNames": form.fields.iter().map(|field| &field.name).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "scriptCount": inventory.scripts.len(),
        })
    } else {
        json!({
            "kind": "other",
            "sizeBucket": replay.resp_captured_size.max(0) / 1024,
        })
    };
    sha256(
        serde_json::to_string(&json!({
            "status": replay.status,
            "contentType": content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase(),
            "complete": replay.outcome == "completed" && !replay.resp_truncated,
            "structure": structure,
        }))
        .unwrap_or_default()
        .as_bytes(),
    )
}

fn collect_json_key_paths(value: &Value, path: &str, depth: usize, out: &mut BTreeSet<String>) {
    if depth >= 6 || out.len() >= 300 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter().take(100) {
                if out.len() >= 300 {
                    break;
                }
                let key = key.chars().take(120).collect::<String>();
                let next = format!("{path}.{key}");
                out.insert(next.clone());
                collect_json_key_paths(child, &next, depth + 1, out);
            }
        }
        Value::Array(values) => {
            if let Some(first) = values.first() {
                let next = format!("{path}[]");
                out.insert(next.clone());
                collect_json_key_paths(first, &next, depth + 1, out);
            }
        }
        _ => {}
    }
}

fn run_local_baseline(
    pool: &Pool,
    project_id: i64,
    endpoint: &AssessmentEndpoint,
    replay: &ReplayRun,
    identity: IdentitySelection,
) -> Result<(), String> {
    let tool = catalog_tool_for_baseline()?;
    let identity_mode = match identity {
        IdentitySelection::Anonymous => "anonymous",
        IdentitySelection::A => "a",
        IdentitySelection::B => "b",
    };
    let mut conn = pool.get().map_err(|error| error.to_string())?;
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM assessment_checks
             WHERE run_id=?1 AND round_id IS NULL AND endpoint_id=?2
               AND template_id=?3 AND identity_mode=?4
             ORDER BY id LIMIT 1",
            rusqlite::params![endpoint.run_id, endpoint.id, tool.id, identity_mode],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if existing.is_some() {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO assessment_checks(
             run_id, round_id, endpoint_id, requested_endpoint_id,
             template_id, template_version, identity_mode, rationale,
             policy_result, policy_reason, status, request_cost
         ) VALUES(?1,NULL,?2,?3,?4,?5,?6,?7,'allowed','local_observe','completed',0)",
        rusqlite::params![
            endpoint.run_id,
            endpoint.id,
            endpoint.endpoint_id,
            tool.id,
            tool.version,
            identity_mode,
            "每个完整发现响应先执行版本固定的本地安全基线；没有新增目标请求。",
        ],
    )
    .map_err(|error| error.to_string())?;
    let check_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO assessment_check_replays(check_id,replay_run_id,role)
         VALUES(?1,?2,'baseline')",
        rusqlite::params![check_id, replay.id],
    )
    .map_err(|error| error.to_string())?;
    let responses = HashMap::from([("baseline".to_string(), ResponseObservation::from(replay))]);
    let outcome = verifier::verify(tool.id, endpoint, &responses, None, false);
    super::outcome::commit_verification_outcome(
        &mut conn,
        super::outcome::VerificationCommitInput {
            project_id,
            run_id: endpoint.run_id,
            check_id,
            template_id: tool.id,
            template_version: tool.version,
            verifier_id: tool.verifier_id,
            verifier_version: tool.verifier_version,
            endpoint_method: &endpoint.method,
            endpoint_url: &endpoint.url,
            parameter_name: None,
            outcome: &outcome,
        },
    )?;
    Ok(())
}

fn catalog_tool_for_baseline() -> Result<&'static super::catalog::ToolSpec, String> {
    super::catalog::tool("security_headers_cookie").ok_or_else(|| "本地基线工具未注册".to_string())
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
            <script src="/app.js">fetch('/not-allowed')</script>
            <img src="/asset.png">
            <form action="/submit" method="post">
              <input name="email" type="email"><input name="token" type="hidden">
            </form>
            <a href="/one?q=a&amp;b=c#section">one</a>
            <A HREF='/two'>two</A>
            <a href="javascript:alert(1)">bad</a>
        "#;
        let inventory = parse_html_inventory(html);
        let hrefs = inventory.anchors;
        assert_eq!(hrefs.len(), 3);
        assert_eq!(
            resolve_href("https://example.test/start", &hrefs[0]).unwrap(),
            "https://example.test/one?q=a&b=c"
        );
        assert!(resolve_href("https://example.test/", &hrefs[2]).is_none());
        assert_eq!(inventory.scripts, vec!["/app.js"]);
        assert_eq!(inventory.resources, vec!["/asset.png"]);
        assert_eq!(inventory.forms.len(), 1);
        assert_eq!(inventory.forms[0].method, "POST");
        assert_eq!(inventory.forms[0].fields.len(), 2);
        assert_eq!(inventory.forms[0].fields[0].name, "email");
    }

    #[test]
    fn extracts_only_static_script_literals_without_executing_javascript() {
        let routes = extract_static_script_routes(
            r#"const routes=['/users/{id}', "/api/items?view=full"];
               fetch(dynamicValue); eval(dynamicCode);
               const external='//outside.test/path';"#,
        );
        assert_eq!(routes, vec!["/api/items?view=full", "/users/{id}"]);
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
                            "<form action='/submit' method='post'><button>submit</button></form>",
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
        let counts: (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM traffic WHERE project_id=?1),
                     (SELECT COUNT(*) FROM assessment_coverage_gaps WHERE run_id=?2),
                     (SELECT COUNT(*) FROM assessment_surfaces WHERE run_id=?2),
                     (SELECT COUNT(*) FROM assessment_surfaces
                      WHERE run_id=?2 AND surface_kind='form' AND method='POST'),
                     (SELECT COUNT(*) FROM assessment_verifications v
                      JOIN assessment_checks c ON c.id=v.check_id
                      WHERE c.run_id=?2 AND c.round_id IS NULL)",
                rusqlite::params![project_id, run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(counts.0, 0, "proxy Traffic is not a discovery prerequisite");
        assert!(
            counts.1 >= 2,
            "dangerous and cross-origin links become gaps"
        );
        assert!(
            counts.2 >= 4,
            "pages, form and resource become stable surfaces"
        );
        assert_eq!(counts.3, 1, "POST form is registered exactly once");
        assert_eq!(
            counts.4, 2,
            "every fetched response receives a local baseline"
        );
    }
}
