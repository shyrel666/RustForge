use super::model::{AssessmentEndpoint, AssessmentVerdict};
use crate::replay::model::{ReplayHeader, ReplayRun};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseObservation {
    pub replay_run_id: i64,
    pub url: String,
    pub status: Option<u16>,
    pub headers: Vec<ReplayHeader>,
    pub body_hash: Option<String>,
    pub body_size: i64,
    pub complete: bool,
}

impl From<&ReplayRun> for ResponseObservation {
    fn from(run: &ReplayRun) -> Self {
        Self {
            replay_run_id: run.id,
            url: run.url.clone(),
            status: run.status,
            headers: run.response_headers.clone(),
            body_hash: run.resp_body_hash.clone(),
            body_size: run.resp_captured_size,
            complete: run.outcome == "completed" && !run.resp_truncated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationOutcome {
    pub verdict: AssessmentVerdict,
    pub observations: Value,
    pub title: String,
    pub vuln_type: String,
    pub severity: String,
    pub confidence: u8,
    pub reasoning: String,
    pub evidence_replay_run_id: Option<i64>,
}

pub fn verify(
    template_id: &str,
    endpoint: &AssessmentEndpoint,
    responses: &HashMap<String, ResponseObservation>,
    reflection_marker: Option<&str>,
    reflection_observed: bool,
) -> VerificationOutcome {
    match template_id {
        "security_headers_cookie" => verify_security_headers(endpoint, responses),
        "credentialed_cors" => verify_cors(responses),
        "jwt_integrity" => verify_jwt(responses),
        "open_redirect" => verify_open_redirect(responses),
        "lazy_reflection" => verify_reflection(responses, reflection_marker, reflection_observed),
        "readonly_idor" => verify_idor(endpoint, responses),
        _ => inconclusive(
            "未知安全模板",
            "unknown_template",
            "验证器注册表中不存在该模板",
            json!({"reason": "unknown_template"}),
        ),
    }
}

fn verify_security_headers(
    _endpoint: &AssessmentEndpoint,
    responses: &HashMap<String, ResponseObservation>,
) -> VerificationOutcome {
    let Some(baseline) = responses.get("baseline") else {
        return inconclusive(
            "安全 Header/Cookie 检查不完整",
            "security_misconfiguration",
            "没有可复用的发现响应",
            json!({"reason": "missing_discovery_baseline"}),
        );
    };
    if !baseline.complete {
        return incomplete("安全 Header/Cookie 检查", baseline);
    }
    let https = Url::parse(&baseline.url)
        .ok()
        .is_some_and(|url| url.scheme() == "https");
    let host_is_dns = Url::parse(&baseline.url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .is_some_and(|host| host != "localhost" && host.parse::<std::net::IpAddr>().is_err());
    let mut gaps = Vec::<Value>::new();
    if https && host_is_dns && header_values(baseline, "strict-transport-security").is_empty() {
        gaps.push(json!({"kind": "missing_hsts", "applicable": true}));
    }
    for cookie in header_values(baseline, "set-cookie") {
        let cookie_name = cookie
            .split('=')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let session_like = ["session", "sess", "auth", "token", "jwt", "sid"]
            .iter()
            .any(|needle| cookie_name.contains(needle));
        if !session_like {
            continue;
        }
        let attributes = cookie.to_ascii_lowercase();
        let attribute_names = split_cookie_attributes(&attributes)
            .into_iter()
            .map(str::trim)
            .collect::<Vec<_>>();
        if !attribute_names.contains(&"httponly") {
            gaps.push(
                json!({"kind": "session_cookie_missing_httponly", "cookieName": cookie_name}),
            );
        }
        if https && !attribute_names.contains(&"secure") {
            gaps.push(json!({"kind": "session_cookie_missing_secure", "cookieName": cookie_name}));
        }
    }
    if gaps.is_empty() {
        not_observed(
            "未观察到事实性安全 Header/Cookie 缺口",
            "security_misconfiguration",
            baseline,
            json!({"facts": []}),
        )
    } else {
        VerificationOutcome {
            verdict: AssessmentVerdict::Confirmed,
            observations: json!({"facts": gaps, "responseComplete": true}),
            title: "安全 Header/Cookie 配置缺口".into(),
            vuln_type: "security_misconfiguration".into(),
            severity: "low".into(),
            confidence: 100,
            reasoning: "版本化验证器仅确认完整响应中可直接观察的 Header/Cookie 配置事实。".into(),
            evidence_replay_run_id: Some(baseline.replay_run_id),
        }
    }
}

fn verify_cors(responses: &HashMap<String, ResponseObservation>) -> VerificationOutcome {
    let (Some(baseline), Some(anonymous), Some(probe)) = (
        responses.get("baseline"),
        responses.get("anonymous"),
        responses.get("probe"),
    ) else {
        return missing_pair("凭据型 CORS", "credentialed_cors");
    };
    if !baseline.complete || !anonymous.complete || !probe.complete {
        return incomplete(
            "凭据型 CORS",
            if !probe.complete {
                probe
            } else if !anonymous.complete {
                anonymous
            } else {
                baseline
            },
        );
    }
    let protected_success = baseline
        .status
        .is_some_and(|status| (200..300).contains(&status));
    let probe_success = probe
        .status
        .is_some_and(|status| (200..300).contains(&status));
    // 匿名与带身份响应等价（同为 2xx 且内容一致）时，端点并不要求认证，
    // 反射任意 Origin 不构成凭据型 CORS 漏洞。
    let anonymous_success = anonymous
        .status
        .is_some_and(|status| (200..300).contains(&status));
    let endpoint_not_protected = protected_success
        && anonymous_success
        && anonymous.body_hash == baseline.body_hash
        && anonymous.body_size == baseline.body_size
        && content_type(anonymous) == content_type(baseline);
    let reflected = header_values(probe, "access-control-allow-origin")
        .iter()
        .any(|value| value.trim() == "https://rf-probe.invalid");
    let credentials = header_values(probe, "access-control-allow-credentials")
        .iter()
        .any(|value| value.trim().eq_ignore_ascii_case("true"));
    if endpoint_not_protected {
        return not_observed(
            "端点无需认证，未确认凭据型 CORS",
            "credentialed_cors",
            anonymous,
            json!({
                "endpointNotProtected": true,
                "anonymousStatus": anonymous.status,
                "probeSuccess": probe_success,
                "reflectedOrigin": reflected,
                "allowCredentials": credentials,
            }),
        );
    }
    if protected_success && probe_success && reflected && credentials {
        VerificationOutcome {
            verdict: AssessmentVerdict::Confirmed,
            observations: json!({
                "baselineStatus": baseline.status,
                "anonymousStatus": anonymous.status,
                "probeStatus": probe.status,
                "reflectedOrigin": true,
                "allowCredentials": true,
            }),
            title: "受保护响应允许任意凭据型跨域来源".into(),
            vuln_type: "credentialed_cors".into(),
            severity: "high".into(),
            confidence: 100,
            reasoning: "完整的已鉴权响应反射固定 .invalid Origin，且明确允许 credentials；匿名请求无法获得等价响应。".into(),
            evidence_replay_run_id: Some(probe.replay_run_id),
        }
    } else {
        not_observed(
            "未观察到凭据型 CORS 反射",
            "credentialed_cors",
            probe,
            json!({
                "probeSuccess": probe_success,
                "reflectedOrigin": reflected,
                "allowCredentials": credentials
            }),
        )
    }
}

fn verify_jwt(responses: &HashMap<String, ResponseObservation>) -> VerificationOutcome {
    let Some(baseline) = responses.get("baseline") else {
        return missing_pair("JWT 完整性", "jwt_integrity");
    };
    let Some(anonymous) = responses.get("anonymous") else {
        return missing_pair("JWT 完整性", "jwt_integrity");
    };
    let (Some(signature_probe), Some(alg_none_probe)) = (
        responses.get("signature_probe"),
        responses.get("alg_none_probe"),
    ) else {
        return missing_pair("JWT 完整性", "jwt_integrity");
    };
    let probes = [signature_probe, alg_none_probe];
    if !baseline.complete || !anonymous.complete || probes.iter().any(|probe| !probe.complete) {
        return incomplete("JWT 完整性", baseline);
    }
    let anonymous_rejected = matches!(anonymous.status, Some(401 | 403));
    let baseline_success = baseline
        .status
        .is_some_and(|status| (200..300).contains(&status))
        && baseline.body_size > 0
        && baseline.body_hash.is_some();
    let accepted_probe = probes.into_iter().find(|probe| {
        baseline_success
            && probe.status == baseline.status
            && probe.body_hash == baseline.body_hash
            && probe.body_size == baseline.body_size
            && content_type(probe) == content_type(baseline)
    });
    if anonymous_rejected {
        if let Some(probe) = accepted_probe {
            return VerificationOutcome {
                verdict: AssessmentVerdict::Confirmed,
                observations: json!({
                    "anonymousRejected": true,
                    "baselineStatus": baseline.status,
                    "invalidProbeEquivalent": true,
                    "equivalentBodyHash": baseline.body_hash,
                }),
                title: "JWT 签名完整性未被强制验证".into(),
                vuln_type: "jwt_integrity".into(),
                severity: "critical".into(),
                confidence: 100,
                reasoning:
                    "匿名请求被拒绝，但后端生成的无效 JWT 获得与有效身份完全等价的完整非空响应。"
                        .into(),
                evidence_replay_run_id: Some(probe.replay_run_id),
            };
        }
    }
    not_observed(
        "未观察到 JWT 完整性绕过",
        "jwt_integrity",
        baseline,
        json!({"anonymousRejected": anonymous_rejected, "invalidProbeEquivalent": false}),
    )
}

fn verify_open_redirect(responses: &HashMap<String, ResponseObservation>) -> VerificationOutcome {
    let Some(probe) = responses.get("probe") else {
        return missing_pair("Open Redirect", "open_redirect");
    };
    if !probe.complete {
        return incomplete("Open Redirect", probe);
    }
    let external = header_values(probe, "location").iter().any(|location| {
        Url::parse(&probe.url)
            .ok()
            .and_then(|base| base.join(location).ok())
            .is_some_and(|target| {
                target.scheme() == "https" && target.host_str() == Some("rf-probe.invalid")
            })
    });
    if probe
        .status
        .is_some_and(|status| (300..400).contains(&status))
        && external
    {
        VerificationOutcome {
            verdict: AssessmentVerdict::Confirmed,
            observations: json!({"externalLocation": "https://rf-probe.invalid/", "followed": false}),
            title: "可控外部重定向".into(),
            vuln_type: "open_redirect".into(),
            severity: "medium".into(),
            confidence: 100,
            reasoning: "未跟随跳转；Location 明确指向后端固定生成的 .invalid 探针域。".into(),
            evidence_replay_run_id: Some(probe.replay_run_id),
        }
    } else {
        not_observed(
            "未观察到外部重定向",
            "open_redirect",
            probe,
            json!({"externalLocation": external}),
        )
    }
}

fn verify_reflection(
    responses: &HashMap<String, ResponseObservation>,
    marker: Option<&str>,
    reflection_observed: bool,
) -> VerificationOutcome {
    let Some(probe) = responses.get("probe") else {
        return missing_pair("惰性反射", "controllable_reflection");
    };
    if !probe.complete {
        return incomplete("惰性反射", probe);
    }
    if reflection_observed {
        VerificationOutcome {
            verdict: AssessmentVerdict::Suspected,
            observations: json!({"marker": marker, "reflected": true, "xssExecuted": false}),
            title: "疑似可控反射".into(),
            vuln_type: "controllable_reflection".into(),
            severity: "info".into(),
            confidence: 70,
            reasoning:
                "纯字母数字 marker 出现在完整响应中；未执行浏览器脚本，因此不会自动确认 XSS。"
                    .into(),
            evidence_replay_run_id: Some(probe.replay_run_id),
        }
    } else {
        not_observed(
            "未观察到 marker 反射",
            "controllable_reflection",
            probe,
            json!({"marker": marker, "reflected": false}),
        )
    }
}

fn verify_idor(
    endpoint: &AssessmentEndpoint,
    responses: &HashMap<String, ResponseObservation>,
) -> VerificationOutcome {
    let (Some(a), Some(b)) = (responses.get("identity_a"), responses.get("identity_b")) else {
        return missing_pair("双身份只读越权", "readonly_idor");
    };
    if !a.complete || !b.complete {
        return incomplete("双身份只读越权", if !b.complete { b } else { a });
    }
    let equivalent = a.status.is_some_and(|status| (200..300).contains(&status))
        && b.status == a.status
        && a.body_size > 0
        && b.body_size == a.body_size
        && a.body_hash.is_some()
        && b.body_hash == a.body_hash
        && content_type(a) == content_type(b);
    if !equivalent {
        return not_observed(
            "未观察到双身份等价响应",
            "readonly_idor",
            b,
            json!({"responsesEquivalent": false}),
        );
    }
    let ownership_declared = endpoint.resource_owner_profile_id.is_some();
    VerificationOutcome {
        verdict: if ownership_declared {
            AssessmentVerdict::Confirmed
        } else {
            AssessmentVerdict::Suspected
        },
        observations: json!({
            "responsesEquivalent": true,
            "responseNonEmpty": true,
            "resourceOwnershipDeclared": ownership_declared,
        }),
        title: if ownership_declared {
            "身份 B 可读取声明仅属于身份 A 的资源".into()
        } else {
            "疑似双身份只读越权".into()
        },
        vuln_type: "readonly_idor".into(),
        severity: "high".into(),
        confidence: if ownership_declared { 100 } else { 75 },
        reasoning: if ownership_declared {
            "用户声明资源仅属于 A，但 B 获得完全等价、完整、非空的 2xx 响应。".into()
        } else {
            "A/B 响应完全等价，但缺少资源归属声明，不能自动确认。".into()
        },
        evidence_replay_run_id: Some(b.replay_run_id),
    }
}

fn header_values<'a>(response: &'a ResponseObservation, name: &str) -> Vec<&'a str> {
    response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
        .collect()
}

/// 按 RFC 6265 拆分 Set-Cookie 属性段：属性值可能被双引号包裹并含分号，
/// 引号内的分号不算属性分隔符。
fn split_cookie_attributes(cookie: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (index, character) in cookie.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                parts.push(&cookie[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&cookie[start..]);
    parts
}

fn content_type(response: &ResponseObservation) -> Option<String> {
    header_values(response, "content-type")
        .first()
        .map(|value| value.trim().to_ascii_lowercase())
}

fn not_observed(
    title: &str,
    vuln_type: &str,
    response: &ResponseObservation,
    observations: Value,
) -> VerificationOutcome {
    VerificationOutcome {
        verdict: AssessmentVerdict::NotObserved,
        observations,
        title: title.into(),
        vuln_type: vuln_type.into(),
        severity: "info".into(),
        confidence: 100,
        reasoning: "本轮安全检查已执行，但确定性验证条件未满足。".into(),
        evidence_replay_run_id: Some(response.replay_run_id),
    }
}

fn incomplete(name: &str, response: &ResponseObservation) -> VerificationOutcome {
    inconclusive(
        &format!("{name}响应不完整"),
        "incomplete_response",
        "截断、取消或流错误响应不能用于自动确认",
        json!({"responseComplete": false, "replayRunId": response.replay_run_id}),
    )
}

fn missing_pair(name: &str, vuln_type: &str) -> VerificationOutcome {
    inconclusive(
        &format!("{name}检查不完整"),
        vuln_type,
        "缺少验证所需的基线或探针响应",
        json!({"reason": "missing_required_response"}),
    )
}

fn inconclusive(
    title: &str,
    vuln_type: &str,
    reasoning: &str,
    observations: Value,
) -> VerificationOutcome {
    VerificationOutcome {
        verdict: AssessmentVerdict::Inconclusive,
        observations,
        title: title.into(),
        vuln_type: vuln_type.into(),
        severity: "info".into(),
        confidence: 0,
        reasoning: reasoning.into(),
        evidence_replay_run_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: i64, status: u16, body: &str) -> ResponseObservation {
        ResponseObservation {
            replay_run_id: id,
            url: "https://example.test/resource".into(),
            status: Some(status),
            headers: Vec::new(),
            body_hash: Some(body.into()),
            body_size: 10,
            complete: true,
        }
    }

    fn with_headers(
        mut response: ResponseObservation,
        headers: &[(&str, &str)],
    ) -> ResponseObservation {
        response.headers = headers
            .iter()
            .map(|(name, value)| ReplayHeader {
                name: (*name).into(),
                value: (*value).into(),
            })
            .collect();
        response
    }

    fn endpoint(owner: Option<i64>) -> AssessmentEndpoint {
        AssessmentEndpoint {
            id: 1,
            run_id: 1,
            endpoint_id: "ep_test".into(),
            method: "GET".into(),
            url: "https://example.test/resource".into(),
            path: "/resource".into(),
            query_parameter_names: Vec::new(),
            source_kind: "crawl".into(),
            status: Some(200),
            content_type: "application/json".into(),
            has_authentication: true,
            passive_tags: Vec::new(),
            response_complete: true,
            resource_owner_profile_id: owner,
        }
    }

    #[test]
    fn idor_requires_explicit_ownership_for_confirmation() {
        let responses = HashMap::from([
            ("identity_a".into(), response(1, 200, "same")),
            ("identity_b".into(), response(2, 200, "same")),
        ]);
        assert_eq!(
            verify_idor(&endpoint(None), &responses).verdict,
            AssessmentVerdict::Suspected
        );
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::Confirmed
        );
    }

    #[test]
    fn incomplete_or_dynamic_responses_never_confirm() {
        let mut responses = HashMap::from([
            ("identity_a".into(), response(1, 200, "left")),
            ("identity_b".into(), response(2, 200, "right")),
        ]);
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::NotObserved
        );
        responses.get_mut("identity_b").unwrap().complete = false;
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn security_header_cookie_verifier_has_fact_only_positive_negative_and_truncation_edges() {
        let missing = with_headers(
            response(1, 200, "body"),
            &[("set-cookie", "session_id=abc; Path=/")],
        );
        let positive = verify_security_headers(
            &endpoint(None),
            &HashMap::from([("baseline".into(), missing)]),
        );
        assert_eq!(positive.verdict, AssessmentVerdict::Confirmed);
        assert!(positive.observations["facts"].as_array().unwrap().len() >= 3);

        let protected = with_headers(
            response(2, 200, "body"),
            &[
                ("strict-transport-security", "max-age=31536000"),
                ("set-cookie", "session_id=abc; Secure; HttpOnly; Path=/"),
            ],
        );
        assert_eq!(
            verify_security_headers(
                &endpoint(None),
                &HashMap::from([("baseline".into(), protected)])
            )
            .verdict,
            AssessmentVerdict::NotObserved
        );
        let mut truncated = response(3, 200, "body");
        truncated.complete = false;
        assert_eq!(
            verify_security_headers(
                &endpoint(None),
                &HashMap::from([("baseline".into(), truncated)])
            )
            .verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn cors_verifier_requires_complete_successful_probe_with_both_headers() {
        let baseline = response(1, 200, "protected");
        let anonymous = with_headers(
            response(3, 401, "denied"),
            &[("content-type", "application/json")],
        );
        let reflected = with_headers(
            response(2, 200, "protected"),
            &[
                ("access-control-allow-origin", "https://rf-probe.invalid"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        let mut responses = HashMap::from([
            ("baseline".into(), baseline),
            ("anonymous".into(), anonymous),
            ("probe".into(), reflected),
        ]);
        assert_eq!(
            verify_cors(&responses).verdict,
            AssessmentVerdict::Confirmed
        );
        responses.get_mut("probe").unwrap().status = Some(500);
        assert_eq!(
            verify_cors(&responses).verdict,
            AssessmentVerdict::NotObserved
        );
        responses.get_mut("probe").unwrap().complete = false;
        assert_eq!(
            verify_cors(&responses).verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn cors_verifier_never_confirms_on_public_endpoints() {
        let baseline = response(1, 200, "public");
        let anonymous = response(2, 200, "public");
        let reflected = with_headers(
            response(3, 200, "public"),
            &[
                ("access-control-allow-origin", "https://rf-probe.invalid"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        let responses = HashMap::from([
            ("baseline".into(), baseline),
            ("anonymous".into(), anonymous),
            ("probe".into(), reflected),
        ]);
        let outcome = verify_cors(&responses);
        assert_eq!(outcome.verdict, AssessmentVerdict::NotObserved);
        assert_eq!(outcome.observations["endpointNotProtected"], true);
    }

    #[test]
    fn jwt_verifier_requires_anonymous_rejection_both_complete_probes_and_exact_response() {
        let typed = |id, status, body| {
            with_headers(
                response(id, status, body),
                &[("content-type", "application/json")],
            )
        };
        let mut responses = HashMap::from([
            ("baseline".into(), typed(1, 200, "same")),
            ("anonymous".into(), typed(2, 401, "denied")),
            ("signature_probe".into(), typed(3, 200, "same")),
            ("alg_none_probe".into(), typed(4, 401, "denied")),
        ]);
        assert_eq!(verify_jwt(&responses).verdict, AssessmentVerdict::Confirmed);
        responses.get_mut("signature_probe").unwrap().body_hash = Some("dynamic".into());
        assert_eq!(
            verify_jwt(&responses).verdict,
            AssessmentVerdict::NotObserved
        );
        responses.remove("alg_none_probe");
        assert_eq!(
            verify_jwt(&responses).verdict,
            AssessmentVerdict::Inconclusive
        );
        responses.insert("alg_none_probe".into(), typed(5, 401, "denied"));
        responses.get_mut("signature_probe").unwrap().complete = false;
        assert_eq!(
            verify_jwt(&responses).verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn open_redirect_verifier_confirms_only_unfollowed_fixed_invalid_location() {
        let external = with_headers(
            response(1, 302, "empty"),
            &[("location", "https://rf-probe.invalid/rf")],
        );
        let mut responses = HashMap::from([("probe".into(), external)]);
        assert_eq!(
            verify_open_redirect(&responses).verdict,
            AssessmentVerdict::Confirmed
        );
        responses.get_mut("probe").unwrap().headers[0].value =
            "https://rf-probe.invalid.evil.test/".into();
        assert_eq!(
            verify_open_redirect(&responses).verdict,
            AssessmentVerdict::NotObserved
        );
        responses.get_mut("probe").unwrap().complete = false;
        assert_eq!(
            verify_open_redirect(&responses).verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn reflection_verifier_never_upgrades_marker_reflection_to_confirmed_xss() {
        let responses = HashMap::from([("probe".into(), response(1, 200, "marker"))]);
        let observed = verify_reflection(&responses, Some("RF123"), true);
        assert_eq!(observed.verdict, AssessmentVerdict::Suspected);
        assert_eq!(observed.observations["xssExecuted"], false);
        assert_eq!(
            verify_reflection(&responses, Some("RF123"), false).verdict,
            AssessmentVerdict::NotObserved
        );
        let mut incomplete = responses;
        incomplete.get_mut("probe").unwrap().complete = false;
        assert_eq!(
            verify_reflection(&incomplete, Some("RF123"), true).verdict,
            AssessmentVerdict::Inconclusive
        );
    }

    #[test]
    fn idor_equivalence_includes_content_type_and_nonempty_complete_body() {
        let a = with_headers(
            response(1, 200, "same"),
            &[("content-type", "application/json")],
        );
        let b = with_headers(response(2, 200, "same"), &[("content-type", "text/html")]);
        let mut responses = HashMap::from([("identity_a".into(), a), ("identity_b".into(), b)]);
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::NotObserved
        );
        responses.get_mut("identity_b").unwrap().headers[0].value = "application/json".into();
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::Confirmed
        );
        responses.get_mut("identity_b").unwrap().body_size = 0;
        responses.get_mut("identity_a").unwrap().body_size = 0;
        assert_eq!(
            verify_idor(&endpoint(Some(7)), &responses).verdict,
            AssessmentVerdict::NotObserved
        );
    }
}
