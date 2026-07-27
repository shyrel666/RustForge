//! Markdown 学习报告：把「抓包 → 分析 → 任务树引导 → 发现验证」的成果
//! 整理成一份可复盘/提交的报告。修复建议复用 knowledge 模块。
//! 红线：报告顶部固定授权免责声明；AI/规则结论标注需人工复核。

use crate::knowledge;
use crate::knowledge::StandardReference;
use rusqlite::Connection;

struct RFinding {
    source: String,
    title: String,
    vuln_type: String,
    standard_references: Vec<StandardReference>,
    severity: String,
    confidence: i64,
    reasoning: String,
    verify_steps: String,
    status: String,
    created_at: String,
    method: Option<String>,
    url: Option<String>,
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

fn source_cn(s: &str) -> &str {
    match s {
        "ai" => "AI 分析",
        "rule" => "被动规则",
        _ => s,
    }
}

fn finding_status_cn(s: &str) -> &str {
    match s {
        "pending" => "待验证",
        "confirmed" => "已确认",
        "rejected" => "已排除",
        _ => s,
    }
}

fn task_status_cn(s: &str) -> &str {
    match s {
        "todo" => "待做",
        "in_progress" => "进行中",
        "done" => "完成",
        "blocked" => "受阻",
        _ => s,
    }
}

fn load_findings(conn: &Connection, project_id: i64) -> Result<Vec<RFinding>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT f.source, f.title, f.vuln_type, f.standard_references, f.severity,
                    f.confidence, f.reasoning, f.verify_steps, f.status, f.created_at,
                    t.method, t.url
             FROM findings f LEFT JOIN traffic t ON t.id = f.traffic_id
             WHERE f.project_id = ?1
             ORDER BY f.id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([project_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<String>>(11)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut findings = Vec::new();
    for row in rows {
        let (
            source,
            title,
            vuln_type,
            references_json,
            severity,
            confidence,
            reasoning,
            verify_steps,
            status,
            created_at,
            method,
            url,
        ) = row.map_err(|e| e.to_string())?;
        findings.push(RFinding {
            source,
            title,
            vuln_type,
            standard_references: knowledge::references_from_json(&references_json)?,
            severity,
            confidence,
            reasoning,
            verify_steps,
            status,
            created_at,
            method,
            url,
        });
    }
    Ok(findings)
}

fn format_references(references: &[StandardReference]) -> String {
    if references.is_empty() {
        "—".to_string()
    } else {
        references
            .iter()
            .map(StandardReference::display_key)
            .collect::<Vec<_>>()
            .join("、")
    }
}

/// 渲染单条发现（供「已确认」「待验证」两节复用）
fn render_finding(out: &mut String, idx: usize, f: &RFinding) -> Result<(), String> {
    out.push_str(&format!("### {}. [{}] {}\n\n", idx, f.severity, f.title));
    out.push_str(&format!(
        "- 类型：{}　置信度：{}　来源：{}\n",
        if f.vuln_type.is_empty() {
            "—"
        } else {
            &f.vuln_type
        },
        f.confidence,
        source_cn(&f.source)
    ));
    out.push_str(&format!(
        "- 标准引用：{}\n",
        format_references(&f.standard_references)
    ));
    if let (Some(m), Some(u)) = (&f.method, &f.url) {
        out.push_str(&format!("- 关联请求：`{m} {u}`\n"));
    }
    out.push_str("\n**证据 / 推理**\n\n");
    out.push_str(&format!(
        "{}\n\n",
        if f.reasoning.is_empty() {
            "（无）"
        } else {
            &f.reasoning
        }
    ));
    out.push_str("**手动验证步骤**\n\n");
    out.push_str(&format!(
        "{}\n\n",
        if f.verify_steps.is_empty() {
            "（无）"
        } else {
            &f.verify_steps
        }
    ));
    let rem = knowledge::remediation_for(&f.standard_references)?;
    if !rem.is_empty() {
        out.push_str("**修复建议**\n\n");
        out.push_str(&format!("{rem}\n\n"));
    }
    Ok(())
}

/// 生成完整报告的 Markdown 文本
pub fn build_markdown(conn: &Connection, project_id: i64) -> Result<String, String> {
    // 项目信息
    let (name, target, scope_json, created_at): (String, String, String, String) = conn
        .query_row(
            "SELECT name, target_host, scope, created_at FROM projects WHERE id = ?1",
            [project_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| format!("项目 #{project_id} 不存在"))?;
    let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();

    let traffic_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM traffic WHERE project_id = ?1",
            [project_id],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let findings = load_findings(conn, project_id)?;
    let confirmed: Vec<&RFinding> = findings
        .iter()
        .filter(|f| f.status == "confirmed")
        .collect();
    let pending: Vec<&RFinding> = findings.iter().filter(|f| f.status == "pending").collect();
    let rejected_n = findings.iter().filter(|f| f.status == "rejected").count();

    // 严重度分布（不含已排除）
    let mut sev = std::collections::BTreeMap::<u8, i64>::new();
    for f in findings.iter().filter(|f| f.status != "rejected") {
        *sev.entry(severity_rank(&f.severity)).or_default() += 1;
    }
    let sev_line = ["critical", "high", "medium", "low", "info"]
        .iter()
        .map(|s| format!("{} {}", s, sev.get(&severity_rank(s)).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join("，");

    // 任务树进度
    let (task_total, task_done): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(status='done'),0) FROM task_nodes WHERE project_id = ?1",
            [project_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((0, 0));

    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut out = String::new();
    out.push_str(&format!("# 渗透测试学习报告：{name}\n\n"));
    out.push_str(&format!(
        "- 目标主机：{}\n",
        if target.is_empty() {
            "（未填写）".into()
        } else {
            target
        }
    ));
    out.push_str(&format!(
        "- 授权范围（Scope）：{}\n",
        if scope.is_empty() {
            "（未设置）".into()
        } else {
            scope.join("、")
        }
    ));
    out.push_str(&format!("- 项目创建时间：{created_at}\n"));
    out.push_str(&format!("- 报告生成时间：{now}\n\n"));
    out.push_str(
        "> **免责声明**：本报告由 RustForge 生成，仅用于**已获授权**的渗透测试与安全学习。\
         其中 AI 与被动规则给出的结论均为「假设」，**每一条都需人工按验证步骤复核**，请勿用于未授权目标。\n\n",
    );

    // 一、执行摘要
    out.push_str("## 一、执行摘要\n\n");
    out.push_str(&format!("- 已抓取流量：{traffic_count} 条\n"));
    out.push_str(&format!(
        "- 发现合计：{} 条（已确认 {} / 待验证 {} / 已排除 {}）\n",
        findings.len(),
        confirmed.len(),
        pending.len(),
        rejected_n
    ));
    out.push_str(&format!("- 严重度分布（不含已排除）：{sev_line}\n"));
    out.push_str(&format!(
        "- 任务树进度：{task_done}/{task_total} 个节点完成\n\n"
    ));

    // 二、已确认发现
    out.push_str("## 二、已确认发现\n\n");
    if confirmed.is_empty() {
        out.push_str("> 暂无已确认发现。\n\n");
    } else {
        let mut sorted = confirmed.clone();
        sorted.sort_by_key(|f| severity_rank(&f.severity));
        for (i, f) in sorted.iter().enumerate() {
            render_finding(&mut out, i + 1, f)?;
        }
    }

    // 三、待验证发现
    out.push_str("## 三、待验证发现（需人工复核后确认）\n\n");
    if pending.is_empty() {
        out.push_str("> 暂无待验证发现。\n\n");
    } else {
        let mut sorted = pending.clone();
        sorted.sort_by_key(|f| severity_rank(&f.severity));
        for (i, f) in sorted.iter().enumerate() {
            render_finding(&mut out, i + 1, f)?;
        }
    }

    // 四、时间线
    out.push_str("## 四、渗透过程时间线\n\n");
    let timeline: Vec<&RFinding> = findings.iter().filter(|f| f.status != "rejected").collect();
    if timeline.is_empty() {
        out.push_str("> 暂无记录。\n\n");
    } else {
        for f in &timeline {
            out.push_str(&format!(
                "- {} · [{}] {}（{}）\n",
                f.created_at,
                source_cn(&f.source),
                f.title,
                finding_status_cn(&f.status)
            ));
        }
        out.push('\n');
    }

    // 五、任务树概览
    out.push_str("## 五、任务树概览\n\n");
    render_task_overview(conn, project_id, &mut out)?;

    // 六、涉及知识点
    let mut cards = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in findings.iter().filter(|f| f.status != "rejected") {
        for c in knowledge::lookup(&f.standard_references)? {
            if seen.insert(c.key.clone()) {
                cards.push(c);
            }
        }
    }
    if !cards.is_empty() {
        out.push_str("## 六、涉及知识点\n\n");
        for c in &cards {
            out.push_str(&format!("- **{}** {}\n", c.key, c.title));
        }
        out.push('\n');
    }

    Ok(out)
}

/// 阶段（顶层节点）→ 直接子任务的状态清单
fn render_task_overview(
    conn: &Connection,
    project_id: i64,
    out: &mut String,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, parent_id, title, status, standard_references FROM task_nodes
             WHERE project_id = ?1 ORDER BY parent_id IS NOT NULL, sort_order, id",
        )
        .map_err(|e| e.to_string())?;
    struct N {
        id: i64,
        parent_id: Option<i64>,
        title: String,
        status: String,
        standard_references: Vec<StandardReference>,
    }
    let nodes: Vec<N> = stmt
        .query_map([project_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(
            |(id, parent_id, title, status, references_json)| -> Result<N, String> {
                Ok(N {
                    id,
                    parent_id,
                    title,
                    status,
                    standard_references: knowledge::references_from_json(&references_json)?,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    if nodes.is_empty() {
        out.push_str("> 尚未生成任务树。\n\n");
        return Ok(());
    }
    let phases: Vec<&N> = nodes.iter().filter(|n| n.parent_id.is_none()).collect();
    for p in phases {
        let children: Vec<&N> = nodes.iter().filter(|n| n.parent_id == Some(p.id)).collect();
        let done = children.iter().filter(|c| c.status == "done").count();
        out.push_str(&format!(
            "### {}（{}，子任务 {}/{} 完成）\n\n",
            p.title,
            task_status_cn(&p.status),
            done,
            children.len()
        ));
        if !p.standard_references.is_empty() {
            out.push_str(&format!(
                "- 标准引用：{}\n",
                format_references(&p.standard_references)
            ));
        }
        for c in &children {
            let references = if c.standard_references.is_empty() {
                String::new()
            } else {
                format!(" · {}", format_references(&c.standard_references))
            };
            out.push_str(&format!(
                "- [{}] {}{}\n",
                task_status_cn(&c.status),
                c.title,
                references
            ));
        }
        out.push('\n');
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::Db;

    #[test]
    fn report_has_core_sections() {
        let dir = std::env::temp_dir().join(format!("rustforge-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("t.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('演示','demo.test','[\"demo.test\"]')",
                [],
            )
            .unwrap();
        let pid = db.conn.last_insert_rowid();
        db.conn
            .execute(
                "INSERT INTO traffic(project_id, method, host, url)
                 VALUES(?1,'POST','demo.test','https://demo.test/login')",
                [pid],
            )
            .unwrap();
        let traffic_id = db.conn.last_insert_rowid();
        db.conn
            .execute(
                "INSERT INTO analysis_runs(
                    project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
                    prompt_version, input_hash, policy_json, manifest_json, validation_status,
                    validation_json, raw_output_hash
                 ) VALUES(?1,?2,'test','https://provider.test/v1','model','prompt',1,?3,'{}','{}','valid','{}',?3)",
                rusqlite::params![pid, traffic_id, "a".repeat(64)],
            )
            .unwrap();
        let run_id = db.conn.last_insert_rowid();
        let references_json = knowledge::references_to_json(&[
            StandardReference::new("owasp-top10", "2021", "A03"),
            StandardReference::new("cwe", "4.20", "CWE-89"),
        ])
        .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(project_id, traffic_id, analysis_run_id, source, title, vuln_type, standard_references, severity,
                                      confidence, reasoning, verify_steps, status)
                 VALUES(?1,?2,?3,'ai','登录存在 SQL 注入','SQL 注入',
                        ?4,
                        'high',80,
                        '参数 user 报错','1. 加单引号观察报错','confirmed')",
                rusqlite::params![pid, traffic_id, run_id, references_json],
            )
            .unwrap();

        let md = build_markdown(&db.conn, pid).unwrap();
        assert!(md.contains("# 渗透测试学习报告：演示"));
        assert!(md.contains("免责声明"));
        assert!(md.contains("## 二、已确认发现"));
        assert!(md.contains("登录存在 SQL 注入"));
        assert!(md.contains("A03:2021"));
        assert!(md.contains("CWE-89 (v4.20)"));
        assert!(md.contains("修复建议"), "已知 CWE 应带修复建议");
        assert!(md.contains("## 六、涉及知识点"));
    }
}
