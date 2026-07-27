//! 旧版（v1）内置被动规则的兼容层。
//!
//! 生产求值已经切到 `packs/builtin-v1.json` 声明式规则包（见 `loader` /
//! `engine`）。这里保留同样 14 条规则的正则实现，只为 Task 3.3 做新旧影子
//! 对比时能跑同一批输入；它带着已知语义缺陷（全局 `must_absent` 会让任意
//! 一条合规 Cookie 掩盖其它 Cookie 的属性缺失），不要再用于判定。

use crate::knowledge::StandardReference;
use crate::rules::schema::Severity;
use regex::Regex;

/// 旧版规则的匹配目标（对哪一段原始文本做正则）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyTarget {
    Url,
    ReqHeaders,
    ReqBody,
    RespHeaders,
    RespBody,
}

/// 旧版单条规则。hit 判定：pattern 命中任一 target 文本 且 must_absent 未命中同一文本。
pub struct LegacyRule {
    pub id: &'static str,
    /// 规则名（也是 Finding 标题）
    pub name: &'static str,
    /// 命中说明（写入 Finding.reasoning）
    pub description: &'static str,
    /// 人工验证提示（写入 Finding.verify_steps）
    pub verify_hint: &'static str,
    pub severity: Severity,
    /// 列表打标文本
    pub tag: &'static str,
    /// Finding 的版本化标准引用
    pub vuln_type: &'static str,
    pub standard_references: Vec<StandardReference>,
    /// 规则置信度（启发式不可能 100%，诚实标注）
    pub confidence: u8,
    pub targets: &'static [LegacyTarget],
    pub pattern: Regex,
    /// 反向条件：文本里不能出现它（如 Set-Cookie 缺少 HttpOnly）
    pub must_absent: Option<Regex>,
}

fn refs(owasp_id: &str, cwe_id: &str) -> Vec<StandardReference> {
    vec![
        StandardReference::new("owasp-top10", "2021", owasp_id),
        StandardReference::new("cwe", "4.20", cwe_id),
    ]
}

pub fn legacy_rules() -> Vec<LegacyRule> {
    let r = |p: &str| Regex::new(p).expect("内置规则正则必须合法");
    vec![
        LegacyRule {
            id: "sensitive-param-in-url",
            name: "URL 中出现敏感参数",
            description: "URL 查询串疑似携带口令/密钥类参数。URL 会被代理、网关、浏览器历史记录，敏感值不应放在 URL 里。",
            verify_hint: "在详情中查看 URL 参数，确认参数值是否真是凭据；再用 Repeater 重放看服务端是否接受。",
            severity: Severity::Medium,
            tag: "敏感参数",
            vuln_type: "敏感信息通过 URL 传输",
            standard_references: refs("A02", "CWE-598"),
            confidence: 70,
            targets: &[LegacyTarget::Url],
            pattern: r(r"(?i)[?&](pass(wd|word)?|pwd|secret|token|api[-_]?key|access[-_]?token|auth[-_]?token|session[-_]?id)="),
            must_absent: None,
        },
        LegacyRule {
            id: "password-in-request-body",
            name: "请求体携带口令字段",
            description: "请求体中出现 password 类字段。本身不必然有问题，但应确认传输加密、服务端不记录明文日志。",
            verify_hint: "确认该请求走 HTTPS；检查响应/后续请求里口令是否被回显或日志泄露。",
            severity: Severity::Low,
            tag: "口令字段",
            vuln_type: "口令传输观察点",
            standard_references: refs("A02", "CWE-319"),
            confidence: 50,
            targets: &[LegacyTarget::ReqBody],
            pattern: r(r#"(?i)("|\b)(pass(wd|word)?|pwd)("\s*:\s*"|=)"#),
            must_absent: None,
        },
        LegacyRule {
            id: "jwt-exposed",
            name: "JWT Token",
            description: "流量中发现 JWT。解码 payload 可获用户信息；重点关注算法混淆（alg=none）与弱密钥风险。",
            verify_hint: "把 JWT 拿到 jwt.io 解码看 payload 泄露了什么；尝试 alg=none/弱密钥爆破（仅授权目标）。",
            severity: Severity::Info,
            tag: "JWT",
            vuln_type: "JWT 使用点",
            standard_references: refs("A02", "CWE-345"),
            confidence: 90,
            targets: &[LegacyTarget::ReqHeaders, LegacyTarget::ReqBody],
            pattern: r(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
            must_absent: None,
        },
        LegacyRule {
            id: "sql-error-leak",
            name: "SQL 错误信息泄露",
            description: "响应包含数据库报错。说明输入可能拼接进 SQL 且错误未处理——SQL 注入的高价值线索。",
            verify_hint: "对比正常/异常输入的响应差异；手工在参数后加引号观察报错变化；确认数据库类型后再深入。",
            severity: Severity::High,
            tag: "SQL报错",
            vuln_type: "SQL 注入线索",
            standard_references: refs("A03", "CWE-89"),
            confidence: 75,
            targets: &[LegacyTarget::RespBody],
            pattern: r(r"(?i)(SQL syntax.*MySQL|You have an error in your SQL syntax|ORA-[0-9]{4,}|PostgreSQL.*ERROR|SQLite3?::|SQLite error|Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|pg_query\(\))"),
            must_absent: None,
        },
        LegacyRule {
            id: "stack-trace-leak",
            name: "错误堆栈泄露",
            description: "响应包含应用堆栈/框架错误页，泄露代码路径、组件版本等内部信息，可能伴随调试接口。",
            verify_hint: "阅读堆栈定位框架与版本；检查是否有 debug 开关；尝试触发更多异常路径收集信息。",
            severity: Severity::Medium,
            tag: "堆栈泄露",
            vuln_type: "错误信息泄露",
            standard_references: refs("A05", "CWE-209"),
            confidence: 70,
            targets: &[LegacyTarget::RespBody],
            pattern: r(r"(?i)(Traceback \(most recent call last\)|at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)|System\.[A-Za-z.]*Exception|NullReferenceException|Whoops, looks like something went wrong|laravel|django\.core\.exceptions)"),
            must_absent: None,
        },
        LegacyRule {
            id: "debug-actuator-endpoint",
            name: "调试/监控端点",
            description: "路径疑似 actuator/metrics/health 等运维端点，可能泄露环境变量、线程转储甚至支持远程操作。",
            verify_hint: "逐个访问确认是否未授权可读；重点看 /actuator/env、/actuator/heapdump、/metrics。",
            severity: Severity::Medium,
            tag: "调试端点",
            vuln_type: "敏感端点暴露",
            standard_references: refs("A05", "CWE-1188"),
            confidence: 60,
            targets: &[LegacyTarget::Url],
            pattern: r(r"(?i)/(actuator|metrics|debug|trace|dump|__debug__|_profiler|server-status|server-info)(/|$|\?)"),
            must_absent: None,
        },
        LegacyRule {
            id: "admin-console-path",
            name: "后台管理路径",
            description: "路径疑似管理后台/控制台。本身无害，但应确认有强认证与访问控制，避免弱口令直入。",
            verify_hint: "确认是否需要登录；尝试默认口令组合前请确认授权范围；留意后台接口是否单独鉴权。",
            severity: Severity::Info,
            tag: "后台路径",
            vuln_type: "管理后台暴露面",
            standard_references: refs("A07", "CWE-306"),
            confidence: 50,
            targets: &[LegacyTarget::Url],
            pattern: r(r"(?i)/(admin|administrator|manager|manage|phpmyadmin|wp-admin|console|backstage|dashboard)(/|$|\?)"),
            must_absent: None,
        },
        LegacyRule {
            id: "sensitive-file-access",
            name: "敏感文件/备份文件",
            description: "路径指向 .git/.env/备份/swap 等文件，可能直接泄露源码、配置与密钥。",
            verify_hint: "确认是否真实可下载；.git 泄露可尝试用工具完整还原仓库；.env 重点找数据库/AK 密钥。",
            severity: Severity::Medium,
            tag: "敏感文件",
            vuln_type: "敏感文件暴露",
            standard_references: refs("A05", "CWE-538"),
            confidence: 65,
            targets: &[LegacyTarget::Url],
            pattern: r(r"(?i)(/\.(git|env|svn|hg|DS_Store|idea|vscode)|\.(bak|swp|swo|old|orig|save|sql|dump|log|ini|conf|config)(\?|$|/))"),
            must_absent: None,
        },
        LegacyRule {
            id: "path-traversal-param",
            name: "路径穿越特征参数",
            description: "URL 参数出现 ../ 或其编码形式，可能存在任意文件读取。",
            verify_hint: "手工尝试 ../ 变体（....//、%2e%2e%2f、绝对路径）读取 /etc/passwd 或 win.ini，对比响应长度变化。",
            severity: Severity::Medium,
            tag: "路径穿越",
            vuln_type: "路径穿越线索",
            standard_references: refs("A01", "CWE-22"),
            confidence: 65,
            targets: &[LegacyTarget::Url],
            pattern: r(r"(?i)(\.\./|\.\.\\|%2e%2e|%252e|\.\.;)"),
            must_absent: None,
        },
        LegacyRule {
            id: "cors-wildcard",
            name: "CORS 通配符",
            description: "响应 Access-Control-Allow-Origin: *。若同时允许携带凭据或接口返回敏感数据，可被跨域读取。",
            verify_hint: "检查是否有 Access-Control-Allow-Credentials 与敏感响应；构造恶意 Origin 看是否被反射。",
            severity: Severity::Low,
            tag: "CORS",
            vuln_type: "CORS 配置宽松",
            standard_references: refs("A05", "CWE-942"),
            confidence: 60,
            targets: &[LegacyTarget::RespHeaders],
            pattern: r(r#"(?i)access-control-allow-origin"\s*:\s*"\s*\*"#),
            must_absent: None,
        },
        LegacyRule {
            id: "cookie-no-httponly",
            name: "Cookie 缺少 HttpOnly",
            description: "Set-Cookie 未带 HttpOnly，XSS 发生时可被脚本直接读取会话。",
            verify_hint: "确认该 Cookie 是否为会话凭据；结合 XSS 面评估实际风险。",
            severity: Severity::Low,
            tag: "Cookie",
            vuln_type: "Cookie 安全属性缺失",
            standard_references: refs("A05", "CWE-1004"),
            confidence: 65,
            targets: &[LegacyTarget::RespHeaders],
            pattern: r(r#"(?i)"set-cookie"\s*:"#),
            must_absent: Some(r(r"(?i)httponly")),
        },
        LegacyRule {
            id: "cookie-no-secure",
            name: "Cookie 缺少 Secure",
            description: "Set-Cookie 未带 Secure，HTTPS 站点会话可能被降级到明文传输。",
            verify_hint: "确认站点是否存在 HTTP 入口；检查 HSTS 是否启用。",
            severity: Severity::Low,
            tag: "Cookie",
            vuln_type: "Cookie 安全属性缺失",
            standard_references: refs("A02", "CWE-614"),
            confidence: 65,
            targets: &[LegacyTarget::RespHeaders],
            pattern: r(r#"(?i)"set-cookie"\s*:"#),
            must_absent: Some(r(r"(?i)secure")),
        },
        LegacyRule {
            id: "server-version-leak",
            name: "服务端版本信息泄露",
            description: "Server/X-Powered-By 等响应头暴露具体版本，便于定向匹配已知漏洞。",
            verify_hint: "记录组件与版本，对照 CVE 库确认是否有已公开漏洞影响该版本。",
            severity: Severity::Info,
            tag: "版本泄露",
            vuln_type: "版本信息泄露",
            standard_references: refs("A05", "CWE-200"),
            confidence: 70,
            targets: &[LegacyTarget::RespHeaders],
            pattern: r(r#"(?i)"(server|x-powered-by|x-aspnet-version|x-generator)"\s*:\s*"[^"]*\d+\.\d+"#),
            must_absent: None,
        },
        LegacyRule {
            id: "internal-ip-leak",
            name: "内网 IP 泄露",
            description: "内容中出现 RFC1918 内网地址，暴露内部网络结构，可作为横向信息。",
            verify_hint: "收集出现的内网段，结合 SSRF/重定向面评估是否可利用。",
            severity: Severity::Info,
            tag: "内网IP",
            vuln_type: "内部信息泄露",
            standard_references: refs("A05", "CWE-200"),
            confidence: 55,
            targets: &[LegacyTarget::RespBody],
            pattern: r(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b"),
            must_absent: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::rules::loader::builtin_pack;

    #[test]
    fn every_legacy_rule_uses_known_versioned_references() {
        for rule in super::legacy_rules() {
            crate::knowledge::validate_references(&rule.standard_references)
                .unwrap_or_else(|error| panic!("{}: {error}", rule.id));
        }
    }

    #[test]
    fn declarative_pack_preserves_legacy_identity_severity_and_references() {
        let pack = builtin_pack().pack().unwrap();
        for legacy in super::legacy_rules() {
            let migrated = pack
                .rules
                .iter()
                .find(|rule| rule.rule_id == legacy.id)
                .unwrap_or_else(|| panic!("规则 {} 未迁移到声明式规则包", legacy.id));
            assert_eq!(migrated.name, legacy.name, "{}", legacy.id);
            assert_eq!(migrated.severity, legacy.severity, "{}", legacy.id);
            assert_eq!(migrated.tag, legacy.tag, "{}", legacy.id);
            assert_eq!(migrated.vuln_type, legacy.vuln_type, "{}", legacy.id);
            assert_eq!(migrated.confidence, legacy.confidence, "{}", legacy.id);
            assert_eq!(
                migrated.references,
                crate::knowledge::validate_references(&legacy.standard_references).unwrap(),
                "{}",
                legacy.id
            );
        }
    }
}
