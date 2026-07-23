//! 知识库：OWASP Top 10 (2021) + 常见 CWE 的中文知识卡片。
//! 纯静态数据，无外部依赖——Finding 上挂 owasp/cwe 字段，前端据此拉卡片，
//! 报告模块也复用这里的「修复建议」。匹配用前缀（如 "A01" / "CWE-89"），
//! 兼容 AI 产出的各种写法（"A01:2021 - Broken Access Control"、"CWE-89: SQL Injection"）。

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeCard {
    /// 归一化后的键，如 "A01:2021" / "CWE-89"
    pub key: String,
    /// "owasp" | "cwe"
    pub kind: String,
    pub title: String,
    /// 原理
    pub principle: String,
    /// 危害
    pub impact: String,
    /// 常见成因
    pub cause: String,
    /// 修复建议
    pub remediation: String,
}

/// (键, 标题, 原理, 危害, 成因, 修复)
type Row = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

const OWASP: &[Row] = &[
    ("A01:2021", "失效的访问控制（Broken Access Control）",
     "对「谁能访问什么资源/执行什么操作」的限制没有正确实施，用户可越权访问他人数据或管理功能。",
     "水平越权（访问他人数据）、垂直越权（普通用户获得管理员能力）、敏感数据泄露与篡改。",
     "直接使用用户可控的对象引用（IDOR）、仅靠前端隐藏入口、缺少服务端授权校验、JWT/Cookie 未校验归属。",
     "服务端对每个请求强制做「主体—资源—操作」授权校验；默认拒绝；对象引用用间接映射或校验归属；关键操作记录审计日志。"),
    ("A02:2021", "加密机制失效（Cryptographic Failures）",
     "敏感数据在传输或存储时未加密、或使用了弱加密/错误用法，导致数据可被读取。",
     "口令、令牌、个人隐私、支付信息等敏感数据泄露。",
     "明文传输（无 HTTPS）、弱算法（MD5/SHA1/DES）、硬编码密钥、口令未加盐哈希、错误的证书校验。",
     "全站强制 TLS 与 HSTS；口令用 bcrypt/scrypt/Argon2 加盐；用现代算法（AES-GCM）；密钥集中托管并轮换；最小化留存敏感数据。"),
    ("A03:2021", "注入（Injection）",
     "不可信输入被拼接进解释器（SQL/OS/LDAP/模板等）指令，改变了原有语义并被执行。",
     "数据被窃取/篡改、命令执行、认证绕过，严重时可完全控制后端。",
     "字符串拼接构造 SQL/命令、未做输入校验与输出编码、动态执行用户输入。",
     "使用参数化查询/预编译语句与 ORM；服务端做白名单校验；对输出按上下文编码；命令执行改用安全 API 并最小权限。"),
    ("A04:2021", "不安全的设计（Insecure Design）",
     "在架构与流程层面缺少必要的安全控制，是「设计缺陷」而非「实现 Bug」。",
     "业务逻辑被滥用（薅羊毛、越权流程、绕过限额），事后难以靠补丁修复。",
     "缺少威胁建模、未考虑滥用场景、关键业务无频率/额度/状态机约束。",
     "在设计阶段做威胁建模；为关键流程设计安全用例与滥用用例；服务端强制业务规则与限额；纵深防御。"),
    ("A05:2021", "安全配置错误（Security Misconfiguration）",
     "系统/框架/中间件使用了不安全的默认或错误配置，暴露了不该暴露的能力或信息。",
     "调试接口/管理台暴露、目录列表、详细报错泄露、默认口令被利用。",
     "开启调试模式、默认账号未改、多余服务/端口开放、缺少安全响应头、云存储权限过宽。",
     "统一安全基线并自动化核查；关闭调试与目录列表；删除默认账号与示例；最小化组件；补齐安全响应头（CSP/X-Frame-Options 等）。"),
    ("A06:2021", "自带已知漏洞的组件（Vulnerable and Outdated Components）",
     "使用了含已知漏洞的第三方库/框架/依赖，攻击者直接利用公开 EXP。",
     "可被现成漏洞利用，影响范围随组件权限而定，常导致 RCE。",
     "依赖版本陈旧、无资产/依赖清单、不关注安全公告、传递依赖失控。",
     "建立依赖清单（SBOM）与升级流程；用 SCA 工具持续扫描；及时打补丁；移除无用依赖；只从可信源获取。"),
    ("A07:2021", "身份识别与认证失效（Identification and Authentication Failures）",
     "认证与会话管理存在缺陷，攻击者可冒充他人身份。",
     "账号被撞库/爆破/接管，会话被劫持或固定。",
     "允许弱口令、无防爆破与多因素、会话 ID 可预测/不失效、凭证明文或弱哈希。",
     "支持并鼓励多因素认证；限制登录尝试与告警；登录后重置会话 ID 并设置合理过期；口令强度校验与安全存储。"),
    ("A08:2021", "软件与数据完整性失效（Software and Data Integrity Failures）",
     "代码或数据在更新/传输/反序列化时未校验完整性，可被植入恶意内容。",
     "供应链投毒、恶意更新、反序列化导致的远程代码执行。",
     "从不可信源加载依赖/更新、无签名校验、反序列化不可信数据。",
     "对更新与关键数据做数字签名校验；使用可信仓库与锁定版本；避免反序列化不可信数据或使用安全格式与白名单。"),
    ("A09:2021", "安全日志与监控失效（Security Logging and Monitoring Failures）",
     "关键安全事件缺少日志或告警，攻击难以被及时发现与追溯。",
     "入侵长期潜伏、事件无法取证复盘、响应迟缓扩大损失。",
     "登录/越权/失败等事件未记录、日志无集中与告警、日志含敏感信息或可被篡改。",
     "记录关键安全事件（登录、越权、异常）并集中存储；设置实时告警与留存策略；日志脱敏与完整性保护；定期演练响应。"),
    ("A10:2021", "服务端请求伪造（SSRF）",
     "服务端根据用户提供的 URL 发起请求，被诱导访问内网或元数据等非预期目标。",
     "探测/访问内网服务、读取云元数据窃取凭证、绕过防火墙形成跳板。",
     "直接用用户输入的 URL 拉取资源、未校验目标地址、允许访问内网/回环/元数据地址。",
     "对目标地址做白名单校验并解析后校验 IP；禁止访问内网/回环/元数据网段；禁用多余协议与重定向跟随；出网流量最小化。"),
];

const CWE: &[Row] = &[
    ("CWE-89", "SQL 注入",
     "用户输入被拼接进 SQL 语句，改变查询逻辑被数据库执行。",
     "拖库、篡改数据、认证绕过，配合功能可能读写文件或命令执行。",
     "字符串拼接 SQL、未参数化、信任前端校验。",
     "全程使用参数化查询/预编译；ORM 安全用法；最小化数据库账号权限；对报错信息做统一处理。"),
    ("CWE-79", "跨站脚本（XSS）",
     "不可信数据未经编码输出到页面，浏览器将其当作脚本执行。",
     "窃取会话/令牌、钓鱼、篡改页面、蠕虫传播。",
     "直接把用户输入拼进 HTML/JS、未按上下文编码、富文本未净化。",
     "按输出上下文编码（HTML/属性/JS/URL）；富文本用白名单净化；启用 CSP；Cookie 加 HttpOnly。"),
    ("CWE-78", "操作系统命令注入",
     "用户输入被拼接进系统命令并由 shell 执行。",
     "在服务器上执行任意命令，通常等同完全控制主机。",
     "拼接命令字符串调用 shell、未校验参数。",
     "避免调用 shell，改用带参数数组的安全 API；严格白名单校验；最小权限运行。"),
    ("CWE-22", "路径遍历（Path Traversal）",
     "用户可控的路径参数含 ../ 等序列，访问了预期目录之外的文件。",
     "读取/写入/删除任意文件，泄露配置与源码，甚至覆盖关键文件。",
     "直接用用户输入拼接文件路径、未规范化与校验。",
     "对路径做规范化后校验是否落在允许根目录内；用白名单与随机映射；避免直接暴露文件系统路径。"),
    ("CWE-352", "跨站请求伪造（CSRF）",
     "利用用户已登录的身份，在其不知情时诱导浏览器发起状态变更请求。",
     "在受害者身份下执行转账、改密、下单等敏感操作。",
     "关键操作仅依赖 Cookie 鉴权、无 CSRF Token、无同源校验。",
     "为状态变更请求加不可预测的 CSRF Token；使用 SameSite Cookie；对敏感操作二次校验（如重输口令）。"),
    ("CWE-434", "危险类型文件上传",
     "允许上传可执行/脚本类型文件且可被访问执行。",
     "上传 WebShell 导致远程代码执行、控制服务器。",
     "仅校验扩展名/前端、未校验内容与存储位置、上传目录可执行。",
     "服务端校验类型与内容并重命名；存储到不可执行目录或对象存储；限制大小；隔离下载域名。"),
    ("CWE-287", "认证不当（Improper Authentication）",
     "认证逻辑存在缺陷，攻击者无需正确凭证即可通过身份校验。",
     "身份冒充、账号接管、越权访问。",
     "认证可绕过、逻辑漏洞、比较不当、信任客户端断言。",
     "使用成熟认证框架；服务端集中校验；开启多因素；避免自造加密与比较逻辑。"),
    ("CWE-798", "使用硬编码凭证",
     "代码或配置中写死了口令/密钥，一旦泄露即被直接利用。",
     "凭证泄露导致系统或第三方服务被直接接管。",
     "为图省事把密钥写进源码/前端/仓库。",
     "凭证移入环境变量或密钥管理服务；轮换已泄露密钥；仓库扫描防止再次提交。"),
    ("CWE-200", "敏感信息泄露",
     "系统把不该暴露的信息返回给了无权获取的一方。",
     "泄露内部路径、版本、堆栈、账号、令牌，为进一步攻击提供情报。",
     "详细报错、调试信息、注释、响应头/接口返回过多字段。",
     "生产环境关闭详细报错与调试；接口按需返回字段；清理注释与敏感响应头。"),
    ("CWE-918", "服务端请求伪造（SSRF）",
     "服务端使用用户可控 URL 发起请求，被引导访问非预期内网/元数据资源。",
     "访问内网服务、窃取云元数据凭证、形成内网跳板。",
     "直接请求用户提供的 URL、未做地址白名单与网段限制。",
     "解析后校验目标 IP 与网段白名单；禁止内网/回环/元数据地址；禁用多余协议与重定向。"),
    ("CWE-611", "XML 外部实体注入（XXE）",
     "XML 解析器处理了外部实体，被用于读取文件或发起请求。",
     "读取服务器本地文件、SSRF、拒绝服务。",
     "启用了外部实体解析、使用了不安全的默认 XML 解析配置。",
     "禁用 DTD 与外部实体解析；使用安全的解析器配置；尽量改用 JSON。"),
    ("CWE-502", "不安全的反序列化",
     "反序列化了不可信数据，触发非预期的对象构造或方法调用。",
     "远程代码执行、权限提升、拒绝服务。",
     "反序列化用户可控数据、使用危险的序列化框架。",
     "避免反序列化不可信数据；使用只含数据的安全格式（如 JSON）；做类型白名单与完整性签名校验。"),
    ("CWE-639", "越权访问（IDOR / 授权绕过）",
     "通过修改请求中标识资源的参数（如 id），访问到不属于自己的资源。",
     "水平越权读取/修改他人数据，批量枚举导致大规模泄露。",
     "仅凭用户提供的对象 id 取数、未校验资源归属。",
     "服务端校验「当前用户是否有权访问该资源」；用不可枚举的间接引用；对枚举行为限流告警。"),
];

fn build_all() -> Vec<KnowledgeCard> {
    let mut out = Vec::new();
    for &(key, title, principle, impact, cause, remediation) in OWASP {
        out.push(KnowledgeCard {
            key: key.into(),
            kind: "owasp".into(),
            title: title.into(),
            principle: principle.into(),
            impact: impact.into(),
            cause: cause.into(),
            remediation: remediation.into(),
        });
    }
    for &(key, title, principle, impact, cause, remediation) in CWE {
        out.push(KnowledgeCard {
            key: key.into(),
            kind: "cwe".into(),
            title: title.into(),
            principle: principle.into(),
            impact: impact.into(),
            cause: cause.into(),
            remediation: remediation.into(),
        });
    }
    out
}

/// 归一化 CWE 写法为 "CWE-<n>"（大写、去空格）
fn normalize_cwe(s: &str) -> Option<String> {
    let up = s.to_ascii_uppercase();
    let idx = up.find("CWE")?;
    let rest = &up[idx + 3..];
    let digits: String = rest
        .trim_start_matches([':', '-', ' '])
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("CWE-{digits}"))
    }
}

/// 归一化 OWASP 写法为 "A01:2021"（取 A?? 前缀）
fn normalize_owasp(s: &str) -> Option<String> {
    let up = s.to_ascii_uppercase();
    let idx = up.find('A')?;
    let after = &up[idx + 1..];
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 1 && digits.len() <= 2 {
        let n: u32 = digits.parse().ok()?;
        if (1..=10).contains(&n) {
            return Some(format!("A{n:02}:2021"));
        }
    }
    None
}

/// 根据 Finding 的 owasp / cwe 字段返回匹配到的知识卡片（0~2 张）
pub fn lookup(owasp: &str, cwe: &str) -> Vec<KnowledgeCard> {
    let all = build_all();
    let mut out = Vec::new();
    if let Some(k) = normalize_owasp(owasp) {
        if let Some(c) = all.iter().find(|c| c.key == k) {
            out.push(c.clone());
        }
    }
    if let Some(k) = normalize_cwe(cwe) {
        if let Some(c) = all.iter().find(|c| c.key == k) {
            out.push(c.clone());
        }
    }
    out
}

/// 给报告用：合并 owasp/cwe 对应的修复建议（可能为空）
pub fn remediation_for(owasp: &str, cwe: &str) -> String {
    let cards = lookup(owasp, cwe);
    cards
        .iter()
        .map(|c| format!("（{}）{}", c.key, c.remediation))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_various_writings() {
        assert_eq!(normalize_cwe("CWE-89"), Some("CWE-89".into()));
        assert_eq!(normalize_cwe("cwe-89: SQL Injection"), Some("CWE-89".into()));
        assert_eq!(normalize_cwe("CWE 79"), Some("CWE-79".into()));
        assert_eq!(normalize_cwe("无"), None);
        assert_eq!(normalize_owasp("A01:2021 - Broken Access Control"), Some("A01:2021".into()));
        assert_eq!(normalize_owasp("a3"), Some("A03:2021".into()));
        assert_eq!(normalize_owasp("A11"), None);
    }

    #[test]
    fn lookup_matches_and_dedupes() {
        let cards = lookup("A03:2021 Injection", "CWE-89");
        assert_eq!(cards.len(), 2);
        assert!(cards.iter().any(|c| c.key == "A03:2021"));
        assert!(cards.iter().any(|c| c.key == "CWE-89"));

        let none = lookup("未知", "无");
        assert!(none.is_empty());
    }

    #[test]
    fn remediation_nonempty_for_known() {
        assert!(!remediation_for("A01:2021", "CWE-639").is_empty());
        assert!(remediation_for("", "").is_empty());
    }
}
