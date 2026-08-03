# Phase 2 · AI 上下文防火墙、版本化标准与被动规则 v1 — 当前说明

> 实现核查日期：2026-07-29。规则命中和 AI 输出都是待验证假设；本阶段不产生自动确认或主动攻击。

## AI 凭据与 provider 边界

- SQLite 只保存 provider ID、名称、Base URL、模型和能力等非敏感元数据。
- API Key 通过 `SecretStore` 写入 Windows Credential Manager、macOS Keychain 或 Linux Secret Service；`get_all_settings` 只返回 `has_api_key` 状态。
- 通用设置接口拒绝敏感 key 和嵌套秘密字段。应用启动会运行 `validate_no_plaintext_settings`，检测到旧式明文秘密时直接失败，不回退为前端明文。
- 已保存 provider 的模型列表和模型调用都由 Rust 后端从 `SecretStore` 读取秘密；新增 provider 可通过专用 IPC 用表单 Key 预览 `/models`，该 Key 仅用于当次请求且不落库。前端编辑框不会回显已保存 Key。
- 错误输出先经过秘密过滤，避免 Authorization、API Key、私钥 PEM 或已知 secret 出现在日志。

## AI 上下文防火墙

`src-tauri/src/ai/context.rs`、`redaction.rs` 和 `validation.rs` 共同定义实际发送边界：

- 默认遮盖 URL 查询值、Authorization/Cookie/Set-Cookie 等敏感 Header、JSON/表单/multipart 中的秘密字段、常见凭据格式和高熵值。
- 默认不发送已截断、二进制或解码异常正文；这三个放宽开关相互独立。
- 安全默认上限：请求正文 8 KiB、响应正文 12 KiB、总上下文 32 KiB。
- 后端硬上限：请求正文 24 KiB、响应正文 24 KiB、总上下文 64 KiB；总上下文下限为 16 KiB。
- 超过默认上限、关闭遮盖或包含异常正文都属于 relaxed policy，前端必须额外确认。
- HTTP 数据放入 `UNTRUSTED_HTTP_DATA` 标记区，潜在闭合标记会被转义；提示词替换只扫描模板本身，不会二次展开流量里的占位符。
- 预览展示 system/user/retry 消息、provider、模型、可选 JSON Schema、脱敏清单、可引用 evidence refs 和最终 SHA-256 `input_hash`。
- 真正发送前，后端从数据库重新构建上下文并比较 hash；流量、provider、模板或 policy 变化会使旧预览失效。

## 模型输出与 AnalysisRun

- 内置分析提示词 ID 为 `rustforge.traffic-analysis`，当前 builtin version 为 3；自定义模板采用 append-only 版本历史，支持复制、回滚和恢复内置版本。
- 模型最多返回 4 个假设。结构化校验拒绝未知字段、非法严重度、越界长度、未知标准引用和伪造 evidence ref。
- 不支持 provider-side JSON Schema 时仍执行同一套本地校验；首次失败只使用固定 retry 消息重试一次。
- 每次得到模型响应都会写入 `analysis_runs`：provider/Base URL、模型、提示词版本、输入 hash、policy、脱敏 manifest、token、Schema 模式、校验结果和原始输出 hash。
- 校验失败的 AnalysisRun 可审计，但不能创建 AI Finding；通过的假设仍以 `pending` 状态开始。
- AnalysisRun Evidence 只证明模型调用和校验过程，`qualifies_for_confirmation = false`，不能单独支撑 confirmed。

## 版本化安全标准

`src-tauri/src/knowledge/packs/` 内置六个离线包：

| framework | 固定版本 |
|---|---|
| OWASP Top 10 | 2021、2025 |
| OWASP API Security Top 10 | 2023 |
| OWASP ASVS | 5.0.0 |
| OWASP WSTG | 4.2 |
| MITRE CWE | 4.20 |

引用身份固定为 `{ framework, version, id }`。包包含来源 URL、发布日期、许可和内容 SHA-256；启动时校验 schema、元数据、内容 hash、编号与交叉引用。相同编号在不同标准版本中保持不同身份，未知版本不会被强制映射到 2021。

## 声明式被动规则 v1

- 内置包 `builtin@1.0.0` 包含 14 条规则，定义位于 `src-tauri/src/rules/packs/builtin-v1.json`。
- schema 只允许从已捕获 HTTP 字段选择数据，并使用 equals/contains/regex/exists/missing/数值比较/all/any/not/for_each；没有脚本、文件、进程、网络或任意 action。
- 支持 method、URL、query、请求/响应 Header、Cookie、正文、status、content type，以及 text/query/form/受限 JSONPath/cookie/JWT metadata 提取器。
- 包加载时严格校验 schema version、唯一 rule ID、标准引用、条件深度、提取器兼容性和正则预算；坏包整体禁用并暴露脱敏原因。
- 代理先完成短事务落库，再把 `{project_id, traffic_id}` 投递到容量 256 的非阻塞队列。队列满时保住网络转发并记录 dropped 诊断，不在代理热路径同步跑规则。
- 单包单流量求值预算为 50 ms；候选数、JSONPath 深度、正则源码/程序/DFA 和证据片段均有硬上限。
- 命中证据默认脱敏；若正文截断，命中标记为 incomplete，置信度最高 40。
- 所有命中都可补写 traffic tag；只有 medium/ high/ critical 命中升级为 pending Finding。
- Finding 指纹由项目、rule ID、method、规范化 host、无查询 path 和 field path 组成；规则补丁版本不参与身份，版本保存在独立命中审计中。
- `(traffic_id, pack_id, pack_version)` 是求值幂等键；规则再次命中同一身份只追加流量/命中关系，不覆盖人工 status。

完整格式与预算见 [architecture/rule-pack-v1.md](architecture/rule-pack-v1.md)。

## 前端交互

- AI 分析前必须先打开上下文预览；发送后可查看对应 AnalysisRun 审计。
- Findings 页面区分 AI/规则来源，展示版本化标准、规则命中、关联流量、Evidence 和不可变复核时间线。
- 设置页管理多个 provider、系统凭据状态、脱敏 policy、提示词版本、token 用量和趋势。
- 规则诊断展示包加载状态、队列 submitted/completed/dropped、超时/失败、最近求值和 worker 状态。

## 自动验证

测试覆盖结构化脱敏、提示注入标记、上下文 hash 失效、Schema 与本地校验、无效输出不建 Finding、秘密不进入设置/日志、知识包 hash 与版本查找、规则恶意 JSON/正则/深度/候选预算、截断置信度、后台队列和稳定指纹。

复现命令：

```text
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
cargo test --manifest-path src-tauri/Cargo.toml --test rules_pack
pnpm check
```

## 手工验收

1. 添加 provider 与 Key，保存前确认可获取模型和测试连接；取消后确认 Key 未配置，再保存并确认 UI 只显示“系统凭据库：已配置”，不回显 Key。
2. 抓取一条包含查询参数、Cookie 和 JSON 密码字段的授权流量，打开 AI 预览，确认这些值已遮盖。
3. 尝试包含截断正文或提高默认上限，确认 UI 要求 relaxed policy 二次确认。
4. 发送后查看 AnalysisRun 的 provider、提示词版本、input hash、manifest 和 validation 状态。
5. 查看规则诊断与命中详情，确认规则 Finding 初始为 pending，重复流量不会创建重复身份。

## 已知限制

- AI 质量取决于脱敏后上下文和所选 provider；grounding 通过也只表示引用了已发送字段，不表示漏洞成立。
- 当前只加载内置规则包；没有第三方规则安装、签名市场或热更新入口。
- 规则只分析已捕获的有界快照，无法从截断片段推断完整正文。
- 当前黑盒 HTTP 流程不读取源码；源码辅助模式属于后续独立设计。
