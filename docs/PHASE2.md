# Phase 2 · AI 分析引擎 + 被动规则引擎 — 完成说明

## 交付内容

**被动规则引擎（src-tauri/src/rules/）**
- `engine.rs` — Rule/TrafficView/RuleHit 抽象，5 类匹配目标（url/请求头/请求体/响应头/响应体），
  支持反向条件（`must_absent`，如 Set-Cookie 缺少 HttpOnly）
- `builtin.rs` — 14 条内置规则，每条带：描述、验证提示、严重度、标签、OWASP/CWE、**诚实置信度（50-90）**：

  | id | 严重度 | 说明 |
  |---|---|---|
  | sql-error-leak | high | 响应含 MySQL/ORA/PostgreSQL/SQLite 报错 → SQL 注入线索 |
  | stack-trace-leak | medium | Python/Java/.NET/Laravel/Django 堆栈泄露 |
  | debug-actuator-endpoint | medium | actuator/metrics/debug 运维端点 |
  | sensitive-file-access | medium | .git/.env/.bak/.sql 等敏感文件 |
  | path-traversal-param | medium | ../ 及编码变体参数 |
  | sensitive-param-in-url | medium | URL 携带 token/password/api_key |
  | cors-wildcard / cookie-no-httponly / cookie-no-secure | low | 配置类问题 |
  | jwt-exposed / password-in-request-body / admin-console-path / server-version-leak / internal-ip-leak | info/low | 观察点 |

- 接入拦截器：每条流量落库后同步跑规则（<10ms），标签写 `traffic.rule_tags`，
  **中危及以上自动生成 source='rule' 的待验证 Finding** 并推 `finding:new` 事件

**AI 分析引擎（src-tauri/src/ai/）**
- `client.rs` — OpenAI 兼容客户端（reqwest + rustls）：120s 超时；
  结构化错误区分 Retryable（网络/5xx，重试一次）与 Fatal（4xx，立即失败不浪费额度）
- `prompts.rs` — 模板系统：占位符 `{METHOD} {URL} {HOST} {STATUS} {REQUEST} {RESPONSE} {RULE_TAGS}`；
  内置中文教学模板；**去敏红线**：authorization/cookie/x-api-key 等凭据头打码后才发给 LLM，
  body 截断 6000 字符
- `analyzer.rs` — 结构化输出：`{purpose, suspicious_params[], hypotheses[{vuln_type, param,
  owasp, cwe, severity, confidence, reasoning, verify_steps}], summary}`；
  解析容错（剥围栏/截取 JSON）+ 失败重试一次 + **confidence 钳位 0-100 +
  缺 reasoning/verify_steps 的假设强制剔除**（误报素养硬约束）
- 结果落 `analyses` 缓存表（不重复烧 token），每个假设生成 source='ai' 的待验证 Finding

**命令（新增 10 个）**
`analyze_traffic / get_analysis / list_findings / update_finding_status / delete_finding /
get_prompt_template / set_prompt_template / reset_prompt_template`
（`analyze_traffic` 前置红线检查：`ai_enabled=false` 拒绝、无 API Key 给清晰报错）

**前端**
- 流量详情抽屉新增「🤖 AI 分析」页签：先读缓存，按钮触发分析，结构化展示
  （用途/可疑参数/假设卡片：严重度+置信度条+OWASP/CWE+推理+验证步骤 Markdown 渲染）
- 流量表格新增「标签」列（规则命中徽标）
- FindingsView 完整实现：状态/严重度/来源过滤，展开行看推理+验证步骤，
  ✓确认 / ✗误报 / ↺重置 状态流转，实时接收新 Finding
- 设置页新增提示词模板编辑器（保存/恢复默认，占位符说明）

## 测试（cargo test 15/15 通过）

- 规则引擎：SQL 报错命中、JWT+敏感参数命中、Cookie 缺标志命中、无害流量不误报
- 分析器：干净 JSON 解析、围栏/噪音 JSON 容错、缺验证步骤假设剔除、解析失败恰好重试一次（mock 客户端）
- 提示词：凭据头去敏、长 body 截断、占位符渲染
- 修复过程中被测试抓出的两个真 bug：规则漏配 `?token=`、raw string 转义问题

## 手工验收（对应 Phase 2 验收标准）

1. 设置页确认 API Key/Base URL/模型（如 DeepSeek），保存
2. 抓一段目标登录请求（POST 带用户名密码）
3. 流量表格点该行 → 详情抽屉 → 「🤖 AI 分析」→ 开始分析
4. 应看到：接口用途、可疑参数、漏洞假设（含 OWASP 分类 + 置信度 + 推理 + 验证步骤）
5. 「发现」页出现对应待验证 Finding，按验证步骤人工复核后标记确认/误报

## 已知限制（后续 Phase）

- 响应体为 gzip/br 时按原字节存储，AI 看到的也是乱码——详情页解码预览列入 Phase 4 前修
- 任务树规划器（Phase 3）会复用本阶段的 client/prompts 基础设施
- token 用量统计在 Phase 5
