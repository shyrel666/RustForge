# Phase 4 · Repeater、Evidence、人工复核与证据化报告 — 当前说明

> 实现核查日期：2026-08-01。本阶段的手动 Repeater 与人工 Evidence 闭环继续保留；Phase 6 另增隔离的 Assessment replay 和版本化安全验证器，不能把模型建议包装成已执行结果。

## Repeater 工作区

### 会话与 TLS 策略

- 每个项目可持久化多个 `replay_sessions`，保存标题、来源流量、选中状态和 TLS policy。
- TLS policy 为 `strict` 或 `ignore_invalid`；后者适合授权测试环境，但由会话显式保存，不能等同于安全连接证明。
- Repeater 不自动跟随重定向，30 秒超时；`Host` 和 `Content-Length` 交由客户端按实际请求生成。
- UI 从 Traffic “发送到 Repeater”时创建或更新项目内会话，不跨项目复用草稿或异步结果。

### 发送前授权与副作用审计

- 每次发送都携带 `project_id + session_id`，后端重新加载会话和项目 Scope。
- `ScopePolicy::authorize_url` 在创建 HTTP 客户端、解析用户 Header 和建立 socket 前执行；返回的规范化 URL 是唯一可用于网络请求的 URL。
- Scope 拒绝、非法 method/header/body/URL 和请求失败都会保存结构化 run 与稳定错误码；Scope 拒绝路径不会建立网络连接。
- 对允许的请求，`replay_attempts` 在网络副作用发生前提交；正常结束后由不可变 `replay_runs` 引用。
- 应用异常退出留下的 attempt 会在下次启动恢复为 `request_failed / APP_INTERRUPTED`，防止“请求可能已发出但没有审计结果”。有 in-flight attempt 时不能删除会话或项目。

### 不可变 run、捕获与比较

- run 保存请求输入快照、实际 wire request、Scope 判定、TLS policy、outcome、错误、响应、耗时及请求/响应 hash。
- 请求与响应复用代理的 1 MiB wire/decoded 捕获语义，保存截断和 decode status；大响应仍流式读取，历史只存有界快照。
- 重复 Header 以有序 name/value 数组保存；请求输入文本/base64 歧义会明确拒绝。
- run 只能随所属会话/项目生命周期级联删除，不能单独更新或删除。
- 历史默认每页 50、最大 200，使用 `before_id` 游标。
- diff 比较 method、URL、Header、请求/响应正文、TLS、Scope、outcome、status 和耗时。完整 hash 不可得或正文截断导致无法断言相等时标记 `indeterminate`，不伪装成“相同”。

## Evidence 与 Finding 状态机

### Evidence 来源与快照

Evidence 可从三类来源创建：

| 来源 | 快照内容 | 可支撑 confirmed |
|---|---|---|
| `traffic` | 脱敏 URL/Header/body、请求/响应状态和捕获元数据 | 仅实际收到 HTTP 响应时可以 |
| `analysis_run` | provider、模型、提示词、input hash、policy、manifest、validation、usage | 永远不可以；仅作 provenance/audit |
| `replay_run` | 脱敏请求/响应、Scope/TLS/outcome、捕获元数据和 hash | outcome 为 completed/response_incomplete 且有响应状态时可以 |

- Evidence 正文最多 8 KiB、Header 4 KiB、URL 4 KiB；观察文字和 actor 也有长度上限。
- 创建时生成不可变脱敏 JSON 快照和 SHA-256；原始来源删除后，Evidence 的来源 ID、快照和 hash 仍保留，读取时单独计算 `source_available`。
- Evidence 本身不可更新；“接受”是 Finding 与 Evidence 关系上的判断，同一 Evidence 可被不同 Finding 独立接受。来源为 `human` 时沿用本节交互；来源为 `safe_verifier` 时必须绑定 Phase 6 的 immutable verification 与同 check ReplayRun。

### 确认约束与事件

- 新 Finding 必须从 `pending` 开始；`confirmed` 需要至少一条人工或版本化安全验证器接受且 `qualifies_for_confirmation = true` 的 Evidence。
- 接受/撤销 Evidence、状态、严重度和 analyst notes 的变化必须先写入匹配的 append-only `finding_events`，再在同一事务更新当前状态。
- rejected 必须提供原因；confirmed 的最后一条合格 Evidence 不能被撤销。
- AI/规则来源、分析 run、关联 traffic、规则 evaluation/hit、Evidence 和人工事件分别保存，报告不从当前 `updated_at` 反推历史。
- 给 Finding 或任务新增 Evidence 会把测试计划标为可更新并 supersede 旧 proposal，但不会自动调用 AI 或推进状态。

## 版本化知识卡片

- 知识卡片来自六个启动时校验的离线包，而不是把模型给出的标题直接当标准事实。
- `StandardReference` 的 framework/version/id 必须精确命中包；卡片标题、原理、影响、成因、修复建议、来源、发布日期和许可由固定版本派生。
- Findings 页面显示标准卡片；报告的修复建议也复用同一 registry。

## Evidence Report Schema v3

`src-tauri/src/report.rs` 先构建一个确定性的结构化 `ReportDocument`，再从同一对象渲染 Markdown 与 JSON：

1. 授权范围、默认排除语义和测试限制。
2. 不可变时间线、实际使用的方法与工具/Schema 版本。
3. 仅基于 confirmed Finding 的执行摘要和风险分布。
4. Finding 身份、目标、版本化标准、风险、置信度和来源。
5. 建议验证步骤、实际 Evidence 观察和脱敏快照分栏。
6. 修复建议和明确的复测状态。
7. 指定 Assessment run 的 confirmed/suspected/not-observed/coverage-gap，或项目累计 Finding 与最近终态覆盖。
8. 契约/registry hash、AI round、请求预算、身份标签、停止原因，以及人工/验证器 acceptance provenance。
9. 旧测试计划只作为 `legacy_plan_summary`，不声明为已执行。

报告约束：

- 报告明确分 confirmed、suspected、not observed 与 coverage gaps；rejected 只计省略数量，不泄露内容。
- 任一 confirmed 缺少合格、已接受且快照 hash 校验通过的 Evidence 时，整份报告拒绝生成。
- 默认预览与导出只读取不可变脱敏 Evidence，查询值和 Markdown 用户输入会再次转义。
- 每次导出同时创建 `.md` 与 `.json`；使用安全文件组件、`create_new` 和冲突后缀，失败时清理本次半成品，不覆盖已有报告。
- “包含原始敏感 Evidence”只能由该次后端命令弹出的原生模态确认授权；前端不能签发或复用 token，选择不会保存为设置，文件名和正文都会标记 `SENSITIVE`。
- 当前模型没有独立的“修复后复测”实体，因此报告明确输出 `not_recorded`，不会把旧计划 done 或 not observed 当作复测通过。

## 前端交互

- Repeater 页面提供会话、请求编辑、发送、历史分页、run 详情和双 run diff。
- `EvidencePanel.vue` 可从当前项目内 Traffic、AnalysisRun 或 ReplayRun 创建 Evidence、填写观察并执行接受/撤销。
- Findings 页面同时展示关联流量、规则命中、Evidence、状态/严重度/备注和审计时间线。
- 报告预览始终是默认脱敏版本；导出返回 Markdown/JSON 两个路径及敏感标志。

## 自动验证

测试覆盖 Scope 拒绝无 socket、副作用前 attempt、异常恢复、run 不可变/分页/diff、大正文有界捕获、跨项目关系、Evidence 资格、最后合格证据保护、Finding 事件、报告快照、秘密泄漏、Markdown 注入、安全文件名、双文件无覆盖和确定性输出。

复现命令：

```text
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
pnpm check
```

## 手工验收

1. 从一条授权流量创建 Repeater 会话，分别执行成功、失败和 Scope 拒绝的发送，确认历史均有明确 outcome。
2. 对两次 run 做比较，确认变更字段和截断/未知比较状态正确。
3. 从 AnalysisRun 创建 Evidence 并接受，确认仍不能把 Finding 改为 confirmed。
4. 从有真实响应的 Traffic 或 ReplayRun 创建 Evidence，填写观察并人工接受，再把 Finding 改为 confirmed。
5. 生成报告，确认 confirmed、suspected、not observed、coverage gap 分组清晰，rejected 不进入事实结论，并同时导出 `.md`/`.json`。
6. 请求敏感导出，确认出现后端原生警告，取消后不生成文件。

## 已知限制

- 手动 Repeater 只执行用户触发的单次 HTTP 请求；Phase 6 Assessment 使用独立、不可由手动 API 访问的 session 执行内置只读模板。两者都没有 WebSocket、自动会话跟随或爆破。
- TLS `ignore_invalid` 只适合明确授权的测试环境，不能证明对端身份。
- Evidence 快照是有界脱敏证据，不等于完整取证镜像。
- 报告首要格式为 Markdown + JSON；当前不导出 PDF/HTML，也没有独立复测工作流。
