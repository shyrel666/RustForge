# Phase 6 · AI 引导式非破坏安全评估 — 当前说明

> 实现核查日期：2026-08-01。Phase 6 用独立 Assessment 领域替换 `/tasks` 主界面；Phase 3 的文字测试计划保留为隐藏兼容数据，不参与执行。

## 产品入口与运行模型

用户不再需要先抓代理流量或手工维护任务树：

1. 填写已授权的 HTTP(S) 起始 URL。
2. 可选配置身份 A/B、资源归属、额外排除路径、Traffic 种子、TLS 和预算。
3. 审阅精确 origin、只读动作、最大请求数、速率、身份标签、AI provider/披露策略、模板 registry 与残余风险。
4. 确认书面授权并以 contract hash 启动后台 run。
5. 查看发现、规划、执行、验证时间线，或取消并保留部分结果。
6. 按已确认、疑似、未观察到、覆盖缺口查看结果并导出单 run 报告。

`AssessmentManager` 是 `AppState` 的全局运行管理器。全局最多一个活动 run，目标请求并发固定为 1；IPC 只负责快速创建持久化 run 和后台任务，不等待完整评估。启动恢复把遗留活动 run 标为 `interrupted`，不会继续网络动作；活动 run 会阻止项目删除。

## 运行契约与后端策略

`preview_assessment_contract` 不访问目标，返回规范化预览和 SHA-256。`start_assessment` 会从数据库和当前 registry 重建预览，hash 不一致即拒绝。契约绑定：

- 项目和规范化 Scope。
- 起始 URL 与精确 `scheme://host:effective-port`。
- 内置/自定义排除路径、TLS、请求/速率/响应预算。
- identity profile ID、秘密修订和 endpoint 资源归属。
- provider/model、披露策略、最多三轮。
- 安全模板 registry 的版本和 content hash。

每次目标请求都再次检查 `AssessmentPolicy + ScopePolicy`：

- 只允许无正文 `GET / HEAD / OPTIONS`。
- 只允许精确 origin；不自动跟随重定向。
- 拒绝危险路径段、重复编码后的破坏性 action/method override、禁止 Header 和用户额外排除项。
- 默认 1 RPS/120 次，硬上限 2 RPS/300 次；发现预算最多 `min(40, budget/3)`。
- 单响应 1 MiB、整轮响应预算 20 MiB；不完整内容无自动确认资格。
- 429、连续三个 5xx/超时、Scope/身份/AI/registry 漂移、取消都会停止；目标请求不自动重试。

取消 token 同时中断 AI/HTTP 等待。已经写入 attempt 的请求会得到明确取消结果；开放 check 被终结并写事件。

## 发现与 AI 规划

发现从起始 URL 开始，只解析 HTML `a[href]` 与同源 redirect：不执行 JavaScript、不加载资源、不提交 form，也不主动读取 sitemap/robots。可选 Traffic 种子只接受同 origin 的唯一 GET/HEAD，不复用 Header、正文或状态变更请求。

AI 看到的数据只有不透明 endpoint ID、路径、query 参数名、状态、Content-Type、鉴权存在性与被动标签。query 值、凭据、正文和原始响应不发送。

每轮最多 12 个 check，最多三轮。DSL 只允许：

```text
template_id
endpoint_id
parameter_name（可选）
identity_mode（anonymous/a/b/a_vs_b）
rationale
```

模型不能输出 URL、方法、Header、正文、payload、shell、SQL、JavaScript、状态或漏洞结论。后端对未知字段、长度/枚举、伪造 endpoint/template、参数不匹配、重复 check 和预算执行 fail closed；被拒选择仍持久化，但不产生 socket。HTTP 元数据放在转义的 `UNTRUSTED_HTTP_DATA` 中，JSON Schema 可用时启用，失败只固定重试一次。每轮输入、manifest、usage、AnalysisRun 和输出 hash 均可审计。

## 模板 registry 与验证器

首版 registry 固定六类模板：

| 模板 | 固定动作 | 结论边界 |
|---|---|---|
| Header/Cookie | 复用发现响应 | 完整且适用时可确认事实性缺失 |
| 凭据型 CORS | `.invalid` Origin 的 GET/OPTIONS | 完整成功基线/探针，反射 Origin 且 credentials 才确认 |
| JWT 完整性 | A、匿名、签名破坏、`alg=none` | 所有响应完整，匿名拒绝且无效 JWT 与 A 严格等价才确认 |
| Open Redirect | 已知参数替换为 `https://rf-probe.invalid/...` | 不跟随跳转，Location 精确指向 probe 才确认 |
| 惰性反射 | query 放纯字母数字随机 marker | 只产生 suspected，首版不确认 XSS |
| A/B 只读越权 | 同一 GET 分别使用 A/B | 已声明资源仅属于 A，完整非空 2xx 严格等价才确认 |

SQL/命令注入、目录穿越、SSRF、上传、爆破、DoS、POST/form、浏览器执行等不主动测试，进入 coverage gap。

## 身份与 Replay 隔离

- profile 只允许四种鉴权 Header，合计不超过 16 KiB；可从 Traffic 导入或粘贴 Header。
- 导入前可用 `list_assessment_auth_candidates` 扫描最近 Traffic（最多 300 条），列出包含所选 Header 的候选请求；只返回方法/URL/状态/时间元数据与存在性（值必须非空、≤16 KiB、无换行才可导入，与 `validate_auth_secret` 一致），Header 值只在用户选中后由 import 提取写入系统凭据库。候选 URL 可能含 query token，其可见范围与抓包页一致，且该命令不进入 AI 上下文。
- secret 值只存 OS credential backend，SQLite/API 只返回 label、Header、revision 和 `has_secret`。
- A/B 必须为不同 profile，并在内存比较拒绝相同 secret。
- live Header 和 audit Header 是不同结构：目标收到真实凭据，attempt、ReplayRun、事件、错误、AI、hash 与报告只看到 `[AUTH_PROFILE:<id>]`。
- Assessment replay session 标记为 `owner_kind = assessment`，手动 Repeater API 只允许 `manual`。
- 不保存用户名/密码、不提交登录、不自动更新 Cookie；写入/删除凭据失败有 metadata 回滚或补偿清理。

## Evidence、Finding 与报告 v3

`commit_verification_outcome` 在一个事务内写不可变 verification，创建/复用安全验证器 Finding，创建脱敏 Replay Evidence，按 verdict 接受或保持未接受，追加 Finding 事件并更新状态；runner 随后发出既有 Finding 事件。

- confirmed 才能以 `safe_verifier:<template>@<version>` 接受 Evidence。
- suspected/inconclusive 保持 pending；模型 Analysis Evidence 没有自动确认权。
- 人工 rejected 不复活，只记录冲突；confirmed 不因后续未观察到降级。
- 人工可把自动确认重置为 pending，再撤销验证器 Evidence。

Evidence Report Schema v3 增加四类结果、运行契约/registry hash、AI rounds、预算、身份标签、停止原因和时间线。可指定 run，也可生成项目累计 Finding并附最近终态覆盖。`requires_human_review` 由确认来源决定；默认导出继续只使用 hash 校验过的脱敏快照。旧 task tree 只作为 legacy appendix。

## 前端与公共接口

`/tasks` 现在加载 `AssessmentView.vue`，导航标题为“AI 评估”。独立 Pinia store 使用 `project_id + selected run_id` 过滤/去重 `assessment:progress`，项目切换丢弃旧 Promise/事件，并从 `get_assessment_detail` 恢复遗漏进度。

主要命令：

- profile：`list/create/set/import/delete_assessment_auth_profile`、`list_assessment_auth_candidates`
- contract：`preview_assessment_contract`
- run：`start/cancel/list/get_assessment_*`
- event：`assessment:progress`
- report：`build_report/export_report` 的可选 `assessment_run_id`

Home 默认继续路径改为 AI 评估并显示最近 run 状态与 confirmed/suspected 数；Findings 标识 `safe_verifier` producer、自动确认和 verification provenance。

## 自动验证

测试覆盖迁移与 DB 不变量、策略拒绝无 socket、真实凭据只到 mock target、重定向/节流/停止/字节上限/取消/崩溃恢复、提示注入与伪造 DSL、六类模板边界、Evidence 原子确认、前端事件隔离以及 Report v3 确定性与 secret redaction。

复现门禁：

```text
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
pnpm check
```

## 残余风险与明确不覆盖

- HTTP 规范中的 GET/HEAD/OPTIONS 是只读意图，不是目标实现无副作用的证明；错误服务器仍可能在 GET 修改状态。
- TLS `ignore_invalid` 必须在单次契约显式开启，不能证明对端身份。
- 自动确认只说明当前版本模板的确定性条件成立，不等于完成所有漏洞类别、源码路径或业务语义审计。
- 不完整响应、缺少身份/归属、预算耗尽与所有主动排除类别必须保留为覆盖缺口，不能写成“安全”。
