# Phase 6 · 目标驱动的可信工具任务系统 — 当前说明

> 实现核查日期：2026-08-03。当前主界面是 Assessment Mission v2；SQLite v3 的固定轮次 run 继续作为真实网络执行与 Evidence 层，并以只读 legacy mission 暴露。Phase 3 的 `task_nodes` 只保留历史兼容，不会被重新激活。

## 产品定位

RustForge 将一次性评估升级为可暂停、可追问、可审批和可恢复的持续任务：

1. 用户给出目标、起始 URL、身份、项目资源、预算档位和权限模式。
2. 后端建立 mission 契约、工具与权限快照，并生成最终脱敏上下文预览。
3. 用户确认上下文后，任务按逻辑 workstream 分解为可解释 action。
4. 后端根据权限矩阵自动执行或等待逐项审批；人工配方获批后也只进入规划器候选集。
5. 只有 AI 在已审批范围内选中具体不透明 surface/参数，且后端再次验证通过，人工动作才进入 `manual_ready`。
6. 真实请求仍由 v3 runner 串行执行，并由固定版本验证器产生事实结论。
7. 用户可中途追问或改变目标；当前单请求安全结束后，下一规划点读取新消息。
8. Report Schema v4 汇总目标、资源、权限、审批、动作、人工接力、成本、覆盖和 Evidence。

未选择项目时，页面直接提供选择/创建入口和 Scope、AI Provider、身份、授权准备清单。任务页采用三栏：历史与工作流、目标对话与动作时间线、Scope/资源/身份/预算/工具权限；窄窗口将右栏折叠为抽屉。

## Mission 状态与恢复

`assessment_missions` 的持久化状态包括：

```text
draft
awaiting_context_approval
queued
discovering / planning / executing / verifying
awaiting_action_approval
awaiting_manual_handoff
completed / stopped / cancelled / failed / interrupted
```

- `awaiting_context_approval`、`awaiting_action_approval` 和 `awaiting_manual_handoff` 不占用网络执行器；应用重启后原状态恢复。
- 只有 `discovering / planning / executing / verifying` 是网络活动态；数据库唯一索引保证全局最多一个。
- 进程重启只把上述瞬态任务标为 `interrupted`，不会自动恢复可能产生网络副作用的请求。
- 多个草稿、等待任务和排队任务可同时存在。已有网络任务时，新的 mission 保持可见 `queued`；用户可在执行槽释放后恢复。
- 停止会立刻取消等待，并向活动 run 发送取消信号；已经发出的单请求有明确结果，部分证据继续保留。
- 每次追问写入不可变、脱敏、带 hash 的 message，并设置 `pending_steering`，供下一规划点消费。

## 预算与权限

| 档位 | 目标请求上限 | 最多规划次数 |
|---|---:|---:|
| 快速 | 40 | 2 |
| 标准（默认） | 120 | 4 |
| 深入 | 300 | 6 |

所有档位仍受 2 RPS、单并发、精确 origin、无自动重定向、响应与总字节预算限制。

权限由后端根据 mission 模式、项目级工具覆盖和 ToolSpec 决定，模型不能修改：

| 模式 | 自动范围 | 必须等待 |
|---|---|---|
| 手动 | 本地 `observe` | 每个目标探针；所有人工配方 |
| 智能（默认） | 本地观察、低风险 GET/HEAD/OPTIONS 基线 | 身份差异、JWT、CORS、重定向、反射、IDOR 等受控探针 |
| 自动 | registry 中非破坏 `observe / safe_probe` | 所有 `manual_recipe` |

项目可把单个工具覆盖为 `disabled / ask / execute`。禁用工具不进入模型上下文；人工配方即使被设为 execute，也只能创建草稿，不能自动发送。

## ToolSpec 与规划 DSL

`SafeTemplate` 已扩展为版本固定的 `ToolSpec`，包含：工具 ID/版本、展示信息、`observe | safe_probe | manual_recipe`、风险等级、参数 JSON Schema、身份要求、请求成本、默认权限和验证器能力。registry 与项目权限快照都进入 mission 契约/hash。

模型只能提出：

```text
workstream
tool_id
surface_id / resource_id（后端生成的不透明 ID）
已登记的 parameter_name
identity_mode
rationale
expected_signal
```

模型不能输出 URL、HTTP 方法、Header、正文、payload、脚本、Shell/SQL 或漏洞结论。未知工具、禁用工具、伪造 surface/resource/参数、过期 revision、权限/Scope/provider/身份/registry 漂移均在建连前 fail closed。

每个 action 持久化并展示：执行理由、预期观察、工具和版本、执行类型、风险、请求成本、权限快照、审批来源、状态，以及展开后的脱敏请求/响应与 hash。action 与旧 `assessment_checks` 通过关联表连接，不复制 Replay、verification 或 Evidence。

## 发现、surface 与上下文

发现仍不执行 JavaScript、不提交表单、不主动发送 POST。新增能力包括：

- 使用标准 HTML5 解析器收集 anchor、form action/method、input 名称/类型、同源 script/resource。
- 对同源脚本文本做有界静态路由候选提取；候选仍须经过 origin、Scope、方法和危险路径校验。
- 导入有界 OpenAPI JSON/YAML；renderer 只获得原生选择器返回的单个路径，后端重新检查扩展名、大小和结构。
- 复用同项目 Traffic、Finding 和历史评估的不可变脱敏摘要。
- 聚合匿名/身份 A/B 可见性与响应结构，不把完整 URL 暴露给模型。

稳定 surface 由方法、规范化路径形状、参数名、表单字段、内容类型、身份可见性、响应结构 hash 和来源组成。完整 URL 只留在后端执行层；POST/PUT/PATCH/DELETE surface 可以被登记为覆盖信息，但 `safe_to_request = false`，任务执行器不会发送。

AI 上下文默认只含脱敏结构摘要、标题/表单/JSON key path、被动标签、少量有界片段、附件摘要和 disclosure manifest。首次调用前必须确认 context hash；资源、数据类别、provider、策略、工具或权限发生漂移后需要重新预览并确认。

## 检测与结论边界

每个完整响应先运行本地确定性基线：Header/Cookie、缓存、CSP/frame、MIME、服务端信息泄露、错误信息、目录列表和 API 文档暴露。新增只读 OPTIONS、匿名/登录可见性差异和 CORS 边界工具；旧六类模板继续保留。

结果分为 `confirmed / suspected / not observed / coverage gap`，按工作流和攻击面聚合。只有版本固定的确定性验证器、完整且语义充分的证据可以自动 confirmed；截断、动态、不完整或语义不足一律降级。模型、人工配方结果和单纯响应差异都不能自动确认。

## 人工 Repeater 接力

SQLi、SSRF、XSS、业务逻辑等类别使用 `manual_recipe`：

1. 审批只授权规划器选择配方；未经模型选择和后端 surface/参数/身份复核，不能创建草稿。
2. 后端从版本化配方生成脱敏 Repeater draft 与 draft hash；创建草稿不发送请求。
3. 草稿绑定一个同项目、`owner_kind = manual` 的独立 Repeater session。
4. Repeater 显示来源 mission/action、配方版本和“必须用户点击发送”的提示。
5. 只有用户点击 Repeater 的普通发送按钮，才会再次经过 Scope 并产生 ReplayRun。
6. 只有同项目、同 handoff/session 的 ReplayRun 可以回传；回传只创建默认未接受的 Evidence，等待人工复核。

Assessment 内部 session 继续与手动 Repeater 隔离；任何 action/AI API 都不能代替用户点击发送。

## API、事件与报告

Mission IPC 包括创建/列表/详情、上下文预览与确认、项目资源/OpenAPI、开始/恢复、追问、停止、action 决策与详情、单工具权限、人工 handoff、ReplayRun 回传，以及 mission 报告预览/导出。

`assessment:mission-event` 使用以下 envelope：

```text
projectId + missionId + runId? + actionId? + revision
eventType + status + phase + message + budget progress + occurredAt
```

前端同时校验 workspace ownership 与 revision，丢弃旧项目、重复和过期事件；事件遗漏时从持久化 detail 恢复。

Report Schema v4 默认且仅导出脱敏数据，新增目标、资源摘要、工作流、ToolSpec/权限 manifest、审批轨迹、动作结果、人工接力、请求/Token 成本与覆盖矩阵。旧 run 仍可用 Schema v3 导出；legacy mission 的 v4 报告明确包含 `legacy: true`，不会伪装成 v2 编排。

## 明确不覆盖

- 任意 Shell、浏览器利用、JavaScript 执行、自动修复、多 Agent 或并行目标请求。
- SQL/命令注入、目录穿越、SSRF、上传、爆破、DoS 和业务写操作的自动发送。
- 模型自行扩大 Scope、判断权限、构造 HTTP 请求或确认漏洞。
- 自动恢复崩溃前的网络动作；只恢复安全等待态和只读任务记录。

## 参考定位

实现定位在 2026-08-03 重新核查：采用 [Burp AT](https://portswigger.net/burp/documentation/desktop/burp-at) 的项目任务、资源附件、工具权限与动作追踪思路；采用 [PentestGPT v1.0](https://github.com/GreyDGL/PentestGPT) 的阶段化分解与会话恢复思路；采用 [Strix](https://github.com/usestrix/strix) 的运行可视化和实时引导思路。RustForge 不继承它们的任意执行、自主利用、多 Agent 攻击或自动修复能力。

## 修改同步清单

任何 mission/tool/action 字段或关系变更必须在同一任务中同步：

1. v4 后续迁移、`LATEST_SCHEMA_VERSION`、完整结构/FK/trigger validation 与迁移前备份。
2. Rust 模型、ToolSpec registry/hash、service 事务、等待/中断恢复和无 socket 拒绝测试。
3. Tauri commands、`assessment:mission-event` 与 `src/api/tauri.ts` 类型。
4. Pinia workspace ownership、任务对话 UI、审批/详情/人工接力与 legacy 只读适配。
5. Report v4、秘密编码变体扫描、跨项目/过期 revision/漂移/并发审批测试。
6. 本文、[数据模型](architecture/data-model.md)、[安全边界](architecture/security-boundaries.md) 与 [授权说明](AUTHORIZATION.md)。
