# Phase 3 · 版本化测试计划 — 当前说明

> Phase 3 最初交付的是静态 PTT。2026-07-28 完成 Task 5.2 后，产品与文档统一称为“测试计划”；旧开发态 task node 不做迁移，开发数据库需按当前 v1 schema 重建。

## 交付内容

**测试计划模型、状态机与合并服务（`src-tauri/src/tree/`）**

- `model.rs`：`TestPlan`、`TaskNode`、`TaskPlanProposal`、`TaskPlanDiff`、revision/event 和人工编辑输入模型。
- 节点类型：`hypothesis / test / decision / manual_note`。
- 状态：`todo / in_progress / done / blocked / skipped / not_applicable`；blocked、skipped、not_applicable 必须填写原因。
- 节点保存 stable key、priority、所需角色/会话、预期/实际观察、来源、字段锁、Finding、Evidence、标准引用、parent 与 prerequisite。
- `state.rs`：白名单状态流转、三层/40 节点预算和确定性“下一步”排序。未满足 prerequisite 的节点不会成为下一步；候选按风险、priority、Evidence 缺口、创建时间和 id 排序。
- `service.rs`：生产环境唯一计划写入边界。人工创建/编辑/状态/归档及 proposal 合并都创建 revision 和 append-only 事件。

**AI 规划器（`src-tauri/src/ai/planner.rs`、`digest.rs`）**

- `generate / expand / alternative` 都只创建持久化 proposal 与 diff，不直接改写节点。
- diff 分为新增、更新、保留和归档；用户确认后才在一个 immediate transaction 中合并。
- stable key 用于跨 revision 对齐。人工节点、人工进度、字段锁和已关联 Evidence 的节点受保护；归档是软归档，不删除历史关系。
- 当前计划 revision、key、类型、状态、priority、来源、锁、Evidence 数和 prerequisite key 会进入经过脱敏和长度限制的规划摘要；actual observation 与 Evidence 内容不会发送。
- 新 Evidence 到达只设置“计划可更新”并使未确认的旧 proposal 失效，不自动调用 AI 或推进节点。
- 产出仍受深度 ≤ 3、活动节点 ≤ 40、标题/枚举/标准引用/Finding 白名单约束。

**Tauri 命令与前端**

- 读取：`get_task_tree / get_test_plan / list_task_plan_events / next_task / get_task_findings`。
- AI：`preview_task_ai / generate_task_tree / expand_task_node / alternative_task_node`，返回 proposal 而非受影响节点数。
- 确认：`apply_task_plan_proposal / reject_task_plan_proposal`。
- 人工操作：`create_task_node / update_task_node / update_task_status / delete_task_node`；最后一个命令保留 IPC 名称，但语义为可审计归档。
- “测试计划”页用 vue-flow 展示 parent 实线和 prerequisite 虚线，并展示 revision、更新标记、节点类型/来源/priority、Finding/Evidence、预期/实际观察、状态原因和字段锁。
- `TaskPlanDiffDialog.vue` 在人工确认前逐项展示新增、更新、保留和归档。AI 预览确认只发起模型调用，不等于确认计划变更。

## 测试

- proposal 重复应用幂等；重新规划保留人工节点、进度、锁、备注和 Evidence。
- AI 只更新未锁字段；Evidence 到达不改节点，并使旧 proposal 变为 `superseded`。
- 特殊状态缺少原因会被应用层和数据库约束拒绝；状态直写必须具有匹配审计事件。
- prerequisite 不满足时不会推荐；风险/priority/Evidence 缺口/时间排序稳定。
- 文件数据库关闭重开后，parent、prerequisite、状态、原因和 revision 保持一致。
- 当前完整门禁：Rust `189` 个单元测试、`4` 个 MITM 集成测试、`8` 个规则包验收测试；前端 `27` 个测试、TypeScript 检查与生产构建通过。

## 手工验收

1. 在“流量”页抓取已授权目标流量，并产生可选 Finding/Evidence。
2. 在“测试计划”页点“AI 生成测试计划”并确认 AI 上下文预览。
3. 查看 proposal diff；确认前当前计划不发生变化，确认后 revision 增加。
4. 人工创建备注、修改状态或锁定字段后再生成更新 proposal，确认这些内容出现在“保留”或不被更新。
5. 为节点或 Finding 新增 Evidence，确认页面只提示“测试计划可更新”，旧 proposal 不能再应用。
6. 设置 prerequisite 后点“下一步”，确认依赖未终结的节点不会被定位。

## 已知限制

- 当前是 parent + prerequisite 的测试计划，不是带 AND/OR 门的攻击树。
- 布局为确定性分层图；活动节点硬上限 40，历史节点通过软归档保留。
- 规划质量仍取决于脱敏后的流量/Finding 摘要和所选模型；所有执行与合并保持人在回路。
