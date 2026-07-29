# Phase 3 · 证据驱动的版本化测试计划 — 当前说明

> 实现核查日期：2026-07-29。Phase 3 最初交付的是静态 PTT；当前产品统一称为“测试计划”。预发布阶段不迁移旧开发态 task node，数据库必须符合当前 v1 基线。

## 当前模型

`src-tauri/src/tree/` 是唯一生产写入边界：

- 每个项目只有一个 `TestPlan` 头，保存当前 revision、`needs_update`、原因和最后应用的 proposal。
- 节点类型为 `hypothesis / test / decision / manual_note`。
- 节点状态为 `todo / in_progress / done / blocked / skipped / not_applicable`；后三种状态必须提供原因。
- 节点保存 stable key、priority、所需角色/会话、预期/实际观察、标准引用、来源、字段锁、Finding、Evidence、parent 和 prerequisite。
- parent 表达结构分组，prerequisite 表达执行依赖；数据库拒绝跨项目关系、自依赖、环和指向已归档节点的新增依赖。
- 所有人工创建、编辑、状态变化、归档和 proposal 合并都会增加 revision 并追加 `task_plan_events`；状态不能绕过匹配事件直接写入。

## AI proposal，而不是直接改计划

`generate / expand / alternative` 的共同流程：

1. 后端从数据库构建脱敏、有界的项目摘要，并把当前 revision 纳入输入 hash。
2. AI 只能返回允许的 proposal 字段，不能返回数据库 ID、status、actual observation、Evidence 内容或执行结果。
3. 后端校验深度、活动节点预算、stable key、枚举、标准引用、Finding 所属项目与状态。
4. 产出持久化为 `task_plan_proposals`，状态从 `pending` 开始；当前计划仍不变化。
5. 前端展示 additions/updates/preserved/archives 四类 diff。
6. 用户显式确认后，后端在 `BEGIN IMMEDIATE` 事务中再次校验 base revision 和保护边界，再合并并创建 revision/events。

重复应用已完成 proposal 是幂等的。AI 调用期间只要人工编辑、流量、Finding、Evidence 或 revision 发生变化，返回结果就不能产生可应用的过时 proposal。

## 人工工作保护

- 人工创建节点默认锁定全部可编辑字段。
- 非 `todo` 的人工进度、已关联 Evidence 的节点和人工来源节点整体受保护。
- AI 节点只更新未锁字段；status、actual observation、blocker reason、source、锁和 Evidence 关系从不接受模型覆盖。
- proposal 省略的安全 AI 节点只做软归档；受保护节点的结构祖先和 prerequisite 一并保留，避免关系悬空。
- `delete_task_node` 保留历史 IPC 名称，但实际语义是带事件的软归档，不删除备注、状态或 Evidence。

## Evidence 增量语义

- 给 Finding 或任务创建 Evidence 时，只在同一事务中写入不可变快照/关系，并把计划标记为 `needs_update`。
- 新 Evidence 不自动调用 AI、不自动更改节点、不自动推进状态。
- 当时仍 pending 的旧 proposal 会被标为 `superseded`，防止确认一个未见到新证据的 diff。
- 用户之后可以明确生成增量 proposal；只有确认合并后才清除更新标记。

## “下一步”排序

候选先执行保守过滤：

- 节点必须活动且状态为 `todo` 或 `in_progress`。
- 所有显式 prerequisite 必须终结；缺失或归档的 prerequisite 视为不满足。
- 全部结构祖先必须活动且未 blocked/skipped/not_applicable；祖先缺失或形成环时 fail closed。
- 仍有未终结子节点的结构节点不会被当作可执行叶子。

通过过滤后按 Finding 风险降序、priority 升序、Evidence 缺口优先、创建时间和 ID 确定性排序。`done / skipped / not_applicable` 被视为终结依赖，但三者保留不同审计含义。

## 前端与命令

- 读取：`get_task_tree`、`get_test_plan`、`list_task_plan_events`、`next_task`、`get_task_findings`。
- AI：`preview_task_ai`、`generate_task_tree`、`expand_task_node`、`alternative_task_node`。
- proposal：`apply_task_plan_proposal`、`reject_task_plan_proposal`。
- 人工操作：`create_task_node`、`update_task_node`、`update_task_status`、`delete_task_node`。
- `TaskTreeView.vue` 用 vue-flow 展示 parent 实线和 prerequisite 虚线，并展示 revision、更新标记、来源、priority、观察、原因、字段锁及 Finding/Evidence。
- AI 预览确认只授权一次模型调用，不等于确认 proposal；计划 diff 有独立确认步骤。

## 自动验证

回归测试覆盖：

- 重新规划保留人工节点、进度、备注、锁和 Evidence。
- 只更新未锁字段；过时 proposal 失效；重复应用幂等。
- 特殊状态原因、append-only 事件和数据库直写防护。
- Evidence 只标记更新并使旧 proposal superseded。
- 跨项目 Finding/Evidence/prerequisite 拒绝，rejected Finding 不能重新挂回计划。
- AI 上下文 TOCTOU、未满足依赖和阻塞祖先不会被推荐。
- 文件数据库重开后 parent、prerequisite、状态、原因和 revision 保持一致。

复现完整门禁：

```text
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
pnpm check
```

## 手工验收

1. 基于授权流量、Finding 和可选 Evidence 生成测试计划 proposal。
2. 确认 diff 出现前后 revision 不变；只有点击应用后 revision 增加。
3. 人工创建备注、修改状态、填写实际观察或锁定字段，再生成增量 proposal，确认这些内容被保留。
4. 新建 Evidence，确认页面只显示“测试计划可更新”，旧 pending proposal 不能应用。
5. 设置 prerequisite 和 blocked 祖先，确认“下一步”不会定位到被阻断节点。
6. 重启应用，确认 revision、节点关系、状态原因和事件仍在。

## 已知限制

- 当前是 parent + prerequisite 的测试计划，不是带 AND/OR 门、概率或防御节点语义的攻击树。
- 布局为确定性分层图；活动节点硬上限为 40、层级上限为 3，历史通过软归档保留。
- AI 只规划和解释；具体测试与网络发送始终由用户完成。
