# Phase 3 · 渗透任务树（PTT）— 完成说明

## 交付内容

**任务树数据模型与状态机（src-tauri/src/tree/）**
- `model.rs` — `TaskNode`（四问字段：description 做什么 / why 为什么 / how_to 怎么做 /
  verify_criteria 怎样算完成）+ `PlannedNode` / `PlannedTree`（AI 产出的中间形态）
- `state.rs` — 白名单式状态机，非法流转直接拒绝：

  | from → to | todo | in_progress | done | blocked |
  |---|---|---|---|---|
  | **todo** | — | ✅ | ✗（不许跳过执行） | ✅ |
  | **in_progress** | ✅ | — | ✅ | ✅ |
  | **blocked** | ✅ | ✅ | ✗ | — |
  | **done** | ✅（误标可重开） | ✗ | ✗ | ✗ |

  `next_actionable()`：进行中优先，否则按规划序（id 序）取第一个「无未完成子任务」的 todo 叶子

**AI 规划器（src-tauri/src/ai/planner.rs）**
- 三段式 API（构建提示词 / 解析校验 / 落库）——调用方在**持锁取数 → 放锁调 LLM → 持锁落库**，
  避免跨 `await` 持有 SQLite 锁
- 三种规划动作：`plan`（整树）、`expand`（节点展开子任务）、`alternative`（换个思路重写四要素）
- 产出校验硬约束：深度 ≤ 3（阶段/任务/子任务）、节点 ≤ 40、标题非空、`finding_ids` 按项目内**白名单过滤**
- **人在回路红线**：树只描述「做什么/怎么做」，不生成可直接运行的攻击脚本，执行永远由用户手动完成

**流量摘要（src-tauri/src/ai/digest.rs）**
- 给规划器看的「侦察报告」：端点聚合 Top 30（方法+host+path+频次+标签）、被动规则命中分布、
  已有 Finding 摘要（含 id 供 AI 建立双向关联）
- **成本控制**：只给聚合摘要不给全量流量；空流量项目直接报错引导先抓包

**命令（9 个）**
`get_task_tree / generate_task_tree(replace) / expand_task_node / alternative_task_node /
next_task / update_task_status / create_task_node / delete_task_node / get_task_findings`

**前端（src/views/TaskTreeView.vue — 本阶段补齐的核心 UI）**
- **vue-flow 可视化**：把扁平的 `parent_id` 结构算成整齐树（左→右分层，深度=列、兄弟纵向排；
  内部节点取子树中点）；节点按状态配色（待做灰 / 进行中蓝 / 完成绿 / 受阻红），
  选中描边、`下一步`定位脉冲高亮、可折叠子树
- **节点详情面板**：状态流转按钮（镜像后端白名单，只给合法目标）；四问字段
  （「为什么」直接展示存储字段**不消耗 token**，`怎么做/完成标准`用 markdown 渲染）；
  关联发现列表（点击跳「发现」页）；AI「展开子任务 / 换个思路」；手动「加子任务 / 删除」
- **工具栏**：AI 生成 / 重新生成（确认清空）、`下一步`引导、完成进度条、人在回路红线提示、
  空态引导（说明会读取流量摘要 + 需先抓包与配 Key）
- 交互命令全部落地：**下一步 / 为什么 / 换个思路 / 展开子任务 / 手动标记状态 / 与 Finding 双向关联**

## 测试（cargo test --lib 22/22 通过）

- 状态机：合法/非法流转、不允许 todo→done 跳过执行、done 可重开
- `next_actionable`：进行中优先、取第一个 todo 叶子、全完成返回 None
- 规划器：深度 4 拒绝、空标题拒绝、`finding_ids` 白名单过滤、`expand` 截断到 6、嵌套落库 + replace 清空重插
- 摘要：端点/标签/条数聚合正确、空项目报错
- 前端 `vite build` 通过（TaskTreeView 独立 chunk，vue-flow 正常打包）

## 手工验收（对应 Phase 3 验收标准）

1. 「流量」页抓一段目标流量（触发被动规则 / 可选做 AI 分析产生 Finding）
2. 「任务树」页点「AI 生成任务树」→ 出现分层任务树
3. 点任意节点 → 右侧看「做什么/为什么/怎么做/怎样算完成」四问 + 关联发现
4. 点「下一步」→ 自动定位并高亮当前该做的叶子任务；手动标记 进行中/完成/受阻
5. 对某节点「展开子任务」或「换个思路」→ 树增量更新

## 已知限制（后续 Phase）

- 布局是确定性整齐树（非力导向），超大树横向滚动 + 折叠应对
- 增量更新依赖「展开 / 重新生成」，未做节点级别的自动同步
- 规划质量取决于流量摘要与所选模型
