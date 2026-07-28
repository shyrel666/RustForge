# Phase 5 · 打磨（用量统计 / 大流量分页 / 打包 / 会话恢复）— 完成说明

收尾阶段：让工具在**真实、长时间、大流量**的使用下更稳、更可控、可发布。

## 交付内容

### 一、Token 用量统计与成本提示

**后端**
- `ai/client.rs` — `LlmClient::chat` 返回类型由 `String` 升级为 `ChatResponse { content, usage }`；
  新增 `Usage { prompt_tokens, completion_tokens, total_tokens }`（含 `add()` 累加）；
  从 OpenAI 兼容响应的 `usage` 字段解析（缺失记 0，兼容不回 usage 的服务）
- `ai/analyzer.rs` / `commands.rs::chat_json` — 透传并**累加**（含解析失败重试的那次调用也计入）
- `commands.rs::record_usage` — 每次 LLM 调用后把用量累加进 `settings` 表
  （`usage_calls / usage_prompt_tokens / usage_completion_tokens / usage_total_tokens`），
  接入全部 4 处 LLM 命令（分析 / 生成测试计划 proposal / 展开 / 换思路）
- 命令：`get_token_usage`（读累计）、`reset_token_usage`（清零）

**前端**
- `SettingsView.vue` 新增「📊 AI 用量统计」卡片：调用次数、输入/输出/合计 token、
  **每百万单价**输入（货币自定）→ **预估成本**；刷新 / 清零
- `settings` 新增持久化项 `price_per_mtok`

### 二、大流量分页（加载更多）

- 后端 `count_traffic` 命令：按与 `list_traffic` 完全一致的筛选条件统计总数
- `stores/traffic.ts` 重构为**窗口分页**：`limit` 起始 200、`loadMore()` 每次 +200 重拉；
  `total` 显示总量；`hasMore` getter 控制按钮；实时新流量 `unshift` 后自增 total 并把窗口裁剪到 limit
- `TrafficView.vue` 表格底部页脚：`已加载 N / 共 M 条` + 「加载更多」按钮
- 效果：数据库全量保留，UI 默认只渲染一页，避免大流量把界面拖垮

### 三、打包配置完善（发布就绪）

- `tauri.conf.json` 的 `bundle` 补齐元数据：`publisher / copyright / category(DeveloperTool) /
  shortDescription / longDescription`，并把 `icon.ico` 纳入图标集
- 说明：`generate_context!` 会在编译期校验该配置，`cargo test --lib` 通过即代表配置合法
- **签名**：Windows 代码签名需自备证书，用 `signCommand` / 环境变量注入，不入库明文；
  未签名安装包在 SmartScreen 会提示"未知发布者"，属预期

### 四、会话恢复 / 复盘

- 项目制 + SQLite 全量持久化（Phase 0 起）：流量 / 发现 / 分析运行 / 测试计划 / revision / 关联关系均落库
- `current_project_id` 存 `settings`，重启后自动恢复上次项目；切换项目即完整"回放"该会话的
  全部记录；配合本阶段的分页可回溯任意长的历史流量

## 测试（cargo test --lib 26/26 通过）

- 客户端/分析器/规划器全部随 trait 变更重编译通过（`ChatResponse` 贯通）
- 既有 26 个单测无回归（含解析失败恰好重试一次的 mock 测试，现走 `ChatResponse` 路径）
- `tauri.conf.json` 经 `generate_context!` 编译期 schema 校验
- 前端 `vite build` 通过（SettingsView 含用量卡片、TrafficView 含分页页脚）

## 手工验收（对应 Phase 5 目标）

1. 设置页配置 Key/模型 → 做几次 AI 分析/测试计划操作 → 「AI 用量统计」出现调用次数与 token；
   填入每百万单价 → 显示预估成本；「清零」可重置
2. 抓取大量流量（>200 条）→ 表格底部显示「已加载 200 / 共 N」→ 点「加载更多」增量加载
3. 关闭并重启应用 → 自动恢复上次项目及其全部流量/发现/测试计划
4. `pnpm tauri build` 产出带完整元数据的安装包（签名需自备证书）

## 已知限制 / 后续可选增强

- 大流量用「窗口分页」而非虚拟滚动（`el-table-v2`）——如需十万级实时渲染可再上虚拟列表
- 成本估算为本地估算，未内置各服务商价目表（价格随模型/时间变动，交由用户填写）
- 用量为**本机全局累计**，未按项目/模型分桶（可后续加维度）
- 代码签名与自动更新（updater）留作发布工程化任务
