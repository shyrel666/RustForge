# Phase 4 · 知识库 + Repeater + 学习报告（闭环）— 完成说明

本阶段补齐三块，把「抓包 → 分析 → 任务树引导 → **验证** → **出报告**」串成完整闭环。

## 交付内容

### 一、知识库（src-tauri/src/knowledge/mod.rs）

- 内置 **OWASP Top 10（2021 · A01–A10）** + **12 条常见 CWE**（SQL 注入/XSS/命令注入/路径遍历/
  CSRF/文件上传/认证不当/硬编码凭证/信息泄露/SSRF/XXE/反序列化/IDOR）中文卡片，
  每张含四段：**原理 / 危害 / 常见成因 / 修复建议**
- 归一化匹配：兼容 AI 产出的各种写法（`A01:2021 - Broken Access Control`、`cwe-89: SQL Injection`、
  `CWE 79` 等）统一成 `A01:2021` / `CWE-89` 再查
- `remediation_for(owasp, cwe)` 供**报告模块复用**修复建议
- 命令：`get_knowledge_cards(owasp, cwe) -> Vec<KnowledgeCard>`

### 二、Repeater 手动改包重发（src-tauri/src/commands.rs::replay_request）

- 人在回路的「验证」工具：由用户**主动触发**、可自由改 method/url/header/body 后重发
- pentest 工具惯例：`danger_accept_invalid_certs`（忽略证书错误）、`redirect=none`（不自动跟随重定向，
  便于观察 3xx/鉴权跳转）、30s 超时；`content-length`/`host` 交给底层按实际计算避免冲突
- 必须携带当前项目 ID；后端与代理共用 `ScopePolicy`，在创建 HTTP 客户端和 socket 前拒绝
  无项目、空 Scope、越界目标、userinfo、非法 URL 和非 HTTP(S) scheme
- 返回结构化响应：状态码 + 原因短语、响应头、响应体（UTF-8 文本或 base64）、耗时、大小
- **红线**：不做自动扫描/爆破，只是「一次一发」的手动验证；UI 使用后端无网络预检禁用越界发送，
  真正发包时后端再次校验

### 三、学习报告（src-tauri/src/report.rs）

- `build_markdown(conn, project_id)` 生成结构化 Markdown：
  1. **执行摘要**：流量条数、发现分布（已确认/待验证/已排除）、严重度分布、任务树进度
  2. **已确认发现** / **待验证发现**（按严重度排序）：类型/置信度/来源、OWASP/CWE、
     **关联请求**（method+url）、证据推理、手动验证步骤、**修复建议（取自知识库）**
  3. **渗透过程时间线**（按发现产生顺序）
  4. **任务树概览**（阶段 → 子任务状态）
  5. **涉及知识点**（去重列出命中的 OWASP/CWE）
- 顶部固定**授权免责声明**；AI/规则结论明确标注「需人工复核」
- 命令：`build_report`（预览文本）、`export_report`（写系统下载目录 `RustForge-Report-<时间戳>.md`，返回路径）

### 前端

- `src/api/tauri.ts` — 提供 `authorizeReplayTarget / replayRequest` 等绑定与 Scope 判定类型
- `src/components/KnowledgeCard.vue` — 按 finding 的 owasp/cwe 拉卡片，渲染四段（修复段绿色高亮）
- `src/views/FindingsView.vue` — 展开行新增「📚 知识卡片」；工具栏新增「📄 生成报告」→
  Markdown 预览弹框（markdown-it 渲染）+「导出 .md 到下载目录」
- **Repeater**：`src/stores/repeater.ts`（草稿：method/url/原始头/body；`headers` 文本 ⇄ 数组互转）+
  `src/views/RepeaterView.vue`（左请求编辑 / 右响应查看，一键发送）；新增路由 `/repeater` + 侧栏导航项
- `src/views/TrafficView.vue` — 流量详情抽屉新增「发送到 Repeater」：一键把该请求载入 Repeater 并跳转

## 测试（cargo test --lib 26/26 通过）

- 知识库：多种写法归一化（`CWE-89` / `cwe-89:` / `CWE 79` / `a3` → `A03:2021`）、命中去重、
  已知项修复建议非空
- 报告：核心分节齐全（标题/免责声明/已确认发现/命中标题/修复建议/涉及知识点）
- 前端 `vite build` 通过（RepeaterView 独立 chunk，FindingsView 含知识卡片 + 报告）

## 手工验收（对应 Phase 4 验收标准：完整闭环）

1. 「流量」页抓包 → 被动规则/AI 分析产生 Finding
2. 「任务树」页 AI 生成任务树，`下一步`引导逐步推进
3. 选一条可疑请求 → 详情抽屉「发送到 Repeater」→ 改参数/头部 → 发送，观察响应**手动验证**
4. 回「发现」页：展开行看到「知识卡片」（原理/危害/成因/修复）；按验证步骤标记 确认/误报
5. 点「生成报告」预览 → 「导出 .md」到下载目录，得到含复现步骤 + 修复建议 + 时间线的学习报告

## 已知限制（后续 Phase 5）

- Repeater 为「单次手动重发」，未做历史记录/多标签页/自动跟随会话（有意保持人在回路）
- 知识库是内置精选静态卡片，非全量 CWE 字典
- 报告导出为 Markdown；PDF/HTML 与 token 用量统计留待 Phase 5
