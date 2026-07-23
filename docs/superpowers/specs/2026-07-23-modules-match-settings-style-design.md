# 模块页对齐设置页视觉语言

**日期:** 2026-07-23  
**状态:** 批准执行（用户：继续直到完成）

## 目标

以 Settings 的视觉语言统一 Home / 流量 / 重放 / 任务树 / 发现，同时保留工具页的全宽高密度工作区。

## 原则（混合）

| 采用（来自设置） | 不采用 |
|---|---|
| `PageHeader` + 分区标题/描述语气 | 工具页强制 `max-width: 720px` |
| `EmptyState` 统一空态 | 把表格/画布改成设置式 row-item 表单 |
| `rf-toolbar` + `rf-toolbar-group` | 破坏现有交互流程 |
| `rf-card` 外壳、token 色与圆角 | 硬编码 rgba / Element 默认空态混用 |
| 主操作右对齐（与设置保存行一致） | |

## 分页改动

1. **Home** — 标题区用 `rf-section-*` 语气；状态卡保持 `rf-card`；模块卡统一 hover/accent（已接近，收紧宽度 720 与设置一致）
2. **Findings** — 无项目时 `EmptyState`；工具栏分组；表格外包 `rf-card` 壳
3. **TaskTree** — 画布空态改 `EmptyState`；去掉硬编码 overlay；详情/画布用 panel token
4. **Repeater** — 工具栏分组；内容区 `rf-card`；空响应用 `EmptyState` 或统一 empty
5. **Traffic** — 表格壳对齐；抽屉内标签区轻量 token 化（已较接近，小幅抛光）

## 非目标

- 不改路由/业务逻辑
- 不重做 VueFlow 交互
- 不引入新依赖
