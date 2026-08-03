# Phase 5 · 持久化、容量、诊断与桌面发布 — 当前说明

> 实现核查日期：2026-08-01。本文区分“仓库内已实现”与“需要外部发布凭据才能完成”的事项。

## SQLite 基线与会话恢复

- 当前 schema 为 v3：空库顺序执行 v1/v2/v3，既有 v2 通过真实 v3 migration 增量升级；启动 validation 检查新增表、列、索引、触发器、外键目标及 `ON DELETE` action。
- 应用在创建连接池前用独占连接完成 schema 初始化/验证；每个池连接启用 WAL、foreign keys、5 秒 busy timeout 和 NORMAL synchronous。
- 连接池最大 8 条，代理写入、后台规则和 UI 查询不共享一个全局 Mutex 连接。
- schema 异常、外键/完整性失败或版本高于应用支持范围时明确拒绝启动，不猜测修复或静默降级。
- 项目、流量、AI run、Finding、Evidence、Repeater、旧测试计划以及 Assessment 契约/轮次/端点/check/verification/gap/events 和报告 provenance 均持久化。
- `current_project_id` 保存在非敏感 settings 中；重启恢复上次项目。项目切换会让旧异步结果和 Repeater 发送令牌失效，避免跨项目污染。
- 应用启动会把没有最终 run 的 Repeater attempt 恢复为 `APP_INTERRUPTED`，并把遗留活动 Assessment 标为 `interrupted`、终结开放 check；两者都不会自动恢复网络动作。

数据关系和删除语义见 [architecture/data-model.md](architecture/data-model.md)。

## 流量容量策略

- 数据库保留项目内全部流量；前端初始只加载最近 200 条。
- “加载更多”每次扩大 200 条窗口并重拉，`count_traffic` 使用与列表一致的过滤条件。
- `traffic:new` 只在当前窗口头部追加并裁剪到窗口大小；后台 `traffic:tags` 做定向增量更新。
- HTTP body、AI 上下文、Evidence、规则候选和报告原始附录各有独立硬上限，避免“大流量 + 大正文”形成乘法内存增长。

当前策略解决默认 UI 一次渲染全库的问题，但还不是十万级虚拟滚动或真正的 traffic cursor pagination。

## AI 用量与本地成本提示

- OpenAI 兼容响应中的 `usage` 会贯穿分析、隐藏旧计划和 Assessment 规划轮次；校验失败后的固定重试也计入总量。
- `analysis_runs` 保存每次响应的 prompt/completion/total tokens；设置页可按日或月聚合趋势。
- `usage_calls / usage_prompt_tokens / usage_completion_tokens / usage_total_tokens` 提供本机累计视图和清零操作。
- 每百万 token 单价由用户自行填写，只做本地估算；RustForge 不内置可能快速过时的供应商价格表。
- provider 不返回 usage 时记 0，不猜测 token 数。

## 桌面安全与运行诊断

- 生产 CSP 的前端 `connect-src` 只允许 Tauri IPC；开发 CSP 仅额外允许本机 Vite/HMR。
- 设置页可查看运行版本、数据库位置、代理状态、规则包/队列诊断和 AI 使用趋势。
- API Key 使用系统凭据库；CA 私钥使用原子写和当前用户权限；敏感日志统一过滤。
- Tauri bundle 已配置 Windows 图标、publisher、分类、描述和 updater artifact 生成。

## 签名自动更新

仓库内已实现：

- `@tauri-apps/plugin-updater` 前后端接入。
- 顶栏与 About 复用更新按钮；应用启动只做一次静默检查，用户可重复手动检查。
- 下载/安装状态、确认对话框、`ReleaseNotFound` 作为“已是最新”和并发检查控制均有前端测试。
- `tauri.conf.json` 固定 updater 公钥与 GitHub Releases `latest.json` endpoint。
- `.github/workflows/release.yml` 校验 tag/version，并从 GitHub Secrets 注入 Tauri 签名私钥和密码来生成签名产物。
- 每个标签必须在 `.github/release-notes/vX.Y.Z.md` 提供中文核心更新说明；发布流水线会校验文件存在、内容非空、包含中文和“核心”二级标题，再把完整 Markdown 写入 GitHub Release。
- `.github/workflows/sync-release-notes.yml` 以版本化说明文件为唯一来源：`main` 上的说明变更会同步到已存在的同名 Release，并从“核心”章节生成适合旧客户端纯文本弹窗的 `latest.json.notes`；更新清单的版本、发布日期、平台 URL 与签名在替换前后必须保持不变。尚未创建的版本会安全跳过并在打标签时由发布流水线使用。

仍需发布环境完成：

- 配置 `TAURI_SIGNING_PRIVATE_KEY` 与 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`；私钥和密码不得进入仓库、日志或文档。
- 用真实签名 Release 做一次 Windows x64 下载、验签、安装、退出与重启 E2E。
- Windows Authenticode 代码签名仍需发布者证书；Tauri updater 签名不能消除 SmartScreen 的“未知发布者”提示。

因此“更新客户端和发布流水线已实现”不等同于“外部 Release E2E 已完成”。

## 自动质量门禁

CI 与本地检查保持一致：

```text
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
pnpm test
pnpm typecheck
pnpm build
```

这些检查不读取真实 API Key、不访问真实目标、不安装根证书。需要网络的测试只访问测试进程启动且显式加入 Scope 的 localhost 服务。

## 手工验收

1. 切换项目、关闭并重启应用，确认恢复正确项目及其流量、Finding、Evidence、Repeater、Assessment 历史和隐藏旧计划；活动 Assessment 只能恢复为 interrupted。
2. 抓取超过 200 条流量，确认默认窗口、总数和“加载更多”一致，实时流量不会无限扩大 DOM。
3. 完成多次 AI 分析/计划调用，确认累计用量与按日/月趋势一致；无 usage 的 provider 显示 0 而非估算值。
4. 检查生产 CSP、系统凭据库状态、CA 权限和规则诊断。
5. 执行 `pnpm tauri build`，确认 bundle 元数据和 updater artifacts 配置有效。
6. 只有在外部 Secrets 和签名 Release 准备好后，再执行 updater E2E；不要用开发私钥或明文密码替代。

## 已知限制 / 后续增强

- traffic 列表是扩大窗口，不是游标分页/虚拟列表；10 万级交互需要 M6 容量专项验证。
- 用量累计是本机全局视图，趋势来自 `analysis_runs`；尚未按项目、provider 或模型提供完整成本账本。
- WebSocket/SSE/HTTP/2 语义、结构化过滤 DSL、受限插件能力和源码辅助模式属于独立 backlog。
- 已支持 v1→v2→v3 顺序迁移和 v2→v3 数据保留；公开发布后的长期备份、降级与跨大版本迁移策略仍需另立计划。
